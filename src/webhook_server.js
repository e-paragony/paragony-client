import http from "node:http";
import crypto from "node:crypto";
import { verify as jwtVerify, b64url, secureCompare } from "./jwt.js";
import { ApiError } from "./errors.js";
import { hhmmss } from "./util.js";

// Serwer nasłuchujący webhooków statusu PR. Weryfikuje podpis każdego webhooka
// (JWT HS256 + `bh` nad SUROWYM body + exp) i wypisuje eventy wg dyskryminatora `kind`.
// Kończy się czysto po SIGINT (Ctrl+C). Zwraca Promise rozwiązywany po zatrzymaniu.
export function serveWebhooks({ port, path, secret, verbose }) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => handleRequest(req, res, { secret, verbose }));

    server.on("error", (e) => {
      process.stderr.write(`[webhook] błąd serwera: ${e.message}\n`);
      resolve();
    });

    server.listen(port, "0.0.0.0", () => {
      process.stdout.write(
        `Nasłuchuję webhooków na http://0.0.0.0:${port}${path} (Ctrl+C aby zakończyć)...\n`
      );
    });

    const onSigint = () => {
      process.stdout.write("\nZatrzymano serwer webhooków.\n");
      server.close(() => resolve());
      // gdyby zostały wiszące połączenia — nie blokuj wyjścia
      resolve();
    };
    process.once("SIGINT", onSigint);
  });
}

// Zbiera SUROWE body jako Buffer (bez reparsowania — `bh` liczone jest nad dokładnymi bajtami),
// weryfikuje podpis i odpowiada.
function handleRequest(req, res, { secret, verbose }) {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    if (verbose) process.stderr.write(`--> ${req.method} (${body.length}B)\n`);
    let status;
    let payload;
    try {
      [status, payload] = processWebhook({ method: req.method, headers: req.headers, body, secret });
    } catch (e) {
      status = 500;
      payload = { error: e.message };
      process.stderr.write(`[webhook] błąd obsługi połączenia: ${e.message}\n`);
    }
    respond(res, status, payload);
  });
  req.on("error", (e) => {
    process.stderr.write(`[webhook] błąd obsługi połączenia: ${e.message}\n`);
  });
}

// Weryfikacja + dispatch. Zwraca [status_http, obiekt_odpowiedzi].
function processWebhook({ method, headers, body, secret }) {
  const auth = String(headers.authorization || "").replace(/^Bearer\s+/i, "");
  let payload;
  try {
    payload = jwtVerify(auth, secret);
  } catch (e) {
    if (e instanceof ApiError) return [401, { error: e.message }];
    throw e;
  }

  const expectedBh = b64url(crypto.createHash("sha256").update(body).digest());
  if (!secureCompare(Buffer.from(expectedBh), Buffer.from(String(payload.bh || "")))) {
    return [401, { error: "bh mismatch (tampered body)" }];
  }

  if (payload.htm && payload.htm !== "POST") {
    process.stderr.write(`[webhook] uwaga: htm=${JSON.stringify(payload.htm)} (oczekiwano "POST")\n`);
  }
  // htu celowo tylko informacyjnie — za tunelem publiczny URL różni się od bind-adresu.

  let event;
  try {
    event = JSON.parse(body.toString("utf8"));
  } catch (e) {
    return [400, { error: `invalid json: ${e.message}` }];
  }

  printEvent(event);
  return [200, { message: "ok" }];
}

// Czytelny wypis eventu wg dyskryminatora `kind`.
function printEvent(event) {
  const ts = hhmmss();
  switch (event.kind) {
    case "print_request:update": {
      const pr = event.print_request || {};
      let line = `[${ts}] PR ${pr.id} ext=${JSON.stringify(pr.external_id)} status=${pr.status}`;
      if (pr.view_url) line += ` view_url=${pr.view_url}`;
      process.stdout.write(`${line}\n`);
      break;
    }
    case "printer:create":
    case "printer:update":
    case "printer:destroy": {
      const printer = event.printer || {};
      process.stdout.write(`[${ts}] ${event.kind} printer id=${printer.id} uid=${JSON.stringify(printer.uid)}\n`);
      break;
    }
    default:
      process.stdout.write(`[${ts}] ${event.kind || "?"}: ${JSON.stringify(event)}\n`);
  }
}

function respond(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", Connection: "close" });
  res.end(body);
}
