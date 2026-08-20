import fs from "node:fs";
import crypto from "node:crypto";
import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";

import { Credentials } from "./creds.js";
import { Http } from "./http.js";
import { Tunnel } from "./tunnel.js";
import { ApiError } from "./errors.js";
import { serveWebhooks } from "./webhook_server.js";
import { col, mask, nowSeconds, hhmmss, sleep, table } from "./util.js";
import {
  CREDENTIALS_PATH, DEFAULT_DOMAIN, DEFAULT_SCHEME, REGISTRATION_PREFIX,
  TERMINAL_STATUSES, PRINTED_STATUSES, DEFAULT_WEBHOOK_CODE,
  DEFAULT_VENDOR, webhookCodeForVendor,
} from "./constants.js";

// Ustala code connectora webhooków: jawne --code > pochodne z --vendor (paragony-<vendor>) >
// zapisane w credentialach > domyślne (paragony-fakturownia).
function resolveWebhookCode(values, creds) {
  if (values.code) return values.code;
  if (values.vendor) return webhookCodeForVendor(values.vendor);
  return creds.webhook_code || DEFAULT_WEBHOOK_CODE;
}

const out = (msg) => process.stdout.write(`${msg}\n`);
const warn = (msg) => process.stderr.write(`${msg}\n`);

// Parser opcji per-subkomenda (odpowiednik ruby OptionParser). Zwraca { values, positionals }.
// Nadmiarowe pozycyjne raportujemy, bo parseArgs przyjmuje je w milczeniu, a komendy czytają
// tylko tyle, ile deklaruje `maxPositionals` — wartość podana bez flagi (np. e-mail bez --email)
// znika wtedy bez śladu, a skutek wygląda jak błąd huba, nie jak błąd wywołania.
function parse(argv, spec) {
  const parsed = parseArgs({ args: argv, options: spec.options, allowPositionals: true, strict: true });

  const extra = parsed.positionals.slice(spec.maxPositionals);
  if (extra.length > 0) {
    warn(`UWAGA: zignorowano argument(y) podane bez flagi: ${extra.map((a) => JSON.stringify(a)).join(", ")}`);
    warn(`  Składnia: paragony-client ${spec.name}${spec.usage ? ` ${spec.usage}` : ""} [opcje] — pełna lista flag: --help`);
  }
  return parsed;
}

// Rejestr subkomend: opis (pomoc globalna), `usage` i `maxPositionals` (argumenty pozycyjne),
// oraz `options` dla parseArgs. Opcje MUSZĄ żyć tutaj, a nie w ciałach funkcji `cmd*` — pomoc
// per-subkomenda drukuje dokładnie ten sam obiekt, którym parsuje, więc nie ma jak się rozjechać.
//
// Pola opcji poza `type`/`short`:
//   default — STAŁA wartość domyślna. Wypełnia ją parseArgs, więc pomoc i zachowanie mają jedno
//             źródło. Nie wolno jej ustawiać flagom, których brak uruchamia dalszy fallback
//             (credentiale, stary print_request) — wypełniona flaga zasłoniłaby ten fallback.
//   note    — krótkie wyjaśnienie dla pomocy: co jest wymagane albo skąd bierze się domyślna
//             wartość, gdy nie jest stała.
const VERBOSE = { verbose: { type: "boolean", short: "v", note: "wypisuj wywołania HTTP (metoda, URL, nagłówki, body)" } };

// Wybór connectora webhooków: bez `default`, bo brak flagi ma sięgnąć po --vendor, potem po
// credentiale, a dopiero na końcu po stałą (resolveWebhookCode).
const WEBHOOK_CODE = {
  code: { type: "string", note: `domyślnie: paragony-<vendor>, potem z credentiali, potem ${DEFAULT_WEBHOOK_CODE}` },
  vendor: { type: "string", note: `code connectora to paragony-<vendor> (domyślnie ${DEFAULT_VENDOR})` },
};

const SPEC = {
  signup: {
    desc: "Załóż nowe konto NATIVE paragony.pl (product_app=fiskator) i zapisz credentiale lokalnie. Wymaga jawnego --password.",
    usage: "", maxPositionals: 0,
    options: {
      domain: { type: "string", default: DEFAULT_DOMAIN },
      scheme: { type: "string", default: DEFAULT_SCHEME },
      "app-host": { type: "string", note: `domyślnie: ${REGISTRATION_PREFIX}.<domain>` },
      prefix: { type: "string", note: "domyślnie: paragony-cli-test-<timestamp>" },
      email: { type: "string", note: "domyślnie: <prefix>@example.com" },
      password: { type: "string", note: "WYMAGANE (signup zakłada realne konto)" },
      ...VERBOSE,
    },
  },
  login: {
    desc: "Zaloguj się (email+hasło) na ISTNIEJĄCE konto, zdobądź api_token i zapisz credentiale.",
    usage: "", maxPositionals: 0,
    options: {
      // Bez `default`: brak flagi ma sięgnąć po zapisane credentiale, a dopiero potem po stałą.
      domain: { type: "string", note: `domyślnie: z credentiali, potem ${DEFAULT_DOMAIN}` },
      scheme: { type: "string", note: `domyślnie: z credentiali, potem ${DEFAULT_SCHEME}` },
      prefix: { type: "string", note: "WYMAGANE (albo zapisane w credentialach) — host to <prefix>.<domain>" },
      email: { type: "string", note: "WYMAGANE: --email albo --login (albo zapisane w credentialach)" },
      login: { type: "string", note: "alternatywa dla --email" },
      password: { type: "string", note: "WYMAGANE" },
      name: { type: "string", default: "paragony-cli", note: "nazwa tworzonego api_tokena" },
      "no-for-account": { type: "boolean", note: "token użytkownika zamiast tokena konta" },
      ...VERBOSE,
    },
  },
  configure: {
    desc: "Ustaw/pokaż zapisaną konfigurację (host/prefix/api_token) ręcznie, bez signupu.",
    usage: "", maxPositionals: 0,
    options: {
      show: { type: "boolean", note: "wypisz zapisaną konfigurację (domyślne, gdy nie podasz żadnej flagi)" },
      domain: { type: "string" }, scheme: { type: "string" },
      prefix: { type: "string" }, "api-token": { type: "string" }, login: { type: "string" },
    },
  },
  "token:create": {
    desc: "Utwórz nowy api_token na koncie (POST /account/api_tokens.json) — do podpięcia aplikacji.",
    usage: "", maxPositionals: 0,
    options: {
      name: { type: "string", default: "paragony-cli-app" },
      "no-for-account": { type: "boolean", note: "token użytkownika zamiast tokena konta" },
      "integration-app-code": { type: "string" }, code: { type: "string" },
      save: { type: "boolean", note: "zapisz nowy token jako aktywny w credentialach" },
      ...VERBOSE,
    },
  },
  "token:list": {
    desc: "Wylistuj api_tokeny konta (GET /account/api_tokens.json) — bez surowych tokenów.",
    usage: "", maxPositionals: 0,
    options: { "for-account": { type: "boolean", note: "tylko tokeny konta (?for_account=yes)" }, ...VERBOSE },
  },
  "printer:list": {
    desc: "Wylistuj drukarki konta (GET /printers.json).",
    usage: "", maxPositionals: 0,
    options: { json: { type: "boolean", note: "surowy JSON zamiast tabeli (tabela przycina długie wartości)" }, ...VERBOSE },
  },
  "printer:register": {
    desc: "Zarejestruj/zaktualizuj drukarkę na koncie (POST update_printer.json) — wymagane przed pr:create.",
    usage: "", maxPositionals: 0,
    options: {
      uid: { type: "string", note: "WYMAGANE — identyfikator drukarki, po nim hub robi upsert" },
      model: { type: "string", default: "MOCK PRINTER CLI" },
      "connection-method": { type: "string", default: "tcp" },
      "e-receipt": { type: "boolean" }, "e-receipt-configured": { type: "boolean" },
      name: { type: "string", note: "domyślnie: hub zostawia dotychczasową nazwę" },
      ...VERBOSE,
    },
  },
  "pr:create": {
    desc: "Utwórz print_request (POST /print_requests) — domyślnie mode=print (papier).",
    usage: "", maxPositionals: 0,
    options: {
      "external-id": { type: "string", note: "domyślnie: cli-<timestamp>" },
      "printer-id": { type: "string", note: "WYMAGANE: --printer-id, --printer-name albo --json" },
      "printer-name": { type: "string", note: "alternatywa dla --printer-id (hub szuka po nazwie)" },
      mode: { type: "string", default: "print", note: "print (papier) albo e_receipt" },
      email: { type: "string", note: "adres nabywcy; bez niego e-paragon powstaje, ale mail nie wychodzi" },
      "system-number": { type: "string", note: "domyślnie: CLI/<external-id>" },
      "order-number": { type: "string", note: "domyślnie: oid-<external-id>" },
      "external-url": { type: "string", note: "domyślnie: http://example.test/invoice/<external-id>" },
      "item-name": { type: "string", default: "Pozycja testowa" },
      price: { type: "string", default: "10.00", note: "brutto, stawka 23%" },
      json: { type: "string", note: "ścieżka do pliku z gotowym dokumentem — pomija pozostałe flagi treści" },
      vendor: { type: "string", default: DEFAULT_VENDOR, note: "steruje też routingiem webhooków (connector paragony-<vendor>)" },
      ...VERBOSE,
    },
  },
  "pr:show": {
    desc: "Pokaż status i dane print_requesta (GET /print_requests/:id.json).",
    usage: "<id>", maxPositionals: 1,
    options: { ...VERBOSE },
  },
  "pr:update": {
    desc: "\"Edycja\" print_requesta = cancel + create-anew (patrz limitations w help) z nowymi danymi.",
    usage: "<id>", maxPositionals: 1,
    // Bez `default` w całej komendzie: brak flagi znaczy "przenieś wartość z anulowanego zlecenia",
    // więc wypełniona flaga zasłoniłaby stary dokument.
    options: {
      "printer-id": { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      mode: { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      email: { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      "system-number": { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      "order-number": { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      "external-url": { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      "item-name": { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      price: { type: "string", note: "domyślnie: jak w anulowanym zleceniu" },
      json: { type: "string", note: "ścieżka do pliku z gotowym dokumentem — pomija pozostałe flagi treści" },
      vendor: { type: "string", note: `domyślnie: jak w anulowanym zleceniu, potem ${DEFAULT_VENDOR}` },
      ...VERBOSE,
    },
  },
  "pr:cancel": {
    desc: "Anuluj print_request (DELETE /print_requests/:id.json).",
    usage: "<id>", maxPositionals: 1,
    options: { ...VERBOSE },
  },
  "pr:watch": {
    desc: "Odpytuj status print_requesta co --interval sekund aż do statusu terminalnego; dzwoni+powiadamia gdy wydrukowany.",
    usage: "<id>", maxPositionals: 1,
    options: {
      interval: { type: "string", default: "5", note: "sekundy między odpytaniami" },
      timeout: { type: "string", default: "300", note: "sekundy do rezygnacji" },
      ...VERBOSE,
    },
  },
  "webhook:create": {
    desc: "Utwórz connector webhooków (kind=paragony/callback) na wskazany URL (POST /connect/connectors.json).",
    usage: "<url>", maxPositionals: 1,
    options: { ...WEBHOOK_CODE, secret: { type: "string", note: "domyślnie: losowy (wypisany po utworzeniu)" }, ...VERBOSE },
  },
  "webhook:serve": {
    desc: "All-in-one: podnieś tunel (cloudflared/ngrok), zarejestruj connector i nasłuchuj webhooków statusu PR.",
    usage: "", maxPositionals: 0,
    options: {
      port: { type: "string", default: "9292", note: "port lokalnego nasłuchu" },
      path: { type: "string", default: "/", note: "ścieżka, na której nasłuchujemy" },
      url: { type: "string", note: "własny publiczny URL zamiast auto-tunelu" },
      tunnel: { type: "string", default: "auto", note: "auto | cloudflared | ngrok | none" },
      ...WEBHOOK_CODE,
      secret: { type: "string", note: "domyślnie: z credentiali albo losowy przy rejestracji" },
      "no-register": { type: "boolean", note: "nie ruszaj connectora — tylko nasłuchuj" },
      ...VERBOSE,
    },
  },
  "webhook:show": {
    desc: "Pokaż aktualny connector webhooków (GET /connect/connectors/<code>.json).",
    usage: "", maxPositionals: 0,
    options: { ...WEBHOOK_CODE, ...VERBOSE },
  },
  "webhook:update": {
    desc: "Zmień URL (i opcjonalnie sekret) istniejącego connectora webhooków.",
    usage: "<url>", maxPositionals: 1,
    options: { ...WEBHOOK_CODE, secret: { type: "string", note: "domyślnie: sekret na hubie zostaje bez zmian" }, ...VERBOSE },
  },
  "webhook:delete": {
    desc: "Usuń connector webhooków (DELETE /connect/connectors/<code>.json).",
    usage: "", maxPositionals: 0,
    options: { ...WEBHOOK_CODE, ...VERBOSE },
  },
  help: {
    desc: "Ta pomoc.",
    usage: "", maxPositionals: 0, options: {},
  },
};

// `spec.name` jest potrzebne w komunikacie parse() o zignorowanych pozycyjnych; trzymamy je
// pochodne od klucza, żeby nazwa nie mogła rozjechać się z rejestrem.
for (const [name, spec] of Object.entries(SPEC)) spec.name = name;

// -----------------------------------------------------------------
// signup
// -----------------------------------------------------------------
async function cmdSignup(creds, argv) {
  const { values } = parse(argv, SPEC.signup);

  const domain = values.domain;
  const scheme = values.scheme;
  const prefix = values.prefix || `paragony-cli-test-${nowSeconds()}`;
  const email = values.email || `${prefix}@example.com`;
  // Bez domyślnego hasła: signup domyślnie zakłada konto na PRODUKCJI (DEFAULT_DOMAIN), więc
  // wymuszamy jawne --password zamiast wsypywać znane wszystkim hasło do realnych kont.
  const password = values.password;
  if (!password) {
    throw new ApiError(
      `--password jest wymagany (signup zakłada konto na ${scheme}://${REGISTRATION_PREFIX}.${domain}) — podaj np. --password 'MojeBezpieczneHaslo123!'`
    );
  }
  // Rejestracja idzie na host aplikacji (app.<domain>), bo gołe paragony.pl to strona marketingowa.
  const appHost = values["app-host"] || `${REGISTRATION_PREFIX}.${domain}`;
  const verbose = !!values.verbose;

  const body = { account: { prefix }, user: { email, password, password_confirmation: password } };
  const r = await Http.rawCall({ scheme, host: appHost, method: "POST", path: "/account/accounts.json", body, verbose });
  if (r.code !== 201) throw new ApiError("Signup nieudany", { code: r.code, body: r.raw });

  creds.scheme = scheme;
  creds.domain = domain;
  creds.prefix = r.json?.prefix;
  creds.login = r.json?.user?.login;
  creds.email = email;
  creds.api_token = r.json?.user?.api_token;
  creds.account_id = r.json?.id ?? null;
  creds.created_at = new Date().toISOString();
  creds.save();

  out(`Konto założone: prefix=${creds.prefix} login=${creds.login} url=${creds.baseUrl()}`);
  out(`api_token zapisany w credentialach (${CREDENTIALS_PATH}).`);
  out(`product_app=${r.json?.product_app} (oczekiwane: fiskator)`);
}

// -----------------------------------------------------------------
// login — zaloguj się na ISTNIEJĄCE konto, zdobądź api_token, zapisz creds.
// Hub nie ma endpointu "pokaż token" — jedyna droga to: login sesyjny (cookie) + utworzenie
// tokena for_account (POST /account/api_tokens.json, jedyne miejsce zwracające surowy token).
// -----------------------------------------------------------------
async function cmdLogin(creds, argv) {
  const { values } = parse(argv, SPEC.login);

  const domain = values.domain || creds.domain || DEFAULT_DOMAIN;
  const scheme = values.scheme || creds.scheme || DEFAULT_SCHEME;
  const prefix = values.prefix || creds.prefix;
  const identifier = values.email || values.login || creds.email || creds.login;
  const password = values.password;
  const name = values.name;
  const forAccount = values["no-for-account"] ? false : true;
  const verbose = !!values.verbose;

  if (!prefix) throw new ApiError("--prefix jest wymagany");
  if (!identifier) throw new ApiError("--email albo --login jest wymagany");
  if (!password) throw new ApiError("--password jest wymagany");

  const host = `${prefix}.${domain}`;

  // 1) login sesyjny — interesuje nas Set-Cookie (sesja), nie body
  const l = await Http.rawCall({
    scheme, host, method: "POST", path: "/login.json",
    body: { log_in: { login: identifier, email: identifier, password } }, verbose,
  });
  if (l.code !== 200) {
    const hint = l.code === 401
      ? "błędny login/hasło"
      : `kod ${l.code} — możliwe 2FA (utwórz token ręcznie w UI) lub zły prefix/host`;
    throw new ApiError(`login nieudany (${hint})`, { code: l.code, body: l.raw });
  }

  const cookieHeader = (l.setCookie || []).map((c) => c.split(";", 1)[0]).join("; ");
  if (!cookieHeader) throw new ApiError("login nie ustawił sesji (brak Set-Cookie)", { code: l.code, body: l.raw });

  // 2) utwórz api_token (jedyny moment, gdy hub zwraca surowy token)
  const t = await Http.rawCall({
    scheme, host, method: "POST", path: "/account/api_tokens.json",
    headers: { Cookie: cookieHeader },
    body: { api_token: { for_account: forAccount, name } }, verbose,
  });
  if (t.code !== 201) throw new ApiError("utworzenie api_tokena nieudane", { code: t.code, body: t.raw });

  const token = t.json?.token;
  if (!token) throw new ApiError("hub nie zwrócił tokena", { code: t.code, body: t.raw });

  creds.scheme = scheme;
  creds.domain = domain;
  creds.prefix = prefix;
  creds.email = identifier;
  // `login` też, bo oba pola są fallbackiem identyfikatora przy kolejnym `login` bez --email.
  // Pozostawione po poprzednim koncie wskazywałoby użytkownika, którego nowe konto nie zna.
  creds.login = identifier;
  creds.api_token = token;
  creds.created_at = new Date().toISOString();
  creds.save();

  out(`Zalogowano na ${creds.baseUrl()}.`);
  out(`Utworzono api_token id=${t.json?.id} name=${JSON.stringify(t.json?.name)} for_account=${t.json?.for_account}`);
  out(`api_token (pełny — zapisz, hub go już nie pokaże): ${token}`);
  out(`Zapisano w credentialach (${CREDENTIALS_PATH}).`);
}

// -----------------------------------------------------------------
// configure — ręczne ustawienie/pokazanie configu
// -----------------------------------------------------------------
async function cmdConfigure(creds, argv) {
  const { values } = parse(argv, SPEC.configure);

  const anySet = values.domain || values.scheme || values.prefix || values["api-token"] || values.login;
  if (values.show || !anySet) {
    if (creds.present()) {
      out(
        `scheme=${creds.scheme} domain=${creds.domain} prefix=${creds.prefix} login=${creds.login} ` +
        `account_id=${creds.account_id} api_token=${mask(creds.api_token)} webhook_code=${creds.webhook_code}`
      );
    } else {
      out(`Brak zapisanej konfiguracji (${CREDENTIALS_PATH}). Użyj \`signup\` albo podaj flagi ręcznie.`);
    }
    return;
  }

  if (values.domain) creds.domain = values.domain;
  if (values.scheme) creds.scheme = values.scheme;
  if (values.prefix) creds.prefix = values.prefix;
  if (values["api-token"]) creds.api_token = values["api-token"];
  if (values.login) creds.login = values.login;
  creds.save();
  out("Zapisano.");
}

// -----------------------------------------------------------------
// token:create
// -----------------------------------------------------------------
async function cmdTokenCreate(creds, argv) {
  const { values } = parse(argv, SPEC["token:create"]);

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const apiToken = { name: values.name, for_account: values["no-for-account"] ? false : true };
  if (values["integration-app-code"]) apiToken.integration_app_code = values["integration-app-code"];
  if (values.code) apiToken.code = values.code;

  const r = await httpc.post("/account/api_tokens.json", { body: { api_token: apiToken } });
  if (r.code !== 201) throw new ApiError("token:create nieudany", { code: r.code, body: r.raw });

  const token = r.json?.token;
  out(`Utworzono api_token id=${r.json?.id} name=${JSON.stringify(r.json?.name)} for_account=${r.json?.for_account}`);
  out(`api_token (pełny — zapisz, hub go już nie pokaże): ${token}`);

  if (values.save) {
    creds.api_token = token;
    creds.save();
    out("Zapisano jako aktywny api_token w credentialach.");
  }
}

// -----------------------------------------------------------------
// token:list
// -----------------------------------------------------------------
async function cmdTokenList(creds, argv) {
  const { values } = parse(argv, SPEC["token:list"]);

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const query = values["for-account"] ? { for_account: "yes" } : null;
  const r = await httpc.get("/account/api_tokens.json", { query });
  if (r.code !== 200) throw new ApiError("token:list nieudany", { code: r.code, body: r.raw });

  const tokens = Array.isArray(r.json) ? r.json : [];
  if (tokens.length === 0) {
    out("Brak api_tokenów.");
    return;
  }

  const rows = tokens.map((t) => [t.id, t.name, t.kind, t.for_account, t.active, t.expires_at]);
  for (const line of table(["id", "name", "kind", "for_account", "active", "expires_at"], rows)) out(line);
}

// -----------------------------------------------------------------
// printer:list
// Index huba zwraca CZYSTĄ tablicę JSON, 25/stronę przez ?page=N. pagy ma overflow=:last_page,
// więc strona poza zakresem zwraca OSTATNIĄ (niepustą) — kończymy, gdy strona nie wnosi NOWYCH id.
// -----------------------------------------------------------------
async function cmdPrinterList(creds, argv) {
  const { values } = parse(argv, SPEC["printer:list"]);

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const all = [];
  const seen = new Set();
  let page = 1;
  for (;;) {
    const r = await httpc.get("/printers.json", { query: { page } });
    if (r.code !== 200) throw new ApiError("printer:list nieudany", { code: r.code, body: r.raw });

    const batch = Array.isArray(r.json) ? r.json : [];
    const fresh = batch.filter((p) => !seen.has(p.id));
    if (fresh.length === 0) break;

    for (const p of fresh) seen.add(p.id);
    all.push(...fresh);
    page += 1;
  }

  if (values.json) {
    out(JSON.stringify(all, null, 2));
    return;
  }

  if (all.length === 0) {
    out(`Brak drukarek na koncie ${creds.prefix}.`);
    return;
  }

  out(`Drukarki konta ${creds.prefix} (${all.length}):`);
  const rows = all.map((p) => [p.id, p.uid, p.name, p.model, p.e_receipt, p.e_receipt_configured, p.default_mode]);
  const headers = ["id", "uid", "name", "model", "e_recpt", "e_recpt_conf", "default_mode"];
  for (const line of table(headers, rows)) out(line);
}

// -----------------------------------------------------------------
// printer:register
// -----------------------------------------------------------------
async function cmdPrinterRegister(creds, argv) {
  const { values } = parse(argv, SPEC["printer:register"]);
  if (values.uid == null) throw new ApiError("--uid jest wymagane");

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const printer = {
    uid: values.uid,
    model: values.model,
    connection_method: values["connection-method"],
    e_receipt: !!values["e-receipt"],
    e_receipt_configured: !!values["e-receipt-configured"],
  };
  if (values.name) printer.name = values.name;

  const r = await httpc.post("/printers/update_printer.json", { body: { printer } });
  if (![200, 201].includes(r.code)) throw new ApiError("Rejestracja drukarki nieudana", { code: r.code, body: r.raw });

  out(`Drukarka OK: id=${r.json?.id} name=${JSON.stringify(r.json?.name)} hub=${r.json?.hub} ready=${r.json?.ready}`);
  out(`(użyj --printer-id ${r.json?.id} w pr:create)`);
}

// -----------------------------------------------------------------
// pr:create
// -----------------------------------------------------------------
async function cmdPrCreate(creds, argv) {
  const { values } = parse(argv, SPEC["pr:create"]);

  const vendor = values.vendor;
  const externalId = values["external-id"] || `cli-${nowSeconds()}`;
  const printerId = values["printer-id"] != null ? Number(values["printer-id"]) : null;
  const printerName = values["printer-name"] || null;
  const mode = values.mode;
  const buyerEmail = values.email || null;
  const price = values.price;
  const itemName = values["item-name"];

  let invoice;
  if (values.json) {
    invoice = JSON.parse(fs.readFileSync(values.json, "utf8"));
  } else {
    if (printerId == null && printerName == null) {
      throw new ApiError("--printer-id albo --printer-name jest wymagane (albo podaj gotowy JSON przez --json)");
    }
    // klucz drukarki nieużyty w danym wywołaniu (printer_id XOR printer_name) nie idzie na wire
    invoice = {
      external_id: externalId,
      mode,
      ...(printerId != null ? { printer_id: printerId } : {}),
      ...(printerName != null ? { printer_name: printerName } : {}),
      system_number: values["system-number"] || `CLI/${externalId}`,
      order_number: values["order-number"] || `oid-${externalId}`,
      external_url: values["external-url"] || `http://example.test/invoice/${externalId}`,
      kind: "receipt",
      kind_text: "Paragon",
      // `buyer` idzie na wire TYLKO z podanym adresem — pusty obiekt nabywcy nie niesie
      // informacji, a brak adresu jest dla huba poprawnym stanem (e-paragon powstaje,
      // mail nie wychodzi).
      ...(buyerEmail != null ? { buyer: { email: buyerEmail } } : {}),
      positions: [
        { name: itemName, quantity: "1", price_gross: price, total_price_gross: price, tax: "23" },
      ],
    };
  }

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const r = await httpc.post("/print_requests.json", { body: { vendor, print_requests: [invoice] } });
  if (!(r.code === 200 && r.json?.status === "success")) {
    throw new ApiError("Utworzenie print_requesta nieudane", { code: r.code, body: r.raw });
  }

  const pr = r.json.print_requests[0];
  out(`PR utworzony: id=${pr.id} external_id=${JSON.stringify(pr.external_id)} status prawdopodobnie to_print`);
  if ((r.json.errors || []).length > 0) out(`errors: ${JSON.stringify(r.json.errors)}`);
}

// -----------------------------------------------------------------
// pr:show
// -----------------------------------------------------------------
async function cmdPrShow(creds, argv) {
  const { values, positionals } = parse(argv, SPEC["pr:show"]);
  const id = positionals[0];
  if (id == null) throw new ApiError("Użycie: pr:show <id>");

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const r = await httpc.get(`/print_requests/${id}.json`);
  if (r.code !== 200) throw new ApiError("pr:show nieudany", { code: r.code, body: r.raw });

  out(JSON.stringify(r.json, null, 2));
}

// -----------------------------------------------------------------
// pr:update — cancel + create-anew (patrz uzasadnienie w help)
// -----------------------------------------------------------------
async function cmdPrUpdate(creds, argv) {
  const { values, positionals } = parse(argv, SPEC["pr:update"]);
  const id = positionals[0];
  if (id == null) throw new ApiError("Użycie: pr:update <id> [opcje nowego zlecenia]");

  const httpc = new Http(creds, { verbose: !!values.verbose });

  // 1) przeczytaj stary PR (żeby przenieść niezmienione pola do nowego)
  const g = await httpc.get(`/print_requests/${id}.json`);
  if (g.code !== 200) throw new ApiError(`pr:update: nie znaleziono print_requesta ${id}`, { code: g.code, body: g.raw });
  const oldPr = g.json || {};
  const oldDoc = oldPr.source_document || {};

  // 2) cancel starego (DELETE)
  const c = await httpc.delete(`/print_requests/${id}.json`);
  if (![200, 204].includes(c.code)) {
    throw new ApiError("pr:update: anulowanie starego print_requesta nieudane", { code: c.code, body: c.raw });
  }
  out(`Stare zlecenie ${id} anulowane, nowy status=${JSON.stringify(c.json?.status)}`);

  // 3) create-anew z nadpisanymi polami
  let invoice;
  if (values.json) {
    invoice = JSON.parse(fs.readFileSync(values.json, "utf8"));
  } else {
    const printerId = values["printer-id"] != null ? Number(values["printer-id"]) : oldPr.printer_id;
    const buyer = values.email != null ? { email: values.email } : oldDoc.buyer;
    const oldPos = (oldDoc.positions && oldDoc.positions[0]) || {};
    let positions;
    if (values["item-name"] || values.price) {
      positions = [{
        name: values["item-name"] || oldPos.name,
        quantity: "1",
        price_gross: values.price || oldPos.price_gross,
        total_price_gross: values.price || oldPos.total_price_gross,
        tax: oldPos.tax || "23",
      }];
    } else {
      positions = oldDoc.positions;
    }
    invoice = {
      external_id: oldPr.external_id,
      mode: values.mode || (oldPr.e_receipt ? "e_receipt" : "print"),
      printer_id: printerId,
      system_number: values["system-number"] || oldDoc.system_number,
      order_number: values["order-number"] || oldDoc.order_number,
      external_url: values["external-url"] || oldPr.external_url,
      kind: oldDoc.kind || "receipt",
      kind_text: oldDoc.kind_text || "Paragon",
      // Nabywca przenosi się ze starego zlecenia jak reszta niezmienionych pól — inaczej
      // „edycja" e-paragonu cicho gubiłaby adres doręczenia razem z wysyłką maila.
      ...(buyer != null ? { buyer } : {}),
      positions,
    };
  }

  const vendor = values.vendor || oldPr.vendor || DEFAULT_VENDOR;
  const n = await httpc.post("/print_requests.json", { body: { vendor, print_requests: [invoice] } });
  if (!(n.code === 200 && n.json?.status === "success")) {
    throw new ApiError("pr:update: utworzenie nowego print_requesta nieudane (stary już anulowany!)", { code: n.code, body: n.raw });
  }

  const pr = n.json.print_requests[0];
  out(`Nowe zlecenie utworzone: id=${pr.id} external_id=${JSON.stringify(pr.external_id)}`);
}

// -----------------------------------------------------------------
// pr:cancel
// -----------------------------------------------------------------
async function cmdPrCancel(creds, argv) {
  const { values, positionals } = parse(argv, SPEC["pr:cancel"]);
  const id = positionals[0];
  if (id == null) throw new ApiError("Użycie: pr:cancel <id>");

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const r = await httpc.delete(`/print_requests/${id}.json`);
  if (![200, 204].includes(r.code)) throw new ApiError("pr:cancel nieudany", { code: r.code, body: r.raw });

  const status = r.json?.status;
  if (status === "cancelled") {
    out(`PR ${id} anulowany, status="cancelled".`);
  } else if (status === "error") {
    out(`PR ${id} anulowany, status="error" (starsze wdrożenia huba mogą zwracać ten status zamiast "cancelled" — traktowany jako anulowanie).`);
  } else if (r.code === 204) {
    out(`PR ${id} twardo usunięty (204, ścieżka system_admin — brak body).`);
  } else {
    out(`PR ${id}: odpowiedź ${r.code}, body=${JSON.stringify(r.json)}`);
  }
}

// -----------------------------------------------------------------
// pr:watch
// -----------------------------------------------------------------
async function cmdPrWatch(creds, argv) {
  const { values, positionals } = parse(argv, SPEC["pr:watch"]);
  const id = positionals[0];
  if (id == null) throw new ApiError("Użycie: pr:watch <id> [--interval N] [--timeout N]");

  const interval = Number(values.interval);
  const timeout = Number(values.timeout);

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const deadline = Date.now() + timeout * 1000;
  let lastStatus = null;

  out(`Obserwuję PR ${id} (interwał=${interval}s, timeout=${timeout}s)... Ctrl+C aby przerwać.`);
  for (;;) {
    const r = await httpc.get(`/print_requests/${id}.json`);
    if (r.code !== 200) throw new ApiError("pr:watch nieudany", { code: r.code, body: r.raw });

    const status = r.json?.status;
    if (status !== lastStatus) {
      out(`[${hhmmss()}] status: ${status}`);
      lastStatus = status;
    }

    if (TERMINAL_STATUSES.includes(status)) {
      if (PRINTED_STATUSES.includes(status)) {
        notifyPrinted(id, status);
      } else {
        out(`Zlecenie ${id} zakończone ze statusem ${JSON.stringify(status)} (nie wydrukowane).`);
      }
      break;
    }

    if (Date.now() > deadline) {
      out(`Timeout — status wciąż ${JSON.stringify(status)} po ${timeout}s.`);
      break;
    }

    await sleep(interval * 1000);
  }
}

function notifyPrinted(id, status) {
  const message = `Print request ${id} wydrukowany! status=${status}`;
  out(message);
  process.stdout.write("\x07"); // bell
  try {
    if (process.platform === "darwin" && spawnSync("which", ["osascript"], { stdio: "ignore" }).status === 0) {
      spawnSync("osascript", ["-e", `display notification ${JSON.stringify(message)} with title "paragony-client"`]);
    }
  } catch {
    // best-effort — nie wywalaj skryptu jeśli osascript niedostępny
  }
}

// -----------------------------------------------------------------
// webhook:create / show / update / delete / serve
// -----------------------------------------------------------------

// Upsert connectora paragony/callback: PATCH gdy istnieje, POST gdy nie. Zapisuje code+secret
// w credentialach (secret potrzebny do weryfikacji podpisu w webhook:serve). Zwraca { action, json }.
async function ensureWebhookConnector(httpc, creds, { code, url, secret }) {
  const g = await httpc.get(`/connect/connectors/${code}.json`);
  let action;
  let json;
  if (g.code === 200) {
    const p = await httpc.patch(`/connect/connectors/${code}.json`, { body: { connector: { url, secret_token: secret } } });
    if (p.code !== 200) throw new ApiError("aktualizacja connectora webhooków nieudana", { code: p.code, body: p.raw });
    json = p.json;
    action = "zaktualizowany";
  } else {
    const c = await httpc.post("/connect/connectors.json", {
      body: { connector: { kind: "paragony/callback", code, url, secret_token: secret } },
    });
    if (c.code !== 201) throw new ApiError("utworzenie connectora webhooków nieudane", { code: c.code, body: c.raw });
    json = c.json;
    action = "utworzony";
  }

  creds.webhook_code = code;
  creds.webhook_secret = secret;
  creds.save();
  return { action, json };
}

async function cmdWebhookCreate(creds, argv) {
  const { values, positionals } = parse(argv, SPEC["webhook:create"]);
  const url = positionals[0];
  if (url == null) throw new ApiError("Użycie: webhook:create <url> [--vendor V | --code CODE] [--secret SECRET]");

  const code = resolveWebhookCode(values, creds);
  const secret = values.secret || crypto.randomBytes(20).toString("hex");
  const httpc = new Http(creds, { verbose: !!values.verbose });
  const { action, json } = await ensureWebhookConnector(httpc, creds, { code, url, secret });
  out(`Connector ${action}: id=${json?.id} code=${json?.code} url=${json?.url}`);
  out(`secret_token (hub go NIE zwraca — zapisany lokalnie w credentialach do weryfikacji podpisu): ${secret}`);
}

async function cmdWebhookShow(creds, argv) {
  const { values } = parse(argv, SPEC["webhook:show"]);
  const code = resolveWebhookCode(values, creds);

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const r = await httpc.get(`/connect/connectors/${code}.json`);
  if (r.code !== 200) throw new ApiError("webhook:show nieudany", { code: r.code, body: r.raw });

  out(JSON.stringify(r.json, null, 2));
}

async function cmdWebhookUpdate(creds, argv) {
  const { values, positionals } = parse(argv, SPEC["webhook:update"]);
  const url = positionals[0];
  if (url == null) throw new ApiError("Użycie: webhook:update <url> [--vendor V | --code CODE] [--secret NOWY_SEKRET]");

  const code = resolveWebhookCode(values, creds);
  const httpc = new Http(creds, { verbose: !!values.verbose });
  const connector = { url };
  if (values.secret) connector.secret_token = values.secret;
  const r = await httpc.patch(`/connect/connectors/${code}.json`, { body: { connector } });
  if (r.code !== 200) throw new ApiError("webhook:update nieudany", { code: r.code, body: r.raw });

  creds.webhook_code = code;
  if (values.secret) creds.webhook_secret = values.secret;
  creds.save();
  out(`Connector zaktualizowany: id=${r.json?.id} url=${r.json?.url}`);
  if (values.secret) out(`Nowy secret_token zapisany na hubie i lokalnie: ${values.secret}`);
}

async function cmdWebhookDelete(creds, argv) {
  const { values } = parse(argv, SPEC["webhook:delete"]);
  const code = resolveWebhookCode(values, creds);

  const httpc = new Http(creds, { verbose: !!values.verbose });
  const r = await httpc.delete(`/connect/connectors/${code}.json`);
  if (r.code !== 204) throw new ApiError("webhook:delete nieudany", { code: r.code, body: r.raw });

  out(`Connector ${code} usunięty.`);
}

// webhook:serve — all-in-one: (opcjonalnie) podnieś tunel, zarejestruj connector, nasłuchuj.
async function cmdWebhookServe(creds, argv) {
  const { values } = parse(argv, SPEC["webhook:serve"]);

  const port = Number(values.port);
  const path = values.path;
  const tunnelMode = values.tunnel;
  const code = resolveWebhookCode(values, creds);
  const register = !values["no-register"];
  const verbose = !!values.verbose;

  let tunnel = null;
  try {
    // 1) publiczny URL: własny --url albo auto-tunel
    let publicUrl = values.url || null;
    if (publicUrl == null && tunnelMode !== "none") {
      const kind = Tunnel.availableKind(tunnelMode);
      if (kind == null) {
        throw new ApiError(
          "brak cloudflared/ngrok w PATH — zainstaluj (`brew install cloudflared`), podaj własny --url, albo --tunnel none"
        );
      }
      tunnel = new Tunnel({ port, kind, verbose });
      const base = await tunnel.start();
      publicUrl = `${base.replace(/\/$/, "")}${path}`;
      out(`Tunel ${kind}: ${publicUrl} → localhost:${port}`);
    }

    // 2) sekret + (opcjonalnie) rejestracja connectora na publicznym URL
    let secret = values.secret || creds.webhook_secret;
    if (register) {
      if (!publicUrl) {
        throw new ApiError("brak publicznego URL do rejestracji — podaj --url albo pozwól podnieść tunel (nie --tunnel none)");
      }
      secret = secret || crypto.randomBytes(20).toString("hex");
      const httpc = new Http(creds, { verbose });
      const { action, json } = await ensureWebhookConnector(httpc, creds, { code, url: publicUrl, secret });
      out(`Connector ${action}: code=${json?.code} url=${json?.url}`);
    }

    if (!secret) {
      throw new ApiError(
        "brak sekretu do weryfikacji — użyj --secret, uruchom najpierw webhook:create, albo pozwól na rejestrację (bez --no-register)"
      );
    }

    // 3) nasłuch (kończy się po SIGINT)
    await serveWebhooks({ port, path, secret, verbose });
  } finally {
    tunnel?.stop();
  }
}

const COMMANDS = {
  signup: cmdSignup,
  login: cmdLogin,
  configure: cmdConfigure,
  "token:create": cmdTokenCreate,
  "token:list": cmdTokenList,
  "printer:list": cmdPrinterList,
  "printer:register": cmdPrinterRegister,
  "pr:create": cmdPrCreate,
  "pr:show": cmdPrShow,
  "pr:update": cmdPrUpdate,
  "pr:cancel": cmdPrCancel,
  "pr:watch": cmdPrWatch,
  "webhook:create": cmdWebhookCreate,
  "webhook:show": cmdWebhookShow,
  "webhook:update": cmdWebhookUpdate,
  "webhook:delete": cmdWebhookDelete,
  "webhook:serve": cmdWebhookServe,
};

// Pomoc jednej subkomendy: składnia, opis i flagi wprost z SPEC.
export function printSubcommandHelp(name) {
  const spec = SPEC[name];
  out(`Użycie: paragony-client ${name}${spec.usage ? ` ${spec.usage}` : ""} [opcje]`);
  out("");
  out(spec.desc);
  out("");

  const options = Object.entries(spec.options);
  if (options.length === 0) {
    out("Ta subkomenda nie przyjmuje opcji.");
    return;
  }

  out("Opcje:");
  for (const [flag, opt] of options) {
    const short = opt.short ? `-${opt.short}, ` : "";
    const value = opt.type === "string" ? " <wartość>" : "";
    // `default` to wartość, którą realnie wstawia parseArgs — nie da się jej rozminąć z
    // zachowaniem. `note` dopowiada resztę: wymagalność i domyślne wyliczane w komendzie.
    const hints = [
      "default" in opt ? `domyślnie: ${JSON.stringify(opt.default)}` : null,
      opt.note,
    ].filter(Boolean);
    out(`  ${col(`${short}--${flag}${value}`, 30)}${hints.join("; ")}`.trimEnd());
  }
  out("");
  out("Uwagi/ograniczenia całego klienta: paragony-client help");
}

export function printHelp() {
  out("Użycie: paragony-client <subcommand> [opcje]");
  out("");
  out("Opcje danej subkomendy: paragony-client <subcommand> --help");
  out("");
  out("Subkomendy:");
  for (const [name, spec] of Object.entries(SPEC)) out(`  ${col(name, 18)} ${spec.desc}`);
  out("");
  out("Uwagi/ograniczenia:");
  out(`  - DOMYŚLNIE celujemy w PRODUKCJĘ ${DEFAULT_DOMAIN} (${DEFAULT_SCHEME}). \`signup\` zakłada REALNE`);
  out("    konto — do pracy na dev użyj: --domain paragony.test --scheme http.");
  out("  - `signup` wymaga jawnego --password (brak domyślnego hasła) — zakłada realne konto.");
  out("  - Auth: standardowy nagłówek Authorization: Bearer <jwt> — JWT mintowany per-request z api_token");
  out("    (sekret=api_token, payload {key: SHA256(api_token)[0,16], exp}), zgodnie z formatem JWT");
  out("    wymaganym przez API paragony.pl.");
  out("  - `login`/`token:create` to JEDYNE momenty, gdy hub zwraca SUROWY api_token — zapisz go od razu.");
  out("    `token:list` pokazuje tylko metadane (hub nie ujawnia tokenów w listingu/show).");
  out("  - `pr:update` NIE używa surowego PATCH /print_requests/:id — ten endpoint pozwala");
  out("    edytować tylko vendor/status/ptu_letter_in_names (nie treść paragonu), a zmiana `status` tą");
  out("    drogą OMIJA maszynę stanów (billing utilize/release). Dlatego robi cancel (DELETE) + create-anew.");
  out("  - `pr:cancel` (DELETE) zwraca status=\"cancelled\"; starsze wdrożenia huba mogą zamiast tego");
  out("    zwrócić \"error\". Skrypt akceptuje oba jako 'anulowane' i wypisuje realny status.");
  out("  - `webhook:serve` (all-in-one) sam podnosi tunel (cloudflared rekomendowany — bez konta;");
  out("    ngrok wymaga `ngrok config add-authtoken`), rejestruje connector na URL tunelu i nasłuchuje.");
  out("    Bez binarki tunelu podaj własny --url (np. z ngroka) lub --tunnel none + --url.");
  out("    Weryfikuje podpis (JWT HS256, bh nad SUROWYM body, exp).");
  out("  - `--vendor` (default intum): idzie w print_request.vendor i steruje routingiem webhooków —");
  out("    PR wiąże się z connectorem paragony-<vendor>. Hub vendora WYMAGA (dokument bez efektywnego");
  out("    vendora odpada z błędem walidacji, bez defaultu); batch-level `vendor` można nadpisać");
  out("    per dokument (print_requests[].vendor).");
  out("  - Print request wymaga istniejącej drukarki na koncie (print_requests[].printer_id, fallback");
  out("    printer_name) — użyj najpierw printer:register.");
  out("  - Connector webhooków musi istnieć ZANIM utworzysz print_request — connector_id jest wiązany");
  out("    przy create PR (bez runtime-lookupu), więc PR-y sprzed rejestracji nie dostaną webhooka.");
  out("  - `--email` jest opcjonalny także dla `--mode e_receipt`: bez adresu e-paragon");
  out("    powstaje normalnie (link masz w `view_url`), tylko mail nie wychodzi. Podany adres");
  out("    włącza automatyczną wysyłkę i zużywa pierwszą z 5 prób wysyłki na zlecenie.");
  out("");
  out(`Credentiale: ${CREDENTIALS_PATH} (nadpisz zmienną PARAGONY_CLIENT_CREDENTIALS)`);
}

// Punkt wejścia CLI: parsuje subkomendę, ładuje credentiale i dispatchuje.
export async function run(argv) {
  const args = [...argv];
  const sub = args.shift();
  if (sub == null || sub === "help" || sub === "-h" || sub === "--help") {
    printHelp();
    return;
  }
  if (!(sub in COMMANDS)) {
    warn(`Nieznana subkomenda: ${JSON.stringify(sub)}\n`);
    printHelp();
    process.exitCode = 1;
    return;
  }

  // --help łapiemy na SUROWEJ tablicy args, bo parse() woła parseArgs ze strict:true — nieznana
  // opcja rzuca błędem, zanim komenda zdąży cokolwiek wypisać.
  if (args.includes("--help") || args.includes("-h")) {
    printSubcommandHelp(sub);
    return;
  }

  const creds = Credentials.load();
  try {
    await COMMANDS[sub](creds, args);
  } catch (e) {
    if (e instanceof ApiError) {
      warn(`BŁĄD: ${e.message}`);
      if (e.code) warn(`  HTTP ${e.code}: ${e.body}`);
      process.exitCode = 1;
      return;
    }
    throw e;
  }
}
