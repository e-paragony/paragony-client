import http from "node:http";
import https from "node:https";
import { mint } from "./jwt.js";

// Prosty klient HTTP. Zawsze JSON in/out. Auth = JWT per-request (chyba że auth=false, np. przy
// signup/login, gdzie konto jeszcze nie istnieje lub token zdobywamy dopiero po sesji cookie).
export class Http {
  constructor(creds, { verbose = false } = {}) {
    this.creds = creds;
    this.verbose = verbose;
  }

  get(path, { query = null, auth = true } = {}) {
    return this.request("GET", path, { query, auth });
  }

  post(path, { body = null, auth = true } = {}) {
    return this.request("POST", path, { body, auth });
  }

  patch(path, { body = null, auth = true } = {}) {
    return this.request("PATCH", path, { body, auth });
  }

  delete(path, { auth = true } = {}) {
    return this.request("DELETE", path, { auth });
  }

  // Wywołanie z jawnym scheme+host (np. signup/login, zanim mamy prefix konta lub api_token).
  // headers: pozwala dosłać np. Cookie (sesja po loginie). Zwraca { code, json, raw, setCookie }.
  static rawCall({ scheme, host, method, path, body = null, headers = {}, verbose = false }) {
    const url = new URL(`${scheme}://${host}${path}`);
    return Http.doRequest(url, { method, body, headers, verbose });
  }

  async request(method, path, { query = null, body = null, auth = true } = {}) {
    const url = new URL(this.creds.baseUrl() + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v != null) url.searchParams.append(k, v);
      }
    }
    const headers = {};
    if (auth) headers.Authorization = `Bearer ${mint(this.creds.api_token)}`;
    return Http.doRequest(url, { method, body, headers, verbose: this.verbose });
  }

  // Pełna weryfikacja SSL (default Node). read timeout 15s. Zwraca surowe body + sparsowany JSON.
  static doRequest(url, { method, body, headers, verbose }) {
    return new Promise((resolve, reject) => {
      const lib = url.protocol === "https:" ? https : http;
      const reqHeaders = { Accept: "application/json", ...headers };
      let bodyStr = null;
      if (body != null) {
        bodyStr = JSON.stringify(body);
        reqHeaders["Content-Type"] = "application/json";
      }

      if (verbose) {
        process.stderr.write(`--> ${method.toUpperCase()} ${url}\n`);
        process.stderr.write(`    headers: ${JSON.stringify(reqHeaders)}\n`);
        if (bodyStr) process.stderr.write(`    body: ${bodyStr}\n`);
      }

      const req = lib.request(
        url,
        { method: method.toUpperCase(), headers: reqHeaders },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const raw = Buffer.concat(chunks).toString("utf8");
            if (verbose) {
              process.stderr.write(`<-- ${res.statusCode} ${url.pathname}\n`);
              process.stderr.write(`    body: ${raw}\n`);
            }
            resolve({
              code: res.statusCode,
              json: Http.safeJson(raw),
              raw,
              setCookie: res.headers["set-cookie"] || [],
            });
          });
        }
      );

      req.setTimeout(15000, () => req.destroy(new Error("read timeout (15s)")));
      req.on("error", reject);
      if (bodyStr != null) req.write(bodyStr);
      req.end();
    });
  }

  static safeJson(raw) {
    if (raw == null || raw === "") return null;
    try {
      return JSON.parse(raw);
    } catch {
      return { _raw: raw };
    }
  }
}
