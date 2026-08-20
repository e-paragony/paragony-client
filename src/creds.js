import fs from "node:fs";
import { ApiError } from "./errors.js";
import { CREDENTIALS_PATH, DEFAULT_SCHEME } from "./constants.js";

// Credentials: JSON w katalogu domowym. Trzyma wszystko co trzeba do dalszych wywołań
// (prefix/host konta, login, api_token) — klient mintuje z tego per-request JWT.
const ATTRS = [
  "scheme", "domain", "prefix", "login", "email", "api_token", "account_id",
  "created_at", "webhook_code", "webhook_secret",
];

export class Credentials {
  constructor() {
    for (const a of ATTRS) this[a] = null;
  }

  static load(path = CREDENTIALS_PATH) {
    const c = new Credentials();
    if (fs.existsSync(path)) {
      const data = JSON.parse(fs.readFileSync(path, "utf8"));
      for (const a of ATTRS) c[a] = data[a] ?? null;
    }
    return c;
  }

  save(path = CREDENTIALS_PATH) {
    const data = {};
    for (const a of ATTRS) data[a] = this[a] ?? null;
    fs.writeFileSync(path, JSON.stringify(data, null, 2));
    fs.chmodSync(path, 0o600);
    process.stderr.write(`[configure] zapisano credentiale do ${path}\n`);
  }

  baseUrl() {
    if (this.prefix == null || this.domain == null) {
      throw new ApiError("Brak konfiguracji — uruchom najpierw `signup` albo `configure`.");
    }
    return `${this.scheme || DEFAULT_SCHEME}://${this.prefix}.${this.domain}`;
  }

  present() {
    return !(this.prefix == null || this.domain == null || this.api_token == null);
  }
}
