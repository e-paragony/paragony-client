import crypto from "node:crypto";
import { ApiError } from "./errors.js";
import { nowSeconds } from "./util.js";

// JWT HS256 minimalny (bez zależności — zgodnie z wymogiem "czysty klient zewnętrzny").
// Zgodnie z formatem JWT wymaganym przez API paragony.pl:
//   secret = surowy api_token, payload {key: SHA256(api_token)[0,16], exp}.

export function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

// Mintuje JWT per-request. Sekretem HMAC jest SUROWY api_token; payload niesie fingerprint tokena
// (pierwsze 16 znaków SHA256 hex) i exp. `extraPayload` pozwala dołożyć pola (nieużywane w tym kliencie).
export function mint(apiToken, { ttl = 300, extraPayload = {} } = {}) {
  if (!apiToken) throw new ApiError("Brak api_token — uruchom `signup` albo `configure`.");

  const header = { alg: "HS256", typ: "JWT" };
  const keyFingerprint = crypto.createHash("sha256").update(apiToken).digest("hex").slice(0, 16);
  const payload = { key: keyFingerprint, exp: nowSeconds() + ttl, ...extraPayload };
  const segments = [header, payload].map((h) => b64url(Buffer.from(JSON.stringify(h))));
  const signature = crypto.createHmac("sha256", apiToken).update(segments.join(".")).digest();
  return [...segments, b64url(signature)].join(".");
}

// Weryfikacja przychodzącego JWT HS256 (webhook:serve) — para do `mint`.
// Sprawdza podpis (stałoczasowo) i wygaśnięcie (exp). Zwraca payload (obiekt) albo rzuca ApiError.
export function verify(jwt, secret) {
  if (!secret) throw new ApiError("brak sekretu do weryfikacji JWT");

  const segments = String(jwt).split(".");
  if (segments.length !== 3) throw new ApiError("nieprawidłowy JWT (oczekiwano 3 segmentów)");

  const [headerB64, payloadB64, signatureB64] = segments;
  const expected = crypto.createHmac("sha256", secret).update(`${headerB64}.${payloadB64}`).digest();

  let given;
  let payload;
  try {
    given = Buffer.from(signatureB64, "base64url");
    if (!secureCompare(expected, given)) {
      throw new ApiError("podpis JWT nie zgadza się (zły secret?)");
    }
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(`nie udało się zdekodować JWT: ${e.message}`);
  }

  const exp = payload.exp;
  if (exp && nowSeconds() > Number(exp)) throw new ApiError("JWT wygasł (exp)");

  return payload;
}

// Porównanie stałoczasowe (chroni przed timing attack). Buforom o różnej długości od razu false —
// crypto.timingSafeEqual rzuca dla różnych długości.
export function secureCompare(a, b) {
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
