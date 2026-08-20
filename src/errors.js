// Błąd wywołania API huba. Niesie kod HTTP i surowe body odpowiedzi (o ile dostępne),
// żeby CLI mogło wypisać czytelną diagnostykę.
export class ApiError extends Error {
  constructor(message, { code = null, body = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.body = body;
  }
}
