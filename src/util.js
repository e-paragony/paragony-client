// Drobne helpery współdzielone przez moduły klienta.

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Sformatowanie kolumny o stałej szerokości (odpowiednik ruby `format("%-Ns", x)`).
// UWAGA: nie przycina — wartość dłuższa niż `width` rozjeżdża kolumny po prawej. Do listingów
// o nieznanej z góry treści użyj `table()`.
export function col(value, width) {
  const s = value == null ? "" : String(value);
  return s.padEnd(width);
}

function truncate(s, width) {
  return s.length <= width ? s : `${s.slice(0, width - 1)}…`;
}

// Tabela o kolumnach dopasowanych do treści: szerokość kolumny = jej najdłuższa wartość, przycięta
// do `maxWidth` (nadmiar oznaczony "…"). Dane huba bywają dłuższe niż jakakolwiek sensowna stała
// szerokość (nazwa drukarki = model + uid), a jedna taka wartość przy stałych kolumnach przesuwa
// wszystkie następne i cały listing przestaje się czytać. Zwraca gotowe linie.
export function table(headers, rows, { maxWidth = 32, gap = 2 } = {}) {
  const body = rows.map((row) => row.map((value) => truncate(value == null ? "" : String(value), maxWidth)));
  const widths = headers.map((header, i) => Math.max(header.length, ...body.map((row) => (row[i] ?? "").length)));
  const line = (row) => row.map((cell, i) => (cell ?? "").padEnd(widths[i])).join(" ".repeat(gap)).trimEnd();
  return [line(headers), ...body.map(line)];
}

// Maskowanie tokena do wypisania (pokazujemy tylko początek i koniec).
export function mask(token) {
  if (token == null) return "";
  if (token.length <= 10) return token;
  return `${token.slice(0, 6)}...${token.slice(-4)}`;
}

// Bieżący czas w sekundach (odpowiednik ruby `Time.now.to_i`).
export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// Godzina HH:MM:SS lokalnego czasu (odpowiednik `Time.now.strftime("%H:%M:%S")`).
export function hhmmss(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
