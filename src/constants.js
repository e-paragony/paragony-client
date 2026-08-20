import os from "node:os";
import path from "node:path";

// Ścieżka do pliku z credentialami (JSON w katalogu domowym). Nadpisywalna zmienną środowiskową.
export const CREDENTIALS_PATH =
  process.env.PARAGONY_CLIENT_CREDENTIALS ||
  path.join(os.homedir(), ".paragony_client_credentials.json");

// Domyślny host huba: PRODUKCJA paragony.pl (https). Dev (paragony.test/http) tylko przez flagi.
export const DEFAULT_DOMAIN = "paragony.pl";
export const DEFAULT_SCHEME = "https";

// Rejestracja konta idzie na host aplikacji app.<domain> (gołe paragony.pl to strona marketingowa,
// nie API huba). Samo konto żyje potem pod <prefix>.<domain>.
export const REGISTRATION_PREFIX = "app";

// Statusy zlecenia wg dokumentacji API paragony.pl. Starsze wdrożenia huba mogą zwracać
// status="error" zamiast "cancelled" przy anulowaniu — skrypt akceptuje oba i mówi wprost, który dostał.
export const TERMINAL_STATUSES = ["printed", "er_fatal", "er_printed", "error", "cancelled"];
export const PRINTED_STATUSES = ["printed", "er_printed"];

// Domyślny vendor print_requestów. Idzie w print_request.vendor oraz steruje code'em
// callback-connectora (paragony-<vendor>). Hub vendora NIE defaultuje (dokument bez efektywnego
// vendora odpada z błędem walidacji), dlatego klient wysyła go zawsze; batch-level `vendor`
// można nadpisać per dokument (`print_requests[].vendor`).
export const DEFAULT_VENDOR = "intum";

// Buduje code connectora webhooków dla danego vendora, zgodnie z konwencją nazewnictwa
// connectorów paragony-<vendor> wg dokumentacji webhooków API paragony.pl.
export function webhookCodeForVendor(vendor) {
  return `paragony-${vendor}`;
}

// code connectora webhooków dla domyślnego vendora (paragony-<DEFAULT_VENDOR>).
export const DEFAULT_WEBHOOK_CODE = webhookCodeForVendor(DEFAULT_VENDOR);
