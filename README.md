# paragony-client

Referencyjne klienty CLI huba paragonów (**paragony.pl** / fiskator) dla integratora
**zewnętrznego** — dwie implementacje o **identycznym zestawie subkomend**:

| Klient | Plik | Technologia |
|---|---|---|
| Node.js | `package.json` + `bin/` + `src/` (pakiet npm `paragony-client`) | czysty Node stdlib (`https`/`http`, `crypto`, `net`, `child_process`), zero zależności npm |
| Ruby | `paragony_client.rb` — jeden plik | czyste ruby stdlib (`net/http`, `openssl`, `json`), zero gemów |

Oba są samodzielne: tak wygląda apka natywna albo dowolny third-party integrator patrzący
na hub z zewnątrz. Wybierz ten, który pasuje do Twojego stacku — kontrakt, format JWT
i weryfikacja podpisu webhooków są w obu takie same.

## Szybki start — Ruby

Jeden plik, bez instalacji czegokolwiek:

```bash
curl -O https://raw.githubusercontent.com/paragonypl/paragony-client/main/paragony_client.rb
ruby paragony_client.rb help
```

## Szybki start — Node.js

Bez instalacji, przez `npx`:

```bash
npx paragony-client help
```

Globalnie:

```bash
npm install -g paragony-client
paragony-client help
```

Instalacja globalna zakłada też alias `paragony_client` — obie komendy uruchamiają ten sam klient.

## Kontrakt (zgodny z hubem)

- **Auth**: standardowy nagłówek `Authorization: Bearer <jwt>`. JWT **HS256**, sekret = surowy `api_token`,
  payload `{ key: SHA256(api_token)[0,16], exp }`, zgodnie z formatem JWT wymaganym przez API paragony.pl.
  Żaden surowy token nie idzie w query.
- **Zlecenia**: `POST /print_requests` z płaską kopertą — batch dokumentów pod top-level
  `print_requests[]`, `vendor` batch-level (nadpisywalny per dokument `print_requests[].vendor`).
  Vendor jest wymagany (hub nie defaultuje); drukarkę wskazuje `print_requests[].printer_id`
  albo `print_requests[].printer_name`.
- **Domyślnie PRODUKCJA**: hub native „fiskator" żyje pod `<prefix>.paragony.pl` (https).
  Dev: nadpisz `--domain paragony.test --scheme http`.
- Rejestracja konta idzie na `app.<domain>` (gołe `paragony.pl` to strona marketingowa, nie API).

## Subkomendy

| Komenda | Opis |
| --- | --- |
| `signup` | Załóż nowe konto NATIVE (product_app=fiskator) i zapisz credentiale lokalnie. Wymaga jawnego `--password`. |
| `login` | Zaloguj się (email+hasło) na istniejące konto, zdobądź `api_token`, zapisz credentiale. |
| `configure` | Ustaw/pokaż zapisaną konfigurację ręcznie (host/prefix/api_token). |
| `token:create` | Utwórz nowy `api_token` (jedyny endpoint zwracający surowy token). |
| `token:list` | Wylistuj `api_tokeny` konta (bez surowych tokenów). |
| `printer:list` | Wylistuj drukarki konta. |
| `printer:register` | Zarejestruj/zaktualizuj drukarkę (wymagane przed `pr:create`). |
| `pr:create` | Utwórz print_request (domyślnie `mode=print`). `--email` opcjonalny — bez niego e-paragon powstaje, ale nie idzie mailem. |
| `pr:show` | Pokaż status i dane print_requesta. |
| `pr:update` | „Edycja" = cancel + create-anew z nowymi danymi. |
| `pr:cancel` | Anuluj print_request. |
| `pr:watch` | Odpytuj status aż do terminalnego; dzwoni+powiadamia gdy wydrukowany. |
| `webhook:create` | Utwórz connector webhooków (`kind=paragony/callback`) na wskazany URL. |
| `webhook:serve` | All-in-one: podnieś tunel (cloudflared/ngrok), zarejestruj connector, nasłuchuj. |
| `webhook:show` | Pokaż aktualny connector webhooków. |
| `webhook:update` | Zmień URL (i opcjonalnie sekret) connectora. |
| `webhook:delete` | Usuń connector webhooków. |

Lista subkomend i ograniczenia całego klienta: `paragony-client help` albo
`ruby paragony_client.rb help`.
Flagi jednej subkomendy: `paragony-client <subcommand> --help` (np. `paragony-client login --help`);
w kliencie Ruby `ruby paragony_client.rb <subcommand> --help`.

## Przykładowy przepływ (dev)

```bash
# 1) załóż konto na dev
npx paragony-client signup --domain paragony.test --scheme http --password "MojeHaslo123!"

# 2) drukarka (wymagana przed pr:create)
npx paragony-client printer:register --uid PRINTER-1

# 3) zlecenie druku
npx paragony-client pr:create --printer-id <ID> --item-name "Kawa" --price 12.50

# 4) obserwuj status
npx paragony-client pr:watch <PR_ID>

# 5) webhooki all-in-one (wymaga cloudflared albo ngrok w PATH)
npx paragony-client webhook:serve
```

## webhook:serve

`webhook:serve` podnosi publiczny tunel HTTPS do lokalnego portu, rejestruje connector na URL tunelu
i nasłuchuje webhooków statusu PR. Każdy webhook jest weryfikowany kryptograficznie
(JWT HS256, `bh` liczone nad **surowym** body, `exp`).

- **cloudflared** — rekomendowany, quick tunnel bez konta (`brew install cloudflared`).
- **ngrok** — wymaga jednorazowego `ngrok config add-authtoken <token>`.
- Bez binarki tunelu: podaj własny `--url` albo `--tunnel none --url <URL>`.

## Credentiale

Zapisywane w `~/.paragony_client_credentials.json` (prawa `0600`). Ścieżkę nadpisuje
zmienna środowiskowa `PARAGONY_CLIENT_CREDENTIALS`.

Oba klienty czytają i zapisują ten sam plik, więc `signup` w jednym i `pr:create` w drugim
działają na tym samym koncie.

## Użycie jako biblioteka (Node.js)

```js
import { Http, Credentials, Jwt, serveWebhooks } from "paragony-client";

const creds = Credentials.load();
const http = new Http(creds);
const { code, json } = await http.get("/printers.json");
```

## Wymagania

- klient Node.js: Node.js **>= 18**
- klient Ruby: Ruby **>= 3.0** (samo stdlib, bez `bundle install`)
- (opcjonalnie, dla `webhook:serve`) `cloudflared` lub `ngrok` w `PATH`
