#!/usr/bin/env ruby

# Samodzielny klient CLI huba paragonów (paragony.pl / fiskator) dla integratora ZEWNĘTRZNEGO.
# Czyste ruby stdlib (net/http + openssl + json), ZERO zależności od Railsów/Fakturowni —
# tak wygląda apka natywna albo dowolny third-party integrator patrzący na hub z zewnątrz.
#
# Kontrakt (zweryfikowany w kodzie huba, 2026-07-17):
#   - Auth: standardowy nagłówek `Authorization: Bearer <jwt>`. JWT HS256 mintowany per-request:
#     secret = surowy api_token, payload {key: SHA256(api_token)[0,16], exp}.
#     ŻADEN raw token nie idzie w query.
#   - Domyślnie celujemy w PRODUKCJĘ: hub native "fiskator" żyje pod <prefix>.paragony.pl (https).
#     Do pracy na dev nadpisz: --domain paragony.test --scheme http.
#
# Użycie: ruby paragony_client.rb <subcommand> [opcje]
# Pełna lista subkomend: ruby paragony_client.rb help

require "net/http"
require "uri"
require "json"
require "optparse"
require "openssl"
require "digest"
require "base64"
require "securerandom"
require "time"
require "socket" # webhook:serve — lokalny TCPServer nasłuchujący webhooków
require "open3"  # webhook:serve — spawn zewnętrznego tunelu (cloudflared/ngrok)

module ParagonyClient
  CREDENTIALS_PATH = ENV["PARAGONY_CLIENT_CREDENTIALS"] || File.join(Dir.home, ".paragony_client_credentials.json")

  # Domyślny host huba: PRODUKCJA paragony.pl (https). Dev (paragony.test/http) tylko przez flagi.
  DEFAULT_DOMAIN = "paragony.pl"
  DEFAULT_SCHEME = "https"
  # Rejestracja konta idzie na host aplikacji app.<domain> — gołe paragony.pl to strona
  # marketingowa, nie API.
  REGISTRATION_PREFIX = "app"

  # Domyślny vendor print_requestów. Idzie w print_request.vendor oraz steruje code'em
  # callback-connectora (paragony-<vendor>).
  # Hub vendora NIE defaultuje (walidacja presence — dokument bez efektywnego vendora odpada),
  # dlatego skrypt wysyła go zawsze; batch-level `vendor` można nadpisać per dokument
  # (`print_requests[].vendor`).
  DEFAULT_VENDOR = "intum"

  # Statusy maszyny stanów huba. `cancelled` bywa niedostępne — starsza wersja huba na DELETE
  # zlecenia do_print/printing zwraca status "error", nie "cancelled". Skrypt uznaje OBA za wynik
  # anulowania i mówi wprost, który dostał.
  TERMINAL_STATUSES = %w[printed er_fatal er_printed error cancelled].freeze
  PRINTED_STATUSES = %w[printed er_printed].freeze

  class ApiError < StandardError
    attr_reader :code, :body

    def initialize(msg, code: nil, body: nil)
      super(msg)
      @code = code
      @body = body
    end
  end

  # ---------------------------------------------------------------------
  # Credentials: JSON obok skryptu. Trzyma wszystko co trzeba do dalszych wywołań
  # (prefix/host konta, login, api_token) — skrypt mintuje z tego per-request JWT.
  # ---------------------------------------------------------------------
  class Credentials
    ATTRS = [:scheme, :domain, :prefix, :login, :email, :api_token, :account_id, :created_at,
      :webhook_code, :webhook_secret].freeze
    attr_accessor(*ATTRS)

    def self.load(path = CREDENTIALS_PATH)
      c = new
      if File.exist?(path)
        data = JSON.parse(File.read(path))
        ATTRS.each { |a| c.public_send("#{a}=", data[a.to_s]) }
      end
      c
    end

    def save!(path = CREDENTIALS_PATH)
      data = ATTRS.to_h { |a| [a.to_s, public_send(a)] }
      File.write(path, JSON.pretty_generate(data))
      File.chmod(0o600, path)
      warn "[configure] zapisano credentiale do #{path}"
    end

    def base_url
      raise ApiError, "Brak konfiguracji — uruchom najpierw `signup` albo `configure`." if prefix == nil || domain == nil

      "#{scheme || DEFAULT_SCHEME}://#{prefix}.#{domain}"
    end

    def present?
      !(prefix == nil || domain == nil || api_token == nil)
    end
  end

  # ---------------------------------------------------------------------
  # JWT HS256 minimalny (bez gemu `jwt` — zgodnie z wymogiem "czysty klient zewnętrzny").
  # Wzorzec wymagany przez hub:
  #   secret = surowy api_token, payload {key: SHA256(api_token)[0,16], exp}.
  # ---------------------------------------------------------------------
  module Jwt
    module_function def b64url(bin)
      Base64.urlsafe_encode64(bin, padding: false)
    end

    module_function def mint(api_token, ttl: 300, extra_payload: {})
      raise ApiError, "Brak api_token — uruchom `signup` albo `configure`." if api_token.to_s.empty?

      header = { alg: "HS256", typ: "JWT" }
      key_fingerprint = Digest::SHA256.hexdigest(api_token)[0, 16]
      payload = { key: key_fingerprint, exp: Time.now.to_i + ttl }.merge(extra_payload)
      segments = [header, payload].map { |h| b64url(JSON.generate(h)) }
      signature = OpenSSL::HMAC.digest("SHA256", api_token, segments.join("."))
      (segments + [b64url(signature)]).join(".")
    end

    # Weryfikacja przychodzącego JWT HS256 (webhook:serve) — para do `mint`, czysty ruby.
    # Sprawdza podpis (stałoczasowo) i wygaśnięcie (exp). Zwraca payload (Hash) albo rzuca ApiError.
    module_function def verify(jwt, secret)
      raise ApiError, "brak sekretu do weryfikacji JWT" if secret.to_s.empty?

      segments = jwt.to_s.split(".")
      raise ApiError, "nieprawidłowy JWT (oczekiwano 3 segmentów)" if segments.size != 3

      header_b64, payload_b64, signature_b64 = segments
      expected = OpenSSL::HMAC.digest("SHA256", secret, "#{header_b64}.#{payload_b64}")
      given = Base64.urlsafe_decode64(signature_b64)
      raise ApiError, "podpis JWT nie zgadza się (zły secret?)" unless secure_compare(expected, given)

      payload = JSON.parse(Base64.urlsafe_decode64(payload_b64))
      exp = payload["exp"]
      raise ApiError, "JWT wygasł (exp)" if exp && Time.now.to_i > exp.to_i # rubocop:disable Rails/TimeZone -- stdlib

      payload
    rescue ArgumentError, JSON::ParserError => e
      raise ApiError, "nie udało się zdekodować JWT: #{e.message}"
    end

    # Porównanie stałoczasowe (bez ActiveSupport::SecurityUtils) — chroni przed timing attack.
    module_function def secure_compare(a, b)
      return false if a.bytesize != b.bytesize

      res = 0
      a.bytes.zip(b.bytes) { |x, y| res |= x ^ y }
      res == 0
    end
  end

  # ---------------------------------------------------------------------
  # Prosty klient HTTP (net/http). Zawsze JSON in/out. Auth = JWT per-request (chyba że auth: false,
  # np. przy signup, gdzie konto jeszcze nie istnieje).
  # ---------------------------------------------------------------------
  class Http
    def initialize(creds, verbose: false)
      @creds = creds
      @verbose = verbose
    end

    def get(path, query: nil, auth: true)
      request(:get, path, query: query, auth: auth)
    end

    def post(path, body: nil, auth: true)
      request(:post, path, body: body, auth: auth)
    end

    def patch(path, body: nil, auth: true)
      request(:patch, path, body: body, auth: auth)
    end

    def delete(path, auth: true)
      request(:delete, path, auth: auth)
    end

    # Wywołanie z jawnym scheme+host (np. signup/login, zanim mamy prefix konta lub api_token).
    # headers: pozwala dosłać np. Cookie (sesja po loginie). Zwraca [code, parsed, raw, res] —
    # 4. element (obiekt odpowiedzi) potrzebny do odczytu Set-Cookie.
    def self.raw_call(scheme:, host:, method:, path:, body: nil, headers: {}, verbose: false)
      uri = URI("#{scheme}://#{host}#{path}")
      do_request(uri, method: method, body: body, headers: headers, verbose: verbose)
    end

    private def request(method, path, query: nil, body: nil, auth: true)
      uri = URI(@creds.base_url + path)
      uri.query = URI.encode_www_form(query) if query&.any?
      headers = {}
      headers["Authorization"] = "Bearer #{Jwt.mint(@creds.api_token)}" if auth
      self.class.do_request(uri, method: method, body: body, headers: headers, verbose: @verbose)
    end

    def self.do_request(uri, method:, body:, headers:, verbose:)
      http = Net::HTTP.new(uri.host, uri.port)
      # Pelna weryfikacja SSL (default). Certy puma-dev sa zaufane takze dla Rubiego;
      # gdyby na innej maszynie nie byly: SSL_CERT_FILE=~/Library/"Application Support"/io.puma.dev/cert.pem
      http.use_ssl = uri.scheme == "https"
      http.read_timeout = 15

      req_class = { get: Net::HTTP::Get, post: Net::HTTP::Post, patch: Net::HTTP::Patch, delete: Net::HTTP::Delete }.fetch(method)
      req = req_class.new(uri)
      req["Accept"] = "application/json"
      headers.each { |k, v| req[k] = v }
      if body
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(body)
      end

      if verbose
        warn "--> #{method.to_s.upcase} #{uri}"
        warn "    headers: #{headers.merge("Content-Type" => body ? "application/json" : nil).compact}"
        warn "    body: #{req.body}" if req.body
      end

      res = http.request(req)

      if verbose
        warn "<-- #{res.code} #{uri.path}"
        warn "    body: #{res.body}"
      end

      parsed = safe_json(res.body)
      # 4. element (res) daje dostęp do nagłówków odpowiedzi (np. Set-Cookie przy loginie).
      # Istniejący callerzy destrukturyzują 3 pierwsze elementy, więc dodatkowy jest bezpieczny.
      [res.code.to_i, parsed, res.body, res]
    end

    def self.safe_json(raw)
      return if raw == nil || raw.empty? # rubocop:disable Rails/Blank -- stdlib, bez ActiveSupport

      JSON.parse(raw)
    rescue JSON::ParserError
      { "_raw" => raw }
    end
  end

  # ---------------------------------------------------------------------
  # Tunnel: podnosi publiczny tunel HTTPS do lokalnego portu (dla webhook:serve),
  # żeby hub paragony.pl mógł dostarczyć webhooki na maszynę deweloperską za NAT-em.
  # Zewnętrzna BINARKA (nie gem): cloudflared (rekomendowany, quick tunnel bez konta)
  # albo ngrok (wymaga jednorazowego authtokena). Proces tunelu jest ubijany w stop.
  # ---------------------------------------------------------------------
  class Tunnel
    attr_reader :public_url, :kind

    # Zwraca nazwę pierwszej dostępnej binarki tunelu (albo nil). preferred: "cloudflared"/"ngrok"/"auto".
    def self.available_kind(preferred = nil)
      candidates = preferred && preferred != "auto" ? [preferred] : %w[cloudflared ngrok]
      candidates.find { |bin| system("which", bin, out: File::NULL, err: File::NULL) }
    end

    def initialize(port:, kind:, verbose: false)
      @port = port
      @kind = kind
      @verbose = verbose
      @public_url = nil
      @url_regex = nil
      @io = nil
      @wait_thr = nil
      @reader = nil
    end

    # Podnosi tunel i zwraca publiczny URL bazowy (bez ścieżki webhooka).
    def start
      case @kind
      when "cloudflared" then start_cloudflared
      when "ngrok" then start_ngrok
      else raise ApiError, "nieobsługiwany tunel: #{@kind.inspect}"
      end
      @public_url
    end

    def stop
      Process.kill("TERM", @wait_thr.pid) if @wait_thr&.alive?
    rescue StandardError
      nil
    ensure
      @reader&.kill
      begin
        @io&.close
      rescue StandardError
        nil
      end
    end

    # cloudflared quick tunnel — URL wypada w logu jako https://<x>.trycloudflare.com
    private def start_cloudflared
      @url_regex = %r{https://[-a-z0-9]+\.trycloudflare\.com}
      @io, @wait_thr = popen_tunnel("cloudflared", "tunnel", "--url", "http://localhost:#{@port}", "--no-autoupdate")
      start_reader
      wait_until(dead_hint: "cloudflared padł przed podaniem URL (zainstalowany? `brew install cloudflared`)") { @public_url }
    end

    # ngrok — URL bierzemy z lokalnego API :4040 (log ngroka nie zawsze go niesie czytelnie).
    private def start_ngrok
      @io, @wait_thr = popen_tunnel("ngrok", "http", @port.to_s, "--log", "stdout")
      start_reader # tylko drenaż strumienia, żeby pipe się nie zapchał
      @public_url = wait_until(dead_hint: "ngrok padł — czy ustawiono authtoken? (`ngrok config add-authtoken <token>`)") { fetch_ngrok_url }
    end

    private def popen_tunnel(*cmd)
      stdin, out_err, wait_thr = Open3.popen2e(*cmd)
      stdin.close
      [out_err, wait_thr]
    rescue Errno::ENOENT
      raise ApiError, "brak binarki #{cmd.first} w PATH"
    end

    # Wątek czytający strumień tunelu: drenuje go (żeby pipe nie blokował) i skanuje po URL.
    private def start_reader
      @reader = Thread.new do
        @io.each_line do |line|
          warn "[tunnel] #{line}" if @verbose
          @public_url = Regexp.last_match(0) if @url_regex && @public_url == nil && line.match(@url_regex)
        end
      rescue IOError, Errno::EBADF
        nil
      end
    end

    private def fetch_ngrok_url
      res = Net::HTTP.get_response(URI("http://127.0.0.1:4040/api/tunnels"))
      return if res.code.to_i != 200

      data = JSON.parse(res.body)
      (data["tunnels"] || []).map { |t| t["public_url"] }.compact.find { |u| u.start_with?("https") }
    rescue StandardError
      nil
    end

    private def wait_until(dead_hint:, timeout: 25)
      deadline = Time.now + timeout # rubocop:disable Rails/TimeZone -- stdlib
      while Time.now < deadline # rubocop:disable Rails/TimeZone -- stdlib
        val = yield
        return val if val
        raise ApiError, dead_hint if @wait_thr && !@wait_thr.alive?

        sleep 0.3
      end
      raise ApiError, "timeout czekając na URL tunelu #{@kind}"
    end
  end

  # ---------------------------------------------------------------------
  # Subkomendy
  # ---------------------------------------------------------------------
  class Cli
    SUBCOMMANDS = {
      "signup" => "Załóż nowe konto NATIVE paragony.pl (product_app=fiskator) i zapisz credentiale lokalnie. " \
        "Wymaga jawnego --password.",
      "login" => "Zaloguj się (email+hasło) na ISTNIEJĄCE konto, zdobądź api_token i zapisz credentiale.",
      "configure" => "Ustaw/pokaż zapisaną konfigurację (host/prefix/api_token) ręcznie, bez signupu.",
      "token:create" => "Utwórz nowy api_token na koncie (POST /account/api_tokens.json) — do podpięcia aplikacji.",
      "token:list" => "Wylistuj api_tokeny konta (GET /account/api_tokens.json) — bez surowych tokenów.",
      "printer:list" => "Wylistuj drukarki konta (GET /printers.json).",
      "printer:register" => "Zarejestruj/zaktualizuj drukarkę na koncie (POST update_printer.json) — wymagane przed pr:create.",
      "pr:create" => "Utwórz print_request (POST /print_requests) — domyślnie mode=print (papier).",
      "pr:show" => "Pokaż status i dane print_requesta (GET /print_requests/:id.json).",
      "pr:update" => "\"Edycja\" print_requesta = cancel + create-anew (patrz limitations w help) z nowymi danymi.",
      "pr:cancel" => "Anuluj print_request (DELETE /print_requests/:id.json).",
      "pr:watch" => "Odpytuj status print_requesta co --interval sekund aż do statusu terminalnego; " \
        "dzwoni+powiadamia gdy wydrukowany.",
      "webhook:create" => "Utwórz connector webhooków (kind=paragony/callback) na wskazany URL (POST /connect/connectors.json).",
      "webhook:serve" => "All-in-one: podnieś tunel (cloudflared/ngrok), zarejestruj connector i nasłuchuj webhooków statusu PR.",
      "webhook:show" => "Pokaż aktualny connector webhooków (GET /connect/connectors/<code>.json).",
      "webhook:update" => "Zmień URL (i opcjonalnie sekret) istniejącego connectora webhooków.",
      "webhook:delete" => "Usuń connector webhooków (DELETE /connect/connectors/<code>.json).",
      "help" => "Ta pomoc.",
    }.freeze

    def initialize(argv)
      @argv = argv
      @global_opts = { verbose: false, credentials: CREDENTIALS_PATH }
    end

    def run
      sub = @argv.shift
      return print_help if sub == nil || sub == "help" || sub == "-h" || sub == "--help"

      unless SUBCOMMANDS.key?(sub)
        warn "Nieznana subkomenda: #{sub.inspect}\n\n"
        print_help
        exit 1
      end

      creds = Credentials.load(@global_opts[:credentials])
      method_name = "cmd_#{sub.gsub(/[:\-]/, "_")}"
      send(method_name, creds)
    rescue ApiError => e
      warn "BŁĄD: #{e.message}"
      warn "  HTTP #{e.code}: #{e.body}" if e.code
      exit 1
    end

    def print_help
      puts "Użycie: ruby #{File.basename(__FILE__)} <subcommand> [opcje]"
      puts
      puts "Subkomendy:"
      SUBCOMMANDS.each { |name, desc| puts "  #{name.ljust(18)} #{desc}" }
      puts
      puts "Uwagi/ograniczenia:"
      puts "  - DOMYŚLNIE celujemy w PRODUKCJĘ #{DEFAULT_DOMAIN} (#{DEFAULT_SCHEME}). `signup` zakłada REALNE"
      puts "    konto — do pracy na dev użyj: --domain paragony.test --scheme http."
      puts "  - `signup` wymaga jawnego --password (brak domyślnego hasła) — zakłada realne konto."
      puts "  - Auth: standardowy nagłówek Authorization: Bearer <jwt> — JWT mintowany per-request z api_token"
      puts "    (sekret=api_token, payload {key: SHA256(api_token)[0,16], exp})."
      puts "  - `login`/`token:create` to JEDYNE momenty, gdy hub zwraca SUROWY api_token — zapisz go od razu."
      puts "    `token:list` pokazuje tylko metadane (hub nie ujawnia tokenów w listingu/show)."
      puts "  - `pr:update` NIE używa surowego PATCH /print_requests/:id (choć route istnieje):"
      puts "    ten endpoint nie zmienia treści paragonu, a podanie `status` tą drogą OMIJA maszynę"
      puts "    stanów (naliczanie zużycia) — niebezpieczne dla integratora. Dlatego `pr:update`"
      puts "    w tym skrypcie robi cancel (DELETE) + create-anew (POST)."
      puts "  - `pr:cancel` (DELETE) na zleceniu to_print/printing zwraca status \"cancelled\", a starsza"
      puts "    wersja huba \"error\". Skrypt uznaje oba za 'anulowane' i wypisuje status, który dostał."
      puts "  - Webhooki: dostawa jest ASYNCHRONICZNA (kolejka po stronie huba), więc zdarzenie przychodzi"
      puts "    z opóźnieniem po zmianie statusu zlecenia — `pr:watch` widzi status wcześniej niż odbiornik"
      puts "    webhooka. webhook:create/show/update/delete to czyste HTTP (publiczne /connect/connectors)."
      puts "  - `webhook:serve` (all-in-one) sam podnosi tunel (cloudflared rekomendowany — bez konta;"
      puts "    ngrok wymaga `ngrok config add-authtoken`), rejestruje connector na URL tunelu i nasłuchuje."
      puts "    Bez binarki tunelu podaj własny --url (np. z ngroka) lub --tunnel none + --url."
      puts "    Weryfikuje podpis (JWT HS256, bh nad SUROWYM body, exp); `htu` bywa różny od bind-adresu"
      puts "    (za tunelem), więc jest tylko informacyjny."
      puts "  - `--vendor` (default intum) idzie w print_request.vendor i steruje routingiem webhooków:"
      puts "    PR wiąże się z connectorem paragony-<vendor>. Hub vendora WYMAGA (walidacja presence,"
      puts "    bez defaultu — dokument bez efektywnego vendora odpada z błędem); batch-level `vendor`"
      puts "    można nadpisać per dokument (print_requests[].vendor)."
      puts "  - Print request wymaga istniejącej drukarki na koncie (print_requests[].printer_id, fallback"
      puts "    printer_name, fallback default_printer, fallback pierwsza istniejąca) — użyj najpierw"
      puts "    printer:register."
      puts "  - `--email` jest opcjonalny także dla `--mode e_receipt`: bez adresu e-paragon"
      puts "    powstaje normalnie (link masz w `view_url`), tylko mail nie wychodzi. Podany adres"
      puts "    włącza automatyczną wysyłkę i zużywa pierwszą z 5 prób wysyłki na zlecenie."
      puts
      puts "Credentiale: #{CREDENTIALS_PATH} (nadpisz zmienną PARAGONY_CLIENT_CREDENTIALS)"
    end

    # -----------------------------------------------------------------
    # signup
    # -----------------------------------------------------------------
    def cmd_signup(creds)
      opts = { domain: DEFAULT_DOMAIN, scheme: DEFAULT_SCHEME, app_host: nil, prefix: nil, email: nil,
               password: nil, verbose: false }
      OptionParser.new do |o|
        o.banner = "Użycie: signup [opcje]"
        o.on("--domain DOMAIN", "domena konta (default: #{DEFAULT_DOMAIN}; dev: paragony.test)") { |v| opts[:domain] = v }
        o.on("--scheme SCHEME", "http|https (default: #{DEFAULT_SCHEME}; dev: http)") { |v| opts[:scheme] = v }
        o.on("--app-host HOST", "host rejestracji (default: app.<domain>, np. app.paragony.pl)") { |v| opts[:app_host] = v }
        o.on("--prefix PREFIX", "prefix konta (default: paragony-cli-test-<timestamp>)") { |v| opts[:prefix] = v }
        o.on("--email EMAIL", "email użytkownika (default: <prefix>@example.com)") { |v| opts[:email] = v }
        o.on("--password PASS", "hasło (WYMAGANE — bez domyślnego)") { |v| opts[:password] = v }
        o.on("-v", "--verbose", "loguj requesty/response") { opts[:verbose] = true }
      end.parse!(@argv)

      # `signup` zakłada REALNE konto, więc hasło musi podać wołający — domyślne hasło w skrypcie
      # rozdawanym integratorom byłoby hasłem znanym wszystkim, na realnych kontach.
      raise ApiError, "--password jest wymagany (signup zakłada realne konto)" if opts[:password].to_s.empty?

      opts[:prefix] ||= "paragony-cli-test-#{Time.now.to_i}"
      opts[:email] ||= "#{opts[:prefix]}@example.com"
      # Rejestracja idzie na host aplikacji (app.<domain>), bo gołe paragony.pl to strona
      # marketingowa. Samo konto żyje potem pod <prefix>.<domain> (creds.domain = domain).
      opts[:app_host] ||= "#{REGISTRATION_PREFIX}.#{opts[:domain]}"

      body = {
        account: { prefix: opts[:prefix] },
        user: { email: opts[:email], password: opts[:password], password_confirmation: opts[:password] },
      }

      code, json, raw = Http.raw_call(
        scheme: opts[:scheme], host: opts[:app_host], method: :post,
        path: "/account/accounts.json", body: body, verbose: opts[:verbose]
      )
      raise ApiError.new("Signup nieudany", code: code, body: raw) unless code == 201

      creds.scheme = opts[:scheme]
      creds.domain = opts[:domain]
      creds.prefix = json["prefix"]
      creds.login = json.dig("user", "login")
      creds.email = opts[:email]
      creds.api_token = json.dig("user", "api_token")
      creds.account_id = json["id"] # zwykle brak w JSON (as_json bez id) — spróbujemy też z Location
      creds.created_at = Time.now.iso8601
      creds.save!(@global_opts[:credentials])

      puts "Konto założone: prefix=#{creds.prefix} login=#{creds.login} url=#{creds.base_url}"
      puts "api_token zapisany w credentialach (#{@global_opts[:credentials]})."
      puts "product_app=#{json["product_app"]} (oczekiwane: fiskator)"
    end

    # -----------------------------------------------------------------
    # login — zaloguj się na ISTNIEJĄCE konto (email/login+hasło), zdobądź api_token, zapisz creds.
    # Hub nie ma endpointu "pokaż token" — jedyna droga to: login sesyjny (cookie) + utworzenie
    # tokena for_account (POST /account/api_tokens.json, jedyne miejsce zwracające surowy token).
    # CSRF jest pomijane dla format.json po stronie huba, więc cookie sesji wystarcza.
    # -----------------------------------------------------------------
    def cmd_login(creds)
      opts = {
        domain: creds.domain || DEFAULT_DOMAIN,
        scheme: creds.scheme || DEFAULT_SCHEME,
        prefix: creds.prefix,
        identifier: creds.email || creds.login,
        password: nil,
        name: "paragony-cli",
        for_account: true,
        verbose: false,
      }
      OptionParser.new do |o|
        o.banner = "Użycie: login --prefix P --email E --password H [opcje]"
        o.on("--domain DOMAIN", "domena huba (default: #{DEFAULT_DOMAIN})") { |v| opts[:domain] = v }
        o.on("--scheme SCHEME", "http|https (default: #{DEFAULT_SCHEME})") { |v| opts[:scheme] = v }
        o.on("--prefix PREFIX", "prefix konta (subdomena)") { |v| opts[:prefix] = v }
        o.on("--email EMAIL", "email użytkownika (albo --login)") { |v| opts[:identifier] = v }
        o.on("--login LOGIN", "login użytkownika (albo --email)") { |v| opts[:identifier] = v }
        o.on("--password PASS", "hasło") { |v| opts[:password] = v }
        o.on("--name NAME", "nazwa tworzonego tokena (default: paragony-cli)") { |v| opts[:name] = v }
        o.on("--no-for-account", "token użytkownika zamiast for_account") { opts[:for_account] = false }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      raise ApiError, "--prefix jest wymagany" if opts[:prefix].to_s.empty?
      raise ApiError, "--email albo --login jest wymagany" if opts[:identifier].to_s.empty?
      raise ApiError, "--password jest wymagany" if opts[:password].to_s.empty?

      host = "#{opts[:prefix]}.#{opts[:domain]}"

      # 1) login sesyjny — interesuje nas Set-Cookie (sesja), nie body
      l_code, _l_json, l_raw, l_res = Http.raw_call(
        scheme: opts[:scheme], host: host, method: :post, path: "/login.json",
        body: { log_in: { login: opts[:identifier], email: opts[:identifier], password: opts[:password] } },
        verbose: opts[:verbose]
      )
      unless l_code == 200
        hint = l_code == 401 ? "błędny login/hasło" : "kod #{l_code} — możliwe 2FA (utwórz token ręcznie w UI) lub zły prefix/host"
        raise ApiError.new("login nieudany (#{hint})", code: l_code, body: l_raw)
      end

      cookie_header = (l_res.get_fields("set-cookie") || []).map { |c| c.split(";", 2).first }.join("; ")
      raise ApiError.new("login nie ustawił sesji (brak Set-Cookie)", code: l_code, body: l_raw) if cookie_header.empty?

      # 2) utwórz api_token (jedyny moment, gdy hub zwraca surowy token)
      t_code, t_json, t_raw = Http.raw_call(
        scheme: opts[:scheme], host: host, method: :post, path: "/account/api_tokens.json",
        headers: { "Cookie" => cookie_header },
        body: { api_token: { for_account: opts[:for_account], name: opts[:name] } },
        verbose: opts[:verbose]
      )
      raise ApiError.new("utworzenie api_tokena nieudane", code: t_code, body: t_raw) unless t_code == 201

      token = t_json["token"]
      raise ApiError.new("hub nie zwrócił tokena", code: t_code, body: t_raw) if token.to_s.empty?

      creds.scheme = opts[:scheme]
      creds.domain = opts[:domain]
      creds.prefix = opts[:prefix]
      creds.email = opts[:identifier]
      creds.api_token = token
      creds.created_at = Time.now.iso8601 # rubocop:disable Rails/TimeZone -- stdlib
      creds.save!(@global_opts[:credentials])

      puts "Zalogowano na #{creds.base_url}."
      puts "Utworzono api_token id=#{t_json["id"]} name=#{t_json["name"].inspect} for_account=#{t_json["for_account"]}"
      puts "api_token (pełny — zapisz, hub go już nie pokaże): #{token}"
      puts "Zapisano w credentialach (#{@global_opts[:credentials]})."
    end

    # -----------------------------------------------------------------
    # configure — ręczne ustawienie/pokazanie configu (gdy user ma już konto)
    # -----------------------------------------------------------------
    def cmd_configure(creds)
      opts = {}
      OptionParser.new do |o|
        o.banner = "Użycie: configure [--show] [--domain D] [--scheme S] [--prefix P] [--api-token T] [--login L]"
        o.on("--show", "pokaż aktualną konfigurację i zakończ") { opts[:show] = true }
        o.on("--domain DOMAIN") { |v| opts[:domain] = v }
        o.on("--scheme SCHEME") { |v| opts[:scheme] = v }
        o.on("--prefix PREFIX") { |v| opts[:prefix] = v }
        o.on("--api-token TOKEN") { |v| opts[:api_token] = v }
        o.on("--login LOGIN") { |v| opts[:login] = v }
      end.parse!(@argv)

      if opts[:show] || opts.empty?
        if creds.present?
          puts "scheme=#{creds.scheme} domain=#{creds.domain} prefix=#{creds.prefix} login=#{creds.login} " \
            "account_id=#{creds.account_id} api_token=#{mask(creds.api_token)} webhook_code=#{creds.webhook_code}"
        else
          puts "Brak zapisanej konfiguracji (#{@global_opts[:credentials]}). Użyj `signup` albo podaj flagi ręcznie."
        end
        return
      end

      creds.domain = opts[:domain] if opts[:domain]
      creds.scheme = opts[:scheme] if opts[:scheme]
      creds.prefix = opts[:prefix] if opts[:prefix]
      creds.api_token = opts[:api_token] if opts[:api_token]
      creds.login = opts[:login] if opts[:login]
      creds.save!(@global_opts[:credentials])
      puts "Zapisano."
    end

    def mask(token)
      return if token == nil

      "#{token[0, 6]}...#{token[-4, 4]}"
    end

    # -----------------------------------------------------------------
    # token:create — utwórz kolejny api_token przez JWT (gdy konto już skonfigurowane).
    # POST /account/api_tokens.json to jedyny endpoint zwracający SUROWY token.
    # -----------------------------------------------------------------
    def cmd_token_create(creds)
      opts = { name: "paragony-cli-app", for_account: true, integration_app_code: nil, code: nil, save: false, verbose: false }
      OptionParser.new do |o|
        o.banner = "Użycie: token:create [--name N] [--integration-app-code C] [--code C] [--save]"
        o.on("--name NAME", "nazwa tokena (default: paragony-cli-app)") { |v| opts[:name] = v }
        o.on("--no-for-account", "token użytkownika zamiast for_account") { opts[:for_account] = false }
        o.on("--integration-app-code CODE", "kod zaufanej integracji (opcjonalnie)") { |v| opts[:integration_app_code] = v }
        o.on("--code CODE", "własny code tokena (opcjonalnie)") { |v| opts[:code] = v }
        o.on("--save", "nadpisz zapisany api_token tym nowym") { opts[:save] = true }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      http = Http.new(creds, verbose: opts[:verbose])
      api_token = { name: opts[:name], for_account: opts[:for_account] }
      api_token[:integration_app_code] = opts[:integration_app_code] if opts[:integration_app_code]
      api_token[:code] = opts[:code] if opts[:code]

      code, json, raw = http.post("/account/api_tokens.json", body: { api_token: api_token })
      raise ApiError.new("token:create nieudany", code: code, body: raw) unless code == 201

      token = json["token"]
      puts "Utworzono api_token id=#{json["id"]} name=#{json["name"].inspect} for_account=#{json["for_account"]}"
      puts "api_token (pełny — zapisz, hub go już nie pokaże): #{token}"

      if opts[:save]
        creds.api_token = token
        creds.save!(@global_opts[:credentials])
        puts "Zapisano jako aktywny api_token w credentialach."
      end
    end

    # -----------------------------------------------------------------
    # token:list — wylistuj api_tokeny (metadane, bez surowych tokenów).
    # -----------------------------------------------------------------
    def cmd_token_list(creds)
      opts = { for_account: false, verbose: false }
      OptionParser.new do |o|
        o.banner = "Użycie: token:list [--for-account] [-v]"
        o.on("--for-account", "pokaż tokeny konta (for_account) zamiast tokenów użytkownika") { opts[:for_account] = true }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      http = Http.new(creds, verbose: opts[:verbose])
      query = opts[:for_account] ? { for_account: "yes" } : nil
      code, json, raw = http.get("/account/api_tokens.json", query: query)
      raise ApiError.new("token:list nieudany", code: code, body: raw) unless code == 200

      tokens = json.is_a?(Array) ? json : []
      if tokens.empty?
        puts "Brak api_tokenów."
        return
      end

      puts format("%-6s %-24s %-12s %-11s %-7s %s", "id", "name", "kind", "for_account", "active", "expires_at")
      tokens.each do |t|
        puts format("%-6s %-24s %-12s %-11s %-7s %s",
          t["id"], t["name"].to_s, t["kind"].to_s, t["for_account"], t["active"], t["expires_at"].to_s)
      end
    end

    # -----------------------------------------------------------------
    # printer:list
    # Index huba zwraca CZYSTĄ tablicę JSON (bez metadanych paginacji), 25/stronę przez ?page=N.
    # UWAGA: pagy jest skonfigurowane z overflow=:last_page, więc strona poza zakresem zwraca
    # OSTATNIĄ stronę (niepustą), a nie pustą — dlatego kończymy, gdy strona nie wnosi NOWYCH id
    # (a nie „gdy pusta"), inaczej byłaby nieskończona pętla.
    # -----------------------------------------------------------------
    def cmd_printer_list(creds)
      opts = { json: false, verbose: false }
      OptionParser.new do |o|
        o.banner = "Użycie: printer:list [--json] [-v]"
        o.on("--json", "wypisz surowy JSON zamiast tabeli") { opts[:json] = true }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      http = Http.new(creds, verbose: opts[:verbose])
      all = []
      seen = {}
      page = 1
      loop do
        code, json, raw = http.get("/printers.json", query: { page: page })
        raise ApiError.new("printer:list nieudany", code: code, body: raw) unless code == 200

        batch = json.is_a?(Array) ? json : []
        fresh = batch.reject { |p| seen[p["id"]] }
        break if fresh.empty?

        fresh.each { |p| seen[p["id"]] = true }
        all.concat(fresh)
        page += 1
      end

      if opts[:json]
        puts JSON.pretty_generate(all)
        return
      end

      if all.empty?
        puts "Brak drukarek na koncie #{creds.prefix}."
        return
      end

      puts "Drukarki konta #{creds.prefix} (#{all.size}):"
      puts format("%-6s %-20s %-24s %-18s %-9s %-14s %s",
        "id", "uid", "name", "model", "e_recpt", "e_recpt_conf", "default_mode")
      all.each do |p|
        puts format("%-6s %-20s %-24s %-18s %-9s %-14s %s",
          p["id"], p["uid"], p["name"].to_s, p["model"].to_s,
          p["e_receipt"], p["e_receipt_configured"], p["default_mode"].to_s)
      end
    end

    # -----------------------------------------------------------------
    # printer:register
    # -----------------------------------------------------------------
    def cmd_printer_register(creds)
      opts = {
        uid: nil,
        model: "MOCK PRINTER CLI",
        connection_method: "tcp",
        e_receipt: false,
        e_receipt_configured: false,
        name: nil,
        verbose: false,
      }
      OptionParser.new do |o|
        o.banner = "Użycie: printer:register --uid UID [opcje]"
        o.on("--uid UID", "identyfikator drukarki (wymagane, klucz find_or_initialize)") { |v| opts[:uid] = v }
        o.on("--model MODEL") { |v| opts[:model] = v }
        o.on("--connection-method M", "tcp|usb|... (default: tcp)") { |v| opts[:connection_method] = v }
        o.on("--e-receipt", "drukarka ma zdolność e-paragonu") { opts[:e_receipt] = true }
        o.on("--e-receipt-configured", "e-paragon skonfigurowany/gotowy") { opts[:e_receipt_configured] = true }
        o.on("--name NAME") { |v| opts[:name] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)
      raise ApiError, "--uid jest wymagane" if opts[:uid] == nil

      http = Http.new(creds, verbose: opts[:verbose])
      printer = {
        uid: opts[:uid],
        model: opts[:model],
        connection_method: opts[:connection_method],
        e_receipt: opts[:e_receipt],
        e_receipt_configured: opts[:e_receipt_configured],
      }
      printer[:name] = opts[:name] if opts[:name]

      code, json, raw = http.post("/printers/update_printer.json", body: { printer: printer })
      raise ApiError.new("Rejestracja drukarki nieudana", code: code, body: raw) unless [200, 201].include?(code) # rubocop:disable Style/InvertibleUnlessCondition -- stdlib, bez .exclude?

      puts "Drukarka OK: id=#{json["id"]} name=#{json["name"].inspect} hub=#{json["hub"]} ready=#{json["ready"]}"
      puts "(użyj --printer-id #{json["id"]} w pr:create)"
    end

    # -----------------------------------------------------------------
    # pr:create
    # -----------------------------------------------------------------
    def cmd_pr_create(creds)
      opts = {
        external_id: "cli-#{Time.now.to_i}",
        printer_id: nil,
        printer_name: nil,
        mode: "print",
        email: nil,
        system_number: nil,
        order_number: nil,
        external_url: nil,
        kind: "receipt",
        kind_text: "Paragon",
        name: "Pozycja testowa",
        price: "10.00",
        tax: "23",
        vendor: DEFAULT_VENDOR,
        json: nil,
        verbose: false,
      }
      OptionParser.new do |o|
        o.banner = "Użycie: pr:create --printer-id ID | --printer-name NAME [opcje]"
        o.on("--vendor VENDOR", "vendor print_requesta / klucz routingu webhooka (default: #{DEFAULT_VENDOR})") { |v| opts[:vendor] = v }
        o.on("--external-id ID", "identyfikator dokumentu u vendora (default: cli-<timestamp>)") { |v| opts[:external_id] = v }
        o.on("--printer-id ID", Integer, "hubowe PK drukarki (z printer:register)") { |v| opts[:printer_id] = v }
        o.on("--printer-name NAME", "nazwa drukarki (matching po nazwie, zamiast --printer-id)") { |v| opts[:printer_name] = v }
        o.on("--mode MODE", "print|e_receipt (default: print)") { |v| opts[:mode] = v }
        o.on("--email EMAIL", "adres nabywcy — OPCJONALNY; podany włącza automatyczną wysyłkę e-paragonu mailem") { |v| opts[:email] = v }
        o.on("--system-number N") { |v| opts[:system_number] = v }
        o.on("--order-number N") { |v| opts[:order_number] = v }
        o.on("--external-url URL") { |v| opts[:external_url] = v }
        o.on("--item-name NAME", "nazwa pozycji (default: 'Pozycja testowa')") { |v| opts[:name] = v }
        o.on("--price PRICE", "cena brutto pozycji (default: 10.00)") { |v| opts[:price] = v }
        o.on("--json PATH", "pełny JSON pozycji print_requests[] (override wszystkiego powyżej)") { |v| opts[:json] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      invoice = if opts[:json]
        JSON.parse(File.read(opts[:json]))
      else
        if opts[:printer_id] == nil && opts[:printer_name] == nil
          raise ApiError, "--printer-id albo --printer-name jest wymagane (albo podaj gotowy JSON przez --json)"
        end

        # compact: klucz drukarki nieużyty w danym wywołaniu (printer_id XOR printer_name)
        # nie idzie na wire jako null.
        {
          "external_id" => opts[:external_id],
          "mode" => opts[:mode],
          "printer_id" => opts[:printer_id],
          "printer_name" => opts[:printer_name],
          "system_number" => opts[:system_number] || "CLI/#{opts[:external_id]}",
          "order_number" => opts[:order_number] || "oid-#{opts[:external_id]}",
          "external_url" => opts[:external_url] || "http://example.test/invoice/#{opts[:external_id]}",
          "kind" => opts[:kind],
          "kind_text" => opts[:kind_text],
          # `buyer` idzie na wire TYLKO z podanym adresem — pusty obiekt nabywcy nie niesie
          # informacji, a brak adresu jest dla huba poprawnym stanem (e-paragon powstaje,
          # mail nie wychodzi).
          "buyer" => (opts[:email] ? { "email" => opts[:email] } : nil),
          "positions" => [
            {
              "name" => opts[:name],
              "quantity" => "1",
              "price_gross" => opts[:price],
              "total_price_gross" => opts[:price],
              "tax" => opts[:tax],
            },
          ],
        }.compact
      end

      http = Http.new(creds, verbose: opts[:verbose])
      body = { vendor: opts[:vendor], print_requests: [invoice] }
      code, json, raw = http.post("/print_requests.json", body: body)

      unless code == 200 && json["status"] == "success"
        raise ApiError.new("Utworzenie print_requesta nieudane", code: code, body: raw)
      end

      pr = json["print_requests"].first
      puts "PR utworzony: id=#{pr["id"]} external_id=#{pr["external_id"].inspect} status prawdopodobnie to_print"
      puts "errors: #{json["errors"]}" unless json["errors"].to_a.empty?
    end

    # -----------------------------------------------------------------
    # pr:show
    # -----------------------------------------------------------------
    def cmd_pr_show(creds)
      verbose = @argv.delete("-v") || @argv.delete("--verbose")
      id = @argv.shift
      raise ApiError, "Użycie: pr:show <id>" if id == nil

      http = Http.new(creds, verbose: !!verbose)
      code, json, raw = http.get("/print_requests/#{id}.json")
      raise ApiError.new("pr:show nieudany", code: code, body: raw) unless code == 200

      puts JSON.pretty_generate(json)
    end

    # -----------------------------------------------------------------
    # pr:update — cancel + create-anew (patrz uzasadnienie w help)
    # -----------------------------------------------------------------
    def cmd_pr_update(creds)
      opts = {
        printer_id: nil,
        mode: nil,
        system_number: nil,
        order_number: nil,
        external_url: nil,
        item_name: nil,
        price: nil,
        vendor: nil,
        json: nil,
        verbose: false,
      }
      id = @argv.shift
      raise ApiError, "Użycie: pr:update <id> [opcje nowego zlecenia]" if id == nil

      OptionParser.new do |o|
        o.banner = "Użycie: pr:update <id> [opcje]"
        o.on("--vendor VENDOR", "vendor nowego zlecenia (default: vendor starego PR albo #{DEFAULT_VENDOR})") { |v| opts[:vendor] = v }
        o.on("--printer-id ID", Integer) { |v| opts[:printer_id] = v }
        o.on("--mode MODE") { |v| opts[:mode] = v }
        o.on("--email EMAIL", "adres nabywcy nowego zlecenia (default: adres ze starego)") { |v| opts[:email] = v }
        o.on("--system-number N") { |v| opts[:system_number] = v }
        o.on("--order-number N") { |v| opts[:order_number] = v }
        o.on("--external-url URL") { |v| opts[:external_url] = v }
        o.on("--item-name NAME") { |v| opts[:item_name] = v }
        o.on("--price PRICE") { |v| opts[:price] = v }
        o.on("--json PATH") { |v| opts[:json] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      http = Http.new(creds, verbose: opts[:verbose])

      # 1) przeczytaj stary PR (żeby przenieść niezmienione pola do nowego)
      code, old_pr, raw = http.get("/print_requests/#{id}.json")
      raise ApiError.new("pr:update: nie znaleziono print_requesta #{id}", code: code, body: raw) unless code == 200

      old_doc = old_pr["source_document"] || {}

      # 2) cancel starego (DELETE)
      c_code, c_json, c_raw = http.delete("/print_requests/#{id}.json")
      unless [200, 204].include?(c_code) # rubocop:disable Style/InvertibleUnlessCondition -- stdlib, bez .exclude?
        raise ApiError.new("pr:update: anulowanie starego print_requesta nieudane", code: c_code, body: c_raw)
      end

      old_status = c_json && c_json["status"]
      puts "Stare zlecenie #{id} anulowane, nowy status=#{old_status.inspect}"

      # 3) create-anew z nadpisanymi polami
      if opts[:json]
        invoice = JSON.parse(File.read(opts[:json]))
      else
        invoice = {
          "external_id" => old_pr["external_id"],
          "mode" => opts[:mode] || (old_pr["e_receipt"] ? "e_receipt" : "print"),
          "printer_id" => opts[:printer_id] || old_pr["printer_id"],
          "system_number" => opts[:system_number] || old_doc["system_number"],
          "order_number" => opts[:order_number] || old_doc["order_number"],
          "external_url" => opts[:external_url] || old_pr["external_url"],
          "kind" => old_doc["kind"] || "receipt",
          "kind_text" => old_doc["kind_text"] || "Paragon",
          # Nabywca przenosi sie ze starego zlecenia jak reszta niezmienionych pol — inaczej
          # "edycja" e-paragonu cicho gubilaby adres doreczenia razem z wysylka maila.
          "buyer" => (opts[:email] ? { "email" => opts[:email] } : old_doc["buyer"]),
          "positions" => if opts[:item_name] || opts[:price]
                           [{
                             "name" => opts[:item_name] || old_doc.dig("positions", 0, "name"),
                             "quantity" => "1",
                             "price_gross" => opts[:price] || old_doc.dig("positions", 0, "price_gross"),
                             "total_price_gross" => opts[:price] || old_doc.dig("positions", 0, "total_price_gross"),
                             "tax" => old_doc.dig("positions", 0, "tax") || "23",
                           }]
                         else
                           old_doc["positions"]
                         end,
        }.compact # klucze nieobecne w starym dokumencie (np. brak nabywcy) nie ida na wire jako null
      end

      vendor = opts[:vendor] || old_pr["vendor"] || DEFAULT_VENDOR
      body = { vendor: vendor, print_requests: [invoice] }
      n_code, n_json, n_raw = http.post("/print_requests.json", body: body)
      unless n_code == 200 && n_json["status"] == "success"
        raise ApiError.new(
          "pr:update: utworzenie nowego print_requesta nieudane (stary już anulowany!)",
          code: n_code, body: n_raw
        )
      end

      pr = n_json["print_requests"].first
      puts "Nowe zlecenie utworzone: id=#{pr["id"]} external_id=#{pr["external_id"].inspect}"
    end

    # -----------------------------------------------------------------
    # pr:cancel
    # -----------------------------------------------------------------
    def cmd_pr_cancel(creds)
      verbose = @argv.delete("-v") || @argv.delete("--verbose")
      id = @argv.shift
      raise ApiError, "Użycie: pr:cancel <id>" if id == nil

      http = Http.new(creds, verbose: !!verbose)
      code, json, raw = http.delete("/print_requests/#{id}.json")
      raise ApiError.new("pr:cancel nieudany", code: code, body: raw) unless [200, 204].include?(code) # rubocop:disable Style/InvertibleUnlessCondition -- stdlib, bez .exclude?

      status = json && json["status"]
      if status == "cancelled"
        puts "PR #{id} anulowany, status=\"cancelled\"."
      elsif status == "error"
        puts "PR #{id} anulowany, status=\"error\" (starsza wersja huba nie zna \"cancelled\" — patrz help)."
      elsif code == 204
        puts "PR #{id} twardo usunięty (204, ścieżka system_admin — brak body)."
      else
        puts "PR #{id}: odpowiedź #{code}, body=#{json.inspect}"
      end
    end

    # -----------------------------------------------------------------
    # pr:watch
    # -----------------------------------------------------------------
    def cmd_pr_watch(creds)
      opts = { interval: 5, timeout: 300, verbose: false }
      id = @argv.shift
      raise ApiError, "Użycie: pr:watch <id> [--interval N] [--timeout N]" if id == nil

      OptionParser.new do |o|
        o.banner = "Użycie: pr:watch <id> [opcje]"
        o.on("--interval N", Integer, "sekundy między pollami (default: 5)") { |v| opts[:interval] = v }
        o.on("--timeout N", Integer, "maks. czas czekania w sekundach (default: 300)") { |v| opts[:timeout] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      http = Http.new(creds, verbose: opts[:verbose])
      deadline = Time.now + opts[:timeout] # rubocop:disable Rails/TimeZone -- stdlib, bez Time.zone
      last_status = nil

      puts "Obserwuję PR #{id} (interwał=#{opts[:interval]}s, timeout=#{opts[:timeout]}s)... Ctrl+C aby przerwać."
      loop do
        code, json, raw = http.get("/print_requests/#{id}.json")
        raise ApiError.new("pr:watch nieudany", code: code, body: raw) unless code == 200

        status = json["status"]
        if status != last_status
          puts "[#{Time.now.strftime("%H:%M:%S")}] status: #{status}" # rubocop:disable Rails/TimeZone -- stdlib
          last_status = status
        end

        if TERMINAL_STATUSES.include?(status)
          if PRINTED_STATUSES.include?(status)
            notify_printed(id, status)
          else
            puts "Zlecenie #{id} zakończone ze statusem #{status.inspect} (nie wydrukowane)."
          end
          break
        end

        if Time.now > deadline # rubocop:disable Rails/TimeZone -- stdlib, bez Time.zone
          puts "Timeout — status wciąż #{status.inspect} po #{opts[:timeout]}s."
          break
        end

        sleep opts[:interval]
      end
    end

    def notify_printed(id, status)
      message = "Print request #{id} wydrukowany! status=#{status}"
      puts message
      print "\a" # bell
      $stdout.flush
      begin
        if RUBY_PLATFORM.include?("darwin") && system("which osascript > /dev/null 2>&1")
          system("osascript", "-e", "display notification #{message.inspect} with title \"paragony_client\"")
        end
      rescue StandardError
        nil # best-effort, nie wywalaj skryptu jeśli osascript niedostępny
      end
    end

    # -----------------------------------------------------------------
    # webhook:create / show / update / delete
    # kind=paragony/callback, code w konwencji huba "paragony-<vendor>" (patrz --vendor w help).
    # Publiczne REST API (/connect/connectors), auth = ten sam JWT co reszta skryptu.
    # -----------------------------------------------------------------
    CODE_PREFIX = "paragony-"
    DEFAULT_WEBHOOK_CODE = "#{CODE_PREFIX}#{DEFAULT_VENDOR}".freeze

    # code connectora dla vendora, w konwencji huba "paragony-<vendor>".
    def self.webhook_code_for_vendor(vendor)
      "#{CODE_PREFIX}#{vendor}"
    end

    # Ustala code connectora webhooków: jawne --code > pochodne z --vendor (paragony-<vendor>) >
    # zapisane w credentialach > domyślne (paragony-<DEFAULT_VENDOR>).
    private def resolve_webhook_code(opts, creds)
      return opts[:code] if opts[:code]
      return self.class.webhook_code_for_vendor(opts[:vendor]) if opts[:vendor]

      creds.webhook_code || DEFAULT_WEBHOOK_CODE
    end

    def cmd_webhook_create(creds)
      opts = { code: nil, vendor: nil, secret: nil, verbose: false }
      url = @argv.shift
      raise ApiError, "Użycie: webhook:create <url> [--vendor V | --code CODE] [--secret SECRET]" if url == nil

      OptionParser.new do |o|
        o.on("--vendor VENDOR", "buduje code=paragony-<vendor> (default: #{DEFAULT_VENDOR})") { |v| opts[:vendor] = v }
        o.on("--code CODE", "jawny code connectora (override --vendor)") { |v| opts[:code] = v }
        o.on("--secret SECRET", "sekret do podpisu HMAC (default: losowy 40-hex)") { |v| opts[:secret] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      code = resolve_webhook_code(opts, creds)
      secret = opts[:secret] || SecureRandom.hex(20)
      http = Http.new(creds, verbose: opts[:verbose])
      action, json = ensure_webhook_connector(http, creds, code: code, url: url, secret: secret)
      puts "Connector #{action}: id=#{json["id"]} code=#{json["code"]} url=#{json["url"]}"
      puts "secret_token (hub go NIE zwraca — zapisany lokalnie w credentialach do weryfikacji podpisu): #{secret}"
    end

    # Upsert connectora paragony/callback: PATCH gdy istnieje, POST gdy nie. Zapisuje code+secret
    # w credentialach (secret potrzebny do weryfikacji podpisu w webhook:serve). Zwraca [action, json].
    private def ensure_webhook_connector(http, creds, code:, url:, secret:)
      g_code, = http.get("/connect/connectors/#{code}.json")
      if g_code == 200
        connector = { url: url, secret_token: secret }
        p_code, json, raw = http.patch("/connect/connectors/#{code}.json", body: { connector: connector })
        raise ApiError.new("aktualizacja connectora webhooków nieudana", code: p_code, body: raw) unless p_code == 200

        action = "zaktualizowany"
      else
        connector = { kind: "paragony/callback", code: code, url: url, secret_token: secret }
        c_code, json, raw = http.post("/connect/connectors.json", body: { connector: connector })
        raise ApiError.new("utworzenie connectora webhooków nieudane", code: c_code, body: raw) unless c_code == 201

        action = "utworzony"
      end

      creds.webhook_code = code
      creds.webhook_secret = secret
      creds.save!(@global_opts[:credentials])
      [action, json]
    end

    def cmd_webhook_show(creds)
      opts = { code: nil, vendor: nil, verbose: false }
      OptionParser.new do |o|
        o.on("--vendor VENDOR") { |v| opts[:vendor] = v }
        o.on("--code CODE") { |v| opts[:code] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      connector_code = resolve_webhook_code(opts, creds)
      http = Http.new(creds, verbose: opts[:verbose])
      code, json, raw = http.get("/connect/connectors/#{connector_code}.json")
      raise ApiError.new("webhook:show nieudany", code: code, body: raw) unless code == 200

      puts JSON.pretty_generate(json)
    end

    def cmd_webhook_update(creds)
      opts = { code: nil, vendor: nil, secret: nil, verbose: false }
      url = @argv.shift
      raise ApiError, "Użycie: webhook:update <url> [--vendor V | --code CODE] [--secret NOWY_SEKRET]" if url == nil

      OptionParser.new do |o|
        o.on("--vendor VENDOR") { |v| opts[:vendor] = v }
        o.on("--code CODE") { |v| opts[:code] = v }
        o.on("--secret SECRET", "rotacja sekretu (opcjonalnie)") { |v| opts[:secret] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      connector_code = resolve_webhook_code(opts, creds)
      http = Http.new(creds, verbose: opts[:verbose])
      connector = { url: url }
      connector[:secret_token] = opts[:secret] if opts[:secret]
      code, json, raw = http.patch("/connect/connectors/#{connector_code}.json", body: { connector: connector })
      raise ApiError.new("webhook:update nieudany", code: code, body: raw) unless code == 200

      creds.webhook_code = connector_code
      creds.webhook_secret = opts[:secret] if opts[:secret]
      creds.save!(@global_opts[:credentials])
      puts "Connector zaktualizowany: id=#{json["id"]} url=#{json["url"]}"
      puts "Nowy secret_token zapisany na hubie i lokalnie: #{opts[:secret]}" if opts[:secret]
    end

    def cmd_webhook_delete(creds)
      opts = { code: nil, vendor: nil, verbose: false }
      OptionParser.new do |o|
        o.on("--vendor VENDOR") { |v| opts[:vendor] = v }
        o.on("--code CODE") { |v| opts[:code] = v }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      connector_code = resolve_webhook_code(opts, creds)
      http = Http.new(creds, verbose: opts[:verbose])
      code, _json, raw = http.delete("/connect/connectors/#{connector_code}.json")
      raise ApiError.new("webhook:delete nieudany", code: code, body: raw) unless code == 204

      puts "Connector #{connector_code} usunięty."
    end

    # -----------------------------------------------------------------
    # webhook:serve — all-in-one: (opcjonalnie) podnieś tunel, zarejestruj connector, nasłuchuj.
    # Weryfikuje podpis każdego webhooka (JWT HS256 + bh nad SUROWYM body + exp) i wypisuje eventy.
    # -----------------------------------------------------------------
    def cmd_webhook_serve(creds)
      opts = {
        port: 9292, path: "/", url: nil, tunnel: "auto",
        code: nil, vendor: nil, secret: nil,
        register: true, verbose: false,
      }
      OptionParser.new do |o|
        o.banner = "Użycie: webhook:serve [--url URL] [--tunnel cloudflared|ngrok|none] [--port N] [--path P]"
        o.on("--port N", Integer, "port lokalny (default: 9292)") { |v| opts[:port] = v }
        o.on("--path P", "ścieżka webhooka (default: /)") { |v| opts[:path] = v }
        o.on("--url URL", "własny publiczny URL (pomija auto-tunel)") { |v| opts[:url] = v }
        o.on("--tunnel MODE", "cloudflared|ngrok|none (default: auto-detekcja)") { |v| opts[:tunnel] = v }
        o.on("--vendor VENDOR", "buduje code=paragony-<vendor> (default: #{DEFAULT_VENDOR})") { |v| opts[:vendor] = v }
        o.on("--code CODE", "jawny code connectora (override --vendor)") { |v| opts[:code] = v }
        o.on("--secret SECRET", "sekret HMAC (default: z creds albo losowy przy rejestracji)") { |v| opts[:secret] = v }
        o.on("--no-register", "nie twórz/aktualizuj connectora — tylko nasłuchuj") { opts[:register] = false }
        o.on("-v", "--verbose") { opts[:verbose] = true }
      end.parse!(@argv)

      connector_code = resolve_webhook_code(opts, creds)
      tunnel = nil
      begin
        # 1) publiczny URL: własny --url albo auto-tunel
        public_url = opts[:url]
        if public_url == nil && opts[:tunnel] != "none"
          kind = Tunnel.available_kind(opts[:tunnel])
          if kind == nil
            raise ApiError, "brak cloudflared/ngrok w PATH — zainstaluj (`brew install cloudflared`), " \
              "podaj własny --url, albo --tunnel none"
          end

          tunnel = Tunnel.new(port: opts[:port], kind: kind, verbose: opts[:verbose])
          base = tunnel.start
          public_url = "#{base.chomp("/")}#{opts[:path]}"
          puts "Tunel #{kind}: #{public_url} → localhost:#{opts[:port]}"
        end

        # 2) sekret + (opcjonalnie) rejestracja connectora na publicznym URL
        secret = opts[:secret] || creds.webhook_secret
        if opts[:register]
          if public_url.to_s.empty?
            raise ApiError, "brak publicznego URL do rejestracji — podaj --url albo pozwól podnieść tunel (nie --tunnel none)"
          end

          secret ||= SecureRandom.hex(20)
          http = Http.new(creds, verbose: opts[:verbose])
          action, json = ensure_webhook_connector(http, creds, code: connector_code, url: public_url, secret: secret)
          puts "Connector #{action}: code=#{json["code"]} url=#{json["url"]}"
        end

        if secret.to_s.empty?
          raise ApiError, "brak sekretu do weryfikacji — użyj --secret, uruchom najpierw webhook:create, " \
            "albo pozwól na rejestrację (bez --no-register)"
        end

        # 3) nasłuch
        serve_webhooks(port: opts[:port], path: opts[:path], secret: secret, verbose: opts[:verbose])
      ensure
        tunnel&.stop
      end
    end

    # Pętla akceptująca połączenia. Ctrl+C kończy czysto.
    private def serve_webhooks(port:, path:, secret:, verbose:)
      $stdout.sync = true # serwer długo żyje — bez tego eventy zawisają w buforze (stdout do pliku/pipe)
      server = TCPServer.new("0.0.0.0", port)
      puts "Nasłuchuję webhooków na http://0.0.0.0:#{port}#{path} (Ctrl+C aby zakończyć)..."
      loop do
        client = server.accept
        handle_webhook_connection(client, secret: secret, verbose: verbose)
      end
    rescue Interrupt
      puts "\nZatrzymano serwer webhooków."
    ensure
      begin
        server&.close
      rescue StandardError
        nil
      end
    end

    # Parsuje jedno żądanie HTTP/1.1, weryfikuje podpis i odpowiada. Body czytamy DOKŁADNIE po
    # Content-Length jako SUROWE bajty — `bh` liczone jest nad nimi (reparsowanie JSON rozjechałoby hash).
    private def handle_webhook_connection(client, secret:, verbose:)
      request_line = client.gets
      return if request_line == nil

      method = request_line.split(" ").first
      headers = {}
      while (line = client.gets) && line != "\r\n" && line != "\n"
        key, value = line.split(":", 2)
        headers[key.strip.downcase] = value.to_s.strip if value
      end
      length = headers["content-length"].to_i
      body = length > 0 ? client.read(length).to_s : ""
      warn "--> #{method} (#{length}B)" if verbose

      status, payload = process_webhook(method: method, headers: headers, body: body, secret: secret)
      respond(client, status, payload)
    rescue StandardError => e
      warn "[webhook] błąd obsługi połączenia: #{e.message}"
    ensure
      begin
        client.close
      rescue StandardError
        nil
      end
    end

    # Weryfikacja + dispatch. Zwraca [status_http, hash_odpowiedzi].
    private def process_webhook(method:, headers:, body:, secret:)
      token = headers["authorization"].to_s.sub(/\ABearer\s+/i, "")
      payload = Jwt.verify(token, secret)

      expected_bh = Jwt.b64url(Digest::SHA256.digest(body))
      return [401, { error: "bh mismatch (tampered body)" }] unless Jwt.secure_compare(expected_bh, payload["bh"].to_s)

      warn "[webhook] uwaga: htm=#{payload["htm"].inspect} (oczekiwano \"POST\")" if payload["htm"] != "POST"
      # htu celowo tylko informacyjnie — za tunelem publiczny URL różni się od bind-adresu.

      event = JSON.parse(body)
      print_event(event)
      [200, { message: "ok" }]
    rescue ApiError => e
      [401, { error: e.message }]
    rescue JSON::ParserError => e
      [400, { error: "invalid json: #{e.message}" }]
    end

    # Czytelny wypis eventu wg dyskryminatora `kind`.
    private def print_event(event)
      ts = Time.now.strftime("%H:%M:%S") # rubocop:disable Rails/TimeZone -- stdlib
      case event["kind"]
      when "print_request:update"
        pr = event["print_request"] || {}
        line = "[#{ts}] PR #{pr["id"]} ext=#{pr["external_id"].inspect} status=#{pr["status"]}"
        line += " view_url=#{pr["view_url"]}" if pr["view_url"]
        puts line
      when "printer:create", "printer:update", "printer:destroy"
        printer = event["printer"] || {}
        puts "[#{ts}] #{event["kind"]} printer id=#{printer["id"]} uid=#{printer["uid"].inspect}"
      else
        puts "[#{ts}] #{event["kind"] || "?"}: #{event.to_json}"
      end
    end

    # Minimalna odpowiedź HTTP/1.1 (Connection: close).
    private def respond(client, status, payload)
      body = JSON.generate(payload)
      reason = { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized" }.fetch(status, "OK")
      client.write("HTTP/1.1 #{status} #{reason}\r\n")
      client.write("Content-Type: application/json\r\n")
      client.write("Content-Length: #{body.bytesize}\r\n")
      client.write("Connection: close\r\n\r\n")
      client.write(body)
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  ParagonyClient::Cli.new(ARGV).run
end
