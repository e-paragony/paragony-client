import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { ApiError } from "./errors.js";
import { sleep } from "./util.js";

// Tunnel: podnosi publiczny tunel HTTPS do lokalnego portu (dla webhook:serve), żeby hub paragony.pl
// mógł dostarczyć webhooki na maszynę deweloperską za NAT-em. Zewnętrzna BINARKA (nie zależność npm):
// cloudflared (rekomendowany, quick tunnel bez konta) albo ngrok (wymaga jednorazowego authtokena).
// Proces tunelu jest ubijany w stop().
export class Tunnel {
  // Zwraca nazwę pierwszej dostępnej binarki tunelu (albo null). preferred: "cloudflared"/"ngrok"/"auto".
  static availableKind(preferred = null) {
    const candidates = preferred && preferred !== "auto" ? [preferred] : ["cloudflared", "ngrok"];
    return candidates.find((bin) => spawnSync("which", [bin], { stdio: "ignore" }).status === 0) || null;
  }

  constructor({ port, kind, verbose = false }) {
    this.port = port;
    this.kind = kind;
    this.verbose = verbose;
    this.publicUrl = null;
    this.urlRegex = null;
    this.proc = null;
    this.dead = false;
  }

  // Podnosi tunel i zwraca publiczny URL bazowy (bez ścieżki webhooka).
  async start() {
    if (this.kind === "cloudflared") return this.startCloudflared();
    if (this.kind === "ngrok") return this.startNgrok();
    throw new ApiError(`nieobsługiwany tunel: ${JSON.stringify(this.kind)}`);
  }

  stop() {
    try {
      if (this.proc && !this.dead) this.proc.kill("SIGTERM");
    } catch {
      // best-effort
    }
  }

  // cloudflared quick tunnel — URL wypada w logu jako https://<x>.trycloudflare.com
  async startCloudflared() {
    this.urlRegex = /https:\/\/[-a-z0-9]+\.trycloudflare\.com/;
    this.spawnProc("cloudflared", ["tunnel", "--url", `http://localhost:${this.port}`, "--no-autoupdate"]);
    await this.waitUntil(
      "cloudflared padł przed podaniem URL (zainstalowany? `brew install cloudflared`)",
      () => this.publicUrl
    );
    return this.publicUrl;
  }

  // ngrok — URL bierzemy z lokalnego API :4040 (log ngroka nie zawsze go niesie czytelnie).
  async startNgrok() {
    this.spawnProc("ngrok", ["http", String(this.port), "--log", "stdout"]);
    this.publicUrl = await this.waitUntil(
      "ngrok padł — czy ustawiono authtoken? (`ngrok config add-authtoken <token>`)",
      () => this.fetchNgrokUrl()
    );
    return this.publicUrl;
  }

  spawnProc(cmd, args) {
    try {
      this.proc = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      throw new ApiError(`brak binarki ${cmd} w PATH`);
    }
    this.proc.on("error", () => { this.dead = true; });
    this.proc.on("exit", () => { this.dead = true; });

    const onLine = (line) => {
      if (this.verbose) process.stderr.write(`[tunnel] ${line}\n`);
      if (this.urlRegex && this.publicUrl == null) {
        const m = line.match(this.urlRegex);
        if (m) this.publicUrl = m[0];
      }
    };
    this.attachLineReader(this.proc.stdout, onLine);
    this.attachLineReader(this.proc.stderr, onLine);
  }

  attachLineReader(stream, onLine) {
    if (!stream) return;
    let buf = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        onLine(buf.slice(0, idx));
        buf = buf.slice(idx + 1);
      }
    });
  }

  async fetchNgrokUrl() {
    const data = await new Promise((resolve) => {
      const req = http.get("http://127.0.0.1:4040/api/tunnels", (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            resolve(null);
          }
        });
      });
      req.on("error", () => resolve(null));
    });
    if (!data) return null;
    return (data.tunnels || [])
      .map((t) => t.public_url)
      .filter(Boolean)
      .find((u) => u.startsWith("https")) || null;
  }

  async waitUntil(deadHint, fn, timeoutMs = 25000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const val = await fn();
      if (val) return val;
      if (this.dead) throw new ApiError(deadHint);
      await sleep(300);
    }
    throw new ApiError(`timeout czekając na URL tunelu ${this.kind}`);
  }
}
