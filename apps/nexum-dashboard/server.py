#!/usr/bin/env python3
"""MANUAL: local GUI prototype. No real vault, signatures, Tor or Monero."""

import argparse
import hmac
import json
import re
import secrets
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PUBLIC = Path(__file__).with_name("public")
LAB_STATE_PATH = Path(__import__("os").environ.get(
    "NXMS_LAB_STATE", str(Path.home() / ".local/share/nxms-lab/lab.json")))
TASKS_STATE_PATH = Path(__import__("os").environ.get(
    "NXMS_TASKS_STATE", str(Path.home() / ".local/share/nxms-tasks/")))
DEMO_PASSWORD = "nexum-demo-2026"
CHALLENGE_TTL = 120
ACCESS_TTL = 300
SESSION_TTL = 1800
MAX_SESSIONS = 32
MAX_BODY = 4096
ESCROWS = {
    "NX-DEMO-041": {"id": "NX-DEMO-041", "amount": "1,25 XMR", "title": "Escrow demonstracyjne", "role": "Kupujący"},
    "NX-DEMO-042": {"id": "NX-DEMO-042", "amount": "0,48 XMR", "title": "Drugie escrow demonstracyjne", "role": "Sprzedawca"},
}


def iso(timestamp=None):
    return datetime.fromtimestamp(time.time() if timestamp is None else timestamp, timezone.utc).isoformat()


class DemoError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


class DemoSession:
    def __init__(self):
        self.csrf = secrets.token_urlsafe(24)
        self.last_used = time.monotonic()
        self.connected = False
        self.offline = False
        self.escrow_id = None
        self.challenge = None
        self.access_until = 0
        self.snapshot = None

    def require_connection(self):
        if not self.connected or self.offline:
            raise DemoError(503, "OFFLINE", "Symulowane połączenie jest niedostępne. Przywróć je w panelu scenariuszy.")

    def require_selection(self):
        if self.escrow_id not in ESCROWS:
            raise DemoError(409, "NO_ESCROW", "Najpierw wybierz escrow demonstracyjne.")

    def phase(self):
        if self.access_until > time.monotonic():
            return "view"
        if self.challenge and not self.challenge["used"]:
            return "challenge"
        return "select" if self.connected else "connect"

    def public_challenge(self):
        if not self.challenge:
            return None
        return {key: value for key, value in self.challenge.items() if key not in ("used", "attempts")}

    def bootstrap(self):
        return {"demo": True, "csrf": self.csrf, "phase": self.phase(),
                "connected": self.connected, "offline": self.offline,
                "escrows": list(ESCROWS.values()), "selected": self.escrow_id,
                "challenge": self.public_challenge(), "demo_password": DEMO_PASSWORD}

    def command(self, action, data):
        if action == "connect":
            self.connected, self.offline = True, False
            return {"demo": True, "connected": True}
        if action == "select":
            self.require_connection()
            escrow_id = data.get("escrow_id")
            if not isinstance(escrow_id, str) or escrow_id not in ESCROWS:
                raise DemoError(400, "UNKNOWN_ESCROW", "Wybierz jedno z syntetycznych escrow. Import prawdziwych danych nie jest dostępny.")
            self.escrow_id = escrow_id
            self.challenge, self.snapshot, self.access_until = None, None, 0
            return {"demo": True, "selected": escrow_id}
        if action == "prepare":
            self.require_connection()
            self.require_selection()
            self.challenge = {"id": "demo-" + secrets.token_hex(8), "nonce": secrets.token_hex(16),
                              "service": "nxms-demo.onion · adres syntetyczny",
                              "service_identity": "DEMO-SERVICE-01", "escrow_id": self.escrow_id,
                              "key_id": "DEMO-LOCAL-KEY-01", "scope": "escrow:read",
                              "expires_at": iso(time.time() + CHALLENGE_TTL),
                              "expires_unix": time.time() + CHALLENGE_TTL, "used": False, "attempts": 0}
            self.access_until, self.snapshot = 0, None
            return {"demo": True, "challenge": self.public_challenge()}
        if action == "confirm":
            self.require_connection()
            self.require_selection()
            challenge = self.challenge
            if not challenge or data.get("challenge_id") != challenge["id"]:
                raise DemoError(409, "CHALLENGE_MISMATCH", "To nie jest bieżące wyzwanie. Pobierz nowe challenge.")
            if challenge["used"]:
                raise DemoError(409, "CHALLENGE_USED", "To challenge zostało już wykorzystane.")
            if challenge["expires_unix"] <= time.time():
                raise DemoError(410, "CHALLENGE_EXPIRED", "Challenge wygasło. Pobierz nowe i zatwierdź je ponownie.")
            if challenge["attempts"] >= 5:
                raise DemoError(429, "TOO_MANY_ATTEMPTS", "Limit prób w demonstracji. Pobierz nowe challenge.")
            password = data.get("password")
            if not isinstance(password, str) or len(password) > 128:
                raise DemoError(400, "INVALID_PASSWORD", "Użyj wyłącznie podanego hasła demonstracyjnego.")
            challenge["attempts"] += 1
            if not hmac.compare_digest(password.encode(), DEMO_PASSWORD.encode()):
                raise DemoError(403, "WRONG_PASSWORD", "Błędne hasło demonstracyjne. Vault demo pozostaje zablokowany.")
            challenge["used"] = True
            self.access_until = time.monotonic() + ACCESS_TTL
            self.snapshot = self.make_snapshot()
            return {"demo": True, "simulated_signature": True, "access_seconds": ACCESS_TTL}
        if action == "lock":
            self.challenge, self.snapshot, self.access_until = None, None, 0
            return {"demo": True, "locked": True}
        if action == "scenario":
            scenario = data.get("scenario")
            if scenario not in ("offline", "online", "expire_challenge", "expire_access"):
                raise DemoError(400, "UNKNOWN_SCENARIO", "Nieznany scenariusz demonstracyjny.")
            if scenario in ("offline", "online"):
                self.offline = scenario == "offline"
            elif scenario == "expire_challenge":
                if self.challenge:
                    self.challenge["expires_unix"] = time.time() - 1
                    self.challenge["expires_at"] = iso(time.time() - 1)
            else:
                self.access_until = 0
            return {"demo": True, "offline": self.offline, "challenge": self.public_challenge()}
        raise DemoError(404, "NOT_FOUND", "Ta operacja nie jest dostępna w prototypie.")

    def make_snapshot(self):
        escrow = ESCROWS[self.escrow_id]
        now = time.time()
        return {**escrow, "stage": "Oczekiwanie na potwierdzenia", "revision": 3,
                "address": "DEMO · adres wpłaty nie istnieje · nie wysyłaj środków",
                "confirmations": 4, "required_confirmations": 10, "funded": True,
                "observed_at": iso(now),
                "history": [
                    {"at": iso(now - 1200), "title": "Escrow utworzone", "description": "Syntetyczne warunki przypięto do escrow."},
                    {"at": iso(now - 900), "title": "Multisig przygotowany", "description": "Symulacja pracy automatu. Nie utworzono portfela Monero."},
                    {"at": iso(now - 240), "title": "Wpłata wykryta", "description": "Dane demonstracyjne: 4 z 10 potwierdzeń."},
                ]}

    def status(self):
        self.require_selection()
        if self.access_until <= time.monotonic():
            raise DemoError(401, "ACCESS_EXPIRED", "Uprawnienie demonstracyjne wygasło. Zatwierdź nowe challenge.")
        if not self.offline:
            self.snapshot["observed_at"] = iso()
        return {"demo": True, "offline": self.offline, "fresh": not self.offline,
                "access_seconds": max(0, int(self.access_until - time.monotonic())),
                "snapshot": self.snapshot}


# --- System: zywy podgląd all-in-one (dane operacyjne, nie escrow). ---

SYSTEM_SERVICES = [
    ("nxms-monerod-a", "monero-a · monerod (Tor-only)"),
    ("nxms-wallet-rpc-a", "monero-a · wallet-rpc"),
    ("nxms-wallet-rpc-b", "monero-b · wallet-rpc"),
    ("nxms-mailbox", "mailbox · relay"),
    ("nxms-signer-a", "signer-a · capability node"),
    ("nxms-signer-b", "signer-b · capability node"),
]
TRUST_BUNDLE_PATH = Path("/etc/nxms/trust/runtime-trust.final.json")
MAILBOX_ONION_PATH = Path("/etc/nxms/trust/mailbox.onion")
MAILBOX_HEALTH_URL = "http://127.0.0.1:4010/health"
WALLET_STUBS = {"monero-a": "http://127.0.0.1:38088/json_rpc",
                "monero-b": "http://127.0.0.1:38089/json_rpc"}
AGENT_LOGS = {"signer_a": Path("/var/log/nxms-signer-a/service.log"),
              "signer_b": Path("/var/log/nxms-signer-b/service.log")}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def _log_tail(path, size=8192):
    with open(path, "rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(0, handle.tell() - size))
        return ANSI_RE.sub("", handle.read().decode("utf-8", "replace"))


def system_status():
    def services():
        names = [name for name, _ in SYSTEM_SERVICES]
        out = subprocess.run(["systemctl", "is-active", *names],
                             capture_output=True, text=True, timeout=5)
        states = out.stdout.split()
        return [{"name": name, "label": label,
                 "state": states[i] if i < len(states) else "unknown"}
                for i, (name, label) in enumerate(SYSTEM_SERVICES)]

    def mailbox_local():
        with urllib.request.urlopen(MAILBOX_HEALTH_URL, timeout=3) as response:
            return json.loads(response.read()).get("ok") is True

    def mailbox_onion():
        onion = MAILBOX_ONION_PATH.read_text().strip()
        out = subprocess.run(
            ["curl", "-s", "--max-time", "5", "--socks5-hostname", "127.0.0.1:9050",
             f"http://{onion}/health"],
            capture_output=True, text=True, timeout=8)
        return {"address": onion, "ok": json.loads(out.stdout).get("ok") is True}

    def stubs():
        result = {}
        for name, url in WALLET_STUBS.items():
            def probe(url=url):
                request = urllib.request.Request(
                    url, data=json.dumps({"jsonrpc": "2.0", "id": "1",
                                          "method": "is_multisig"}).encode(),
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(request, timeout=3) as response:
                    return "result" in json.loads(response.read())
            result[name] = _safe(probe, False)
        return result

    def trust():
        data = json.loads(TRUST_BUNDLE_PATH.read_text())
        signatures = data.get("signatures") or []
        return {"epoch": data.get("trust_epoch") or data.get("epoch") or "nieznany",
                "signers": sorted({s.get("signer_role", "?") for s in signatures}),
                "signatures": len(signatures)}

    def agents():
        result = {}
        for name, path in AGENT_LOGS.items():
            def probe(path=path):
                tail = _log_tail(path)
                lines = [line for line in tail.splitlines() if line.strip()]
                return {"started": "nxms-signer started" in tail,
                        "pull_failures": tail.count("pull failed"),
                        "last_line": lines[-1][:160] if lines else ""}
            result[name] = _safe(probe, {"started": False, "pull_failures": 0,
                                         "last_line": "brak logu"})
        return result

    def monero():
        with urllib.request.urlopen("http://127.0.0.1:38081/get_info", timeout=3) as response:
            info = json.loads(response.read())
        return {"height": info.get("height", 0),
                "synchronized": info.get("synchronized") is True,
                "nettype": "stagenet" if info.get("stagenet") else "?",
                "outgoing": info.get("outgoing_connections_count", 0)}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {name: pool.submit(fn) for name, fn in (
            ("services", services), ("local", mailbox_local), ("onion", mailbox_onion),
            ("stubs", stubs), ("monero", monero), ("trust", trust), ("agents", agents))}

    def result(name, default):
        try:
            return futures[name].result()
        except Exception:
            return default

    return {
        "live": True,
        "observed_at": iso(),
        "services": result("services", []),
        "mailbox": {"local": result("local", False),
                    "onion": result("onion", {"address": "?", "ok": False})},
        "wallet_stubs": result("stubs", {}),
        "monero": result("monero", {"height": 0, "synchronized": False,
                                    "nettype": "?", "outgoing": 0}),
        "trust": result("trust", {"epoch": "nieznany", "signers": [], "signatures": 0}),
        "agents": result("agents", {}),
    }


def lab_status():
    """Stan labu multisig — dane z tools/l.sh (lab.json), bez wywolan zewnetrznych."""
    try:
        data = json.loads(LAB_STATE_PATH.read_text())
    except (OSError, ValueError):
        data = {}
    raw = data.get("instances")
    instances = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    summary = {}
    for instance in instances:
        state = instance.get("state", "unknown")
        summary[state] = summary.get(state, 0) + 1
    return {
        "lab": True,
        "observed_at": iso(),
        "generated_at": data.get("generated_at"),
        "summary": summary,
        "instances": instances,
    }


def _text(value):
    """Pole tekstowe — obce typy z uszkodzonych zapisow nie psuja odpowiedzi."""
    return value if isinstance(value, str) else ""


def tasks_status():
    """Zadania dockerowe — kolejne instancje all-in-one z katalogu *.json."""
    try:
        files = sorted(TASKS_STATE_PATH.glob("*.json"))
    except OSError:
        files = []
    instances = []
    for path in files:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        roles = []
        roles_raw = data.get("roles")
        if isinstance(roles_raw, list):
            for role in roles_raw:
                if isinstance(role, dict):
                    roles.append({"name": _text(role.get("name")),
                                  "state": _text(role.get("state")) or "unknown",
                                  "detail": _text(role.get("detail"))})
        onion_raw = data.get("onion")
        onion = {str(key): _text(value) for key, value in onion_raw.items()} \
            if isinstance(onion_raw, dict) else {}
        instances.append({
            "id": _text(data.get("id")) or path.stem,
            "kind": _text(data.get("kind")),
            "state": _text(data.get("state")) or "unknown",
            "step": _text(data.get("step")),
            "container": _text(data.get("container")),
            "started_at": _text(data.get("started_at")),
            "finished_at": _text(data.get("finished_at")),
            "created_at": _text(data.get("created_at")),
            "roles": roles,
            "onion": onion,
            "note": _text(data.get("note")),
        })
    summary = {}
    for instance in instances:
        summary[instance["state"]] = summary.get(instance["state"], 0) + 1
    return {
        "tasks": True,
        "observed_at": iso(),
        "summary": summary,
        "instances": instances,
    }


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        super().__init__(address, Handler)
        self.sessions = {}
        self.sessions_lock = threading.RLock()

    def session(self, cookie_header, create=False):
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header or "")
        except Exception:
            cookie = SimpleCookie()
        item = cookie.get("nxms_demo")
        sid = item.value if item else ""
        now = time.monotonic()
        for key in list(self.sessions):
            if now - self.sessions[key].last_used > SESSION_TTL:
                del self.sessions[key]
        if sid not in self.sessions:
            if not create:
                raise DemoError(403, "LOCAL_SESSION", "Odśwież lokalny panel demonstracyjny.")
            if len(self.sessions) >= MAX_SESSIONS:
                raise DemoError(429, "SESSION_LIMIT", "Limit lokalnych sesji demonstracyjnych.")
            sid = secrets.token_urlsafe(24)
            self.sessions[sid] = DemoSession()
        self.sessions[sid].last_used = now
        return sid, self.sessions[sid]


class Handler(BaseHTTPRequestHandler):
    server_version = "NexumDemo/0.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass  # Never log request bodies, passwords, tokens or URL parameters.

    def local_origin(self):
        port = self.server.server_port
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        host = self.headers.get("Host", "")
        if host not in allowed or self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise DemoError(403, "LOCAL_ONLY", "Panel jest dostępny wyłącznie przez lokalny adres.")
        return "http://" + host

    def respond(self, status, payload, content_type="application/json; charset=utf-8", cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode() if isinstance(payload, dict) else payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", f"nxms_demo={cookie}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def fail(self, error):
        self.respond(error.status, {"demo": True, "error": error.code, "message": error.message})

    def do_GET(self):
        try:
            self.local_origin()
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/styles.css": ("styles.css", "text/css; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8")}
            if self.path in assets:
                filename, kind = assets[self.path]
                self.respond(200, (PUBLIC / filename).read_bytes(), kind)
                return
            if self.path == "/api/system/status":
                self.respond(200, system_status())
                return
            if self.path == "/api/lab/status":
                self.respond(200, lab_status())
                return
            if self.path == "/api/tasks/status":
                self.respond(200, tasks_status())
                return
            with self.server.sessions_lock:
                if self.path == "/api/demo/bootstrap":
                    sid, session = self.server.session(self.headers.get("Cookie"), create=True)
                    self.respond(200, session.bootstrap(), cookie=sid)
                elif self.path == "/api/demo/status":
                    _, session = self.server.session(self.headers.get("Cookie"))
                    self.respond(200, session.status())
                else:
                    raise DemoError(404, "NOT_FOUND", "Nie znaleziono zasobu.")
        except DemoError as error:
            self.fail(error)

    def do_POST(self):
        try:
            origin = self.local_origin()
            if self.headers.get("Origin") != origin:
                raise DemoError(403, "ORIGIN", "Odrzucono żądanie spoza lokalnego panelu.")
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                raise DemoError(415, "CONTENT_TYPE", "Wymagane jest lokalne żądanie JSON.")
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                raise DemoError(413, "BODY_LIMIT", "Nieprawidłowy rozmiar żądania.")
            with self.server.sessions_lock:
                _, session = self.server.session(self.headers.get("Cookie"))
                csrf = self.headers.get("X-Nexum-CSRF", "")
                if not hmac.compare_digest(csrf.encode(), session.csrf.encode()):
                    raise DemoError(403, "CSRF", "Odśwież panel przed wykonaniem tej operacji.")
            try:
                data = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                raise DemoError(400, "INVALID_JSON", "Nieprawidłowe żądanie.") from None
            if not isinstance(data, dict):
                raise DemoError(400, "INVALID_JSON", "Wymagany jest obiekt JSON.")
            actions = {"/api/demo/connect": "connect", "/api/demo/select": "select",
                       "/api/demo/challenge/prepare": "prepare", "/api/demo/challenge/confirm": "confirm",
                       "/api/demo/lock": "lock", "/api/demo/scenario": "scenario"}
            action = actions.get(self.path)
            if not action:
                raise DemoError(404, "NOT_FOUND", "Ta operacja nie istnieje w prototypie.")
            with self.server.sessions_lock:
                self.respond(200, session.command(action, data))
        except DemoError as error:
            self.fail(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    server = DemoServer((args.bind, args.port))
    print(f"Nexum DEMO: http://127.0.0.1:{args.port} — synthetic data only", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
