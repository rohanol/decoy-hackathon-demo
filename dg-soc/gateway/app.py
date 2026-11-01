"""Small fixed-upstream HTTP gateway for the isolated DeceptionGraph lab.

No request values are logged. Sessions are opaque, signed, bounded, and pinned to
one upstream for their lifetime. A process restart invalidates active sessions so
an old diversion can never silently fall back to the normal application.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_BODY = 1_048_576
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
FORWARD_HEADERS = {"accept", "accept-language", "content-type", "user-agent"}


class SessionStore:
    def __init__(self, key: bytes, ttl: int = 900, capacity: int = 4096, clock=time.time):
        if len(key) < 32:
            raise ValueError("gateway signing key must be at least 32 bytes")
        if not 30 <= ttl <= 86400 or not 1 <= capacity <= 100000:
            raise ValueError("invalid gateway session bounds")
        self.key, self.ttl, self.capacity, self.clock = key, ttl, capacity, clock
        self.rows: dict[str, tuple[str, float]] = {}
        self.lock = threading.Lock()

    def _cookie(self, sid: str) -> str:
        sig = hmac.new(self.key, sid.encode("ascii"), hashlib.sha256).hexdigest()
        return sid + "." + sig

    def resolve(self, cookie: str | None) -> tuple[str | None, str]:
        now = self.clock()
        if not cookie:
            sid = secrets.token_urlsafe(24)
            return sid, "new"
        try:
            sid, sig = cookie.rsplit(".", 1)
        except ValueError:
            return None, "tampered"
        if not (20 <= len(sid) <= 64) or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in sid):
            return None, "tampered"
        expected = hmac.new(self.key, sid.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None, "tampered"
        with self.lock:
            self._expire(now)
            row = self.rows.get(sid)
            if row is None:
                return None, "unknown"
            route, expiry = row
            self.rows[sid] = (route, min(now + self.ttl, expiry + self.ttl))
            return sid, route

    def pin(self, sid: str, route: str) -> bool:
        now = self.clock()
        with self.lock:
            self._expire(now)
            if sid not in self.rows and len(self.rows) >= self.capacity:
                return False
            current = self.rows.get(sid)
            if current and current[0] == "decoy":
                route = "decoy"
            self.rows[sid] = (route, now + self.ttl)
            return True

    def cookie(self, sid: str) -> str:
        return self._cookie(sid)

    def _expire(self, now: float) -> None:
        for sid in [k for k, (_, expiry) in self.rows.items() if expiry <= now]:
            del self.rows[sid]


class FixedUpstreamGateway:
    def __init__(self, normal: str, decoy: str, sessions: SessionStore, allowed_hosts: set[str],
                 trigger_path="/backup/backup.zip", allowed_upstream_hosts=None):
        allowed_upstream_hosts = allowed_upstream_hosts or {"192.168.77.20"}
        self.normal = self._upstream(normal, allowed_upstream_hosts)
        self.decoy = self._upstream(decoy, allowed_upstream_hosts)
        self.sessions = sessions
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.trigger_path = trigger_path

    @staticmethod
    def _upstream(url: str, allowed_hosts: set[str]) -> tuple[str, int, str]:
        parsed = urlsplit(url)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("upstreams must be fixed plain HTTP origins")
        if parsed.hostname not in allowed_hosts:
            raise ValueError("upstream host is not on the deployment allowlist")
        port = parsed.port or 80
        if not (1 <= port <= 65535):
            raise ValueError("invalid upstream port")
        prefix = parsed.path.rstrip("/")
        return parsed.hostname, port, prefix

    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        host = handler.headers.get("Host", "").lower()
        if host not in self.allowed_hosts:
            self._reply(handler, 421, b"Unsupported host\n")
            return
        if handler.command not in ALLOWED_METHODS:
            self._reply(handler, 405, b"Method not allowed\n")
            return
        if handler.headers.get("Upgrade") or handler.headers.get("Transfer-Encoding"):
            self._reply(handler, 400, b"Unsupported request framing\n")
            return
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(handler, 400, b"Invalid content length\n")
            return
        if length < 0 or length > MAX_BODY:
            self._reply(handler, 413, b"Request too large\n")
            return
        body = handler.rfile.read(length) if length else None
        raw_cookie = handler.headers.get("Cookie", "")
        session_cookie = next((part.strip()[len("dg_session="):]
                               for part in raw_cookie.split(";") if part.strip().startswith("dg_session=")), None)
        sid, route = self.sessions.resolve(session_cookie)
        if sid is None:
            self._reply(handler, 400 if route == "tampered" else 410,
                        b"Invalid gateway session\n" if route == "tampered" else b"Gateway session expired\n")
            return
        path = urlsplit(handler.path)
        if path.scheme or path.netloc or not path.path.startswith("/") or path.path.startswith("//"):
            self._reply(handler, 400, b"Invalid request target\n")
            return
        if route == "new":
            route = "decoy" if path.path == self.trigger_path else "normal"
            if not self.sessions.pin(sid, route):
                self._reply(handler, 503, b"Gateway session capacity reached\n")
                return
        elif route == "normal" and path.path == self.trigger_path:
            # Divert before forwarding the qualifying request; normal-app cookies
            # are route-scoped and therefore are not sent to the decoy.
            if not self.sessions.pin(sid, "decoy"):
                self._reply(handler, 503, b"Gateway session capacity reached\n")
                return
            route = "decoy"
        upstream = self.decoy if route == "decoy" else self.normal
        self._proxy(handler, upstream, path.path + (("?" + path.query) if path.query else ""), body, sid, route)

    def _proxy(self, h, upstream, target, body, sid, route):
        host, port, prefix = upstream
        conn = http.client.HTTPConnection(host, port, timeout=5)
        headers = {k: v for k, v in h.headers.items() if k.lower() in FORWARD_HEADERS}
        headers["X-Forwarded-For"] = h.client_address[0]
        headers["X-Forwarded-Proto"] = "http"
        headers["X-Gateway-Session"] = hashlib.sha256(sid.encode()).hexdigest()
        cookie_prefix = "dg_gateway_" + route + "_"
        scoped_cookies = []
        for part in h.headers.get("Cookie", "").split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name.startswith(cookie_prefix):
                scoped_cookies.append(name[len(cookie_prefix):] + "=" + value)
        if scoped_cookies:
            headers["Cookie"] = "; ".join(scoped_cookies)
        try:
            conn.request(h.command, prefix + target, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read(MAX_BODY + 1)
            if len(payload) > MAX_BODY:
                self._reply(h, 502, b"Upstream response too large\n")
                return
            h.send_response(response.status)
            h.send_header("Set-Cookie", "dg_session=" + self.sessions.cookie(sid) + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + str(self.sessions.ttl))
            for key, value in response.getheaders():
                if key.lower() in {"content-type", "cache-control"}:
                    h.send_header(key, value)
                elif key.lower() == "location" and value.startswith("/") and not value.startswith("//"):
                    h.send_header(key, value)
                elif key.lower() == "set-cookie":
                    cookie_name, sep, cookie_value = value.partition(";")
                    name, equals, val = cookie_name.partition("=")
                    if equals:
                        h.send_header("Set-Cookie", cookie_prefix + name + "=" + val + sep + cookie_value)
            h.send_header("Content-Length", str(len(payload)))
            h.send_header("Connection", "close")
            h.end_headers()
            if h.command != "HEAD":
                h.wfile.write(payload)
        except (OSError, http.client.HTTPException):
            # One selected upstream only; never retry a decoy request against normal.
            self._reply(h, 502, b"Selected upstream unavailable\n")
        finally:
            conn.close()

    @staticmethod
    def _reply(h, status, body):
        h.send_response(status)
        h.send_header("Content-Type", "text/plain; charset=utf-8")
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Connection", "close")
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(body)


def load_key(path: str) -> bytes:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "rb") as f:
            key = f.read(128)
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    if len(key) < 32:
        raise RuntimeError("gateway key file is invalid")
    return key


def serve():
    bind_ip = os.environ["GATEWAY_BIND_IP"]
    normal = os.environ["NORMAL_UPSTREAM"]
    decoy = os.environ["DECOY_UPSTREAM"]
    port = int(os.environ.get("GATEWAY_PORT", "8081"))
    ttl = int(os.environ.get("GATEWAY_SESSION_TTL", "900"))
    capacity = int(os.environ.get("GATEWAY_SESSION_CAPACITY", "4096"))
    key = load_key(os.environ.get("GATEWAY_KEY_PATH", "/state/gateway.key"))
    app = FixedUpstreamGateway(normal, decoy, SessionStore(key, ttl, capacity), {f"{bind_ip}:{port}", bind_ip})

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return  # request targets and client-supplied data are never written to logs
        def do_GET(self):
            if self.path == "/__health":
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            app.handle(self)
        def do_HEAD(self): app.handle(self)
        def do_POST(self): app.handle(self)
        def do_PUT(self): app.handle(self)
        def do_PATCH(self): app.handle(self)
        def do_DELETE(self): app.handle(self)
        def do_OPTIONS(self): app.handle(self)

    ThreadingHTTPServer((bind_ip, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()


