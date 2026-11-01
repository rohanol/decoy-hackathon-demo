import http.client
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gateway.app import FixedUpstreamGateway, SessionStore


class TestGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seen = {"normal": [], "decoy": []}
        def make(name):
            seen = cls.seen[name]
            class H(BaseHTTPRequestHandler):
                def do_GET(self):
                    seen.append((self.path, self.headers.get("X-Forwarded-For"), self.headers.get("Cookie"), self.headers.get("X-Forwarded-Host")))
                    body = (name + ":" + self.path).encode()
                    self.send_response(200)
                    self.send_header("Set-Cookie", ("dg_lab_session=decoycookie" if name == "decoy" else "app_session=normalcookie") + "; Path=/; HttpOnly")
                    self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                def log_message(self, *_): pass
            return H
        cls.servers = []
        for name in ("normal", "decoy"):
            server = ThreadingHTTPServer(("127.0.0.1", 0), make(name))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
        cls.normal_port, cls.decoy_port = [s.server_port for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers: server.shutdown(); server.server_close()

    def setUp(self):
        self.seen["normal"].clear(); self.seen["decoy"].clear()
        sessions = SessionStore(b"k" * 32, ttl=120, capacity=4)
        self.app = FixedUpstreamGateway(f"http://127.0.0.1:{self.normal_port}",
                                        f"http://127.0.0.1:{self.decoy_port}", sessions,
                                        {"127.0.0.1:18081"}, allowed_upstream_hosts={"127.0.0.1"})
        class H(BaseHTTPRequestHandler):
            def do_GET(inner): self.app.handle(inner)
            def log_message(inner, *_): pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port

    def tearDown(self): self.server.shutdown(); self.server.server_close()

    def get(self, path, cookie=None, host="127.0.0.1:18081", spoof=None, app_cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        headers = {"Host": host, "X-Forwarded-For": spoof or "203.0.113.99", "X-Forwarded-Host": "evil.test"}
        cookies = (["dg_session=" + cookie] if cookie else []) + ([app_cookie] if app_cookie else [])
        if cookies: headers["Cookie"] = "; ".join(cookies)
        c.request("GET", path, headers=headers)
        r = c.getresponse(); body = r.read(); result = (r.status, r.getheaders(), body)
        c.close(); return result

    def cookie(self, response):
        value = next(v for k, v in response[1] if k.lower() == "set-cookie" and v.startswith("dg_session="))
        return value.split(";", 1)[0].split("=", 1)[1]

    def test_explicit_bait_trigger_diverts_before_normal_upstream(self):
        r = self.get("/backup/backup.zip")
        self.assertEqual(r[0], 200); self.assertTrue(r[2].startswith(b"decoy:"))
        self.assertEqual(self.seen["normal"], [])
        self.assertEqual(self.seen["decoy"][0][1], "127.0.0.1")
        self.assertIsNone(self.seen["decoy"][0][2])
        self.assertIsNone(self.seen["decoy"][0][3])
        self.assertTrue(any(v.startswith("dg_gateway_decoy_dg_lab_session=") for k, v in r[1] if k.lower() == "set-cookie"))

    def test_session_affinity_and_two_sessions_same_ip(self):
        a = self.cookie(self.get("/backup/backup.zip"))
        b = self.cookie(self.get("/home"))
        self.assertTrue(self.get("/login", a, app_cookie="dg_gateway_decoy_dg_lab_session=decoycookie")[2].startswith(b"decoy:"))
        self.assertTrue(self.get("/login", b)[2].startswith(b"normal:"))
        switched = self.get("/backup/backup.zip", b, app_cookie="dg_gateway_normal_app_session=normalcookie")
        self.assertTrue(switched[2].startswith(b"decoy:"))
        self.assertIsNone(self.seen["decoy"][-1][2])
        self.assertTrue(self.get("/login", b, app_cookie="dg_gateway_decoy_dg_lab_session=decoycookie")[2].startswith(b"decoy:"))
        self.assertEqual(len(self.seen["normal"]), 2)
        self.assertEqual(len(self.seen["decoy"]), 4)

    def test_tamper_restart_capacity_and_bad_hosts_fail_closed(self):
        token = self.cookie(self.get("/backup/backup.zip"))
        self.assertEqual(self.get("/", token[:-1] + ("A" if token[-1] != "A" else "B"))[0], 400)
        restarted = FixedUpstreamGateway(f"http://127.0.0.1:{self.normal_port}",
                                         f"http://127.0.0.1:{self.decoy_port}",
                                         SessionStore(b"k" * 32), {"127.0.0.1:18081"},
                                         allowed_upstream_hosts={"127.0.0.1"})
        old = self.app; self.app = restarted
        self.assertEqual(self.get("/", token)[0], 410)
        self.app = old
        self.assertEqual(self.get("/", host="evil.test")[0], 421)

    def test_decoy_outage_never_falls_back_to_normal(self):
        dead = FixedUpstreamGateway(f"http://127.0.0.1:{self.normal_port}", "http://127.0.0.1:1",
                                    SessionStore(b"z" * 32), {"127.0.0.1:18081"},
                                    allowed_upstream_hosts={"127.0.0.1"})
        old = self.app; self.app = dead
        self.assertEqual(self.get("/backup/backup.zip")[0], 502)
        self.assertEqual(self.seen["normal"], [])
        self.app = old

    def test_session_capacity_expiry_and_upstream_allowlist(self):
        now = [100.0]
        store = SessionStore(b"c" * 32, ttl=30, capacity=1, clock=lambda: now[0])
        first, state = store.resolve(None)
        self.assertEqual(state, "new")
        self.assertTrue(store.pin(first, "normal"))
        second, _ = store.resolve(None)
        self.assertFalse(store.pin(second, "normal"))
        now[0] = 131.0
        third, _ = store.resolve(None)
        self.assertTrue(store.pin(third, "normal"))
        with self.assertRaises(ValueError):
            FixedUpstreamGateway("http://example.com:8082", "http://127.0.0.1:8080",
                                 store, {"localhost"})


if __name__ == "__main__": unittest.main()

