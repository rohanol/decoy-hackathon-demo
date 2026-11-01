"""Exercise actual M1/M2 checkout code without modifying either member's branch.

Loopback only. This does not certify signed attribution, telemetry shipping or
SMB integration. Missing capabilities are reported as integration gaps.
"""
import argparse
import importlib.util
import json
import secrets
import sys
import tempfile
import threading
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import HTTPCookieProcessor, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.web.app import create_app
from werkzeug.serving import make_server, WSGIRequestHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--portal-root", type=Path, required=True, help="M1 dg-soc directory")
    parser.add_argument("--gateway-root", type=Path, required=True, help="M2 dg-soc directory")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--serve", action="store_true", help="keep loopback pages open for browser review until Ctrl+C")
    args = parser.parse_args()
    sys.path.insert(0, str(args.portal_root.resolve() / "demo-app"))
    from portal.app import create_app as create_normal
    spec = importlib.util.spec_from_file_location("actual_m2_gateway", args.gateway_root / "gateway/app.py")
    gateway = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gateway)
    with tempfile.TemporaryDirectory(prefix="m4-gateway-check-") as directory:
        state = Path(directory)
        policy, log = state / "policy.json", state / "web.json"
        policy.write_text('{"version":0,"entries":[]}')
        normal_log = state / "normal.json"
        key = "DGLAB-GWCTX-" + "ab" * 32
        normal = create_normal({"LAB_RUN_ID": "gateway-check", "TELEMETRY_PATH": str(normal_log), "GATEWAY_CONTEXT_KEY": key})
        decoy = create_app({"WEB_EVENT_SCHEMA_VERSION": "1.2", "LAB_RUN_ID": "gateway-check",
                            "LOG_PATH": str(log), "BLOCKLIST_PATH": str(policy), "DG_GATEWAY_CONTEXT_KEY": key,
                            "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml")})
        class Quiet(WSGIRequestHandler):
            def log(self, *args, **kwargs):
                pass
        servers, threads = [], []
        def upstream(app):
            server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=Quiet)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            servers.append(server)
            threads.append(thread)
            thread.start()
            return f"http://127.0.0.1:{server.server_port}"
        normal_base, decoy_base = upstream(normal), upstream(decoy)
        app = None
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                app.handle(self)
            def do_HEAD(self):
                app.handle(self)
        http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        base = f"http://127.0.0.1:{http.server_port}"
        app = gateway.FixedUpstreamGateway(normal_base, decoy_base,
                gateway.SessionStore(secrets.token_bytes(32)), {f"127.0.0.1:{http.server_port}"},
                allowed_upstream_hosts={"127.0.0.1"})
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        servers.append(http)
        threads.append(thread)
        thread.start()
        checks = []
        def check(name):
            checks.append(name)
            print("PASS", name, flush=True)
        def browser():
            return build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
        def read(client, path):
            with client.open(base + path, timeout=5) as response:
                return response.status, response.read(), dict(response.headers)
        try:
            first, second = browser(), browser()
            assert read(first, "/")[0] == 200 and not log.exists()
            check("ordinary gateway session reaches M1 normal portal")
            status, archive, headers = read(first, "/backup/backup.zip")
            assert status == 200 and archive.startswith(b"PK\x03\x04")
            assert read(first, "/reports")[0] == 200
            app_records = [json.loads(line) for line in normal_log.read_text().splitlines()]
            assert [r["attributes"]["path"] for r in app_records] == ["/"]
            check("triggering request and later session traffic reach M4 decoy, never normal portal")
            before = len(log.read_text().splitlines())
            assert read(second, "/")[0] == 200
            assert len(log.read_text().splitlines()) == before
            check("independent session sharing loopback IP stays on normal app")
            web_records = [json.loads(line) for line in log.read_text().splitlines()]
            contexts = sorted({r["attributes"]["ingress"]["gateway_context"] for r in web_records})
            gaps = []
            if contexts != ["verified"]:
                gaps.append("M2 gateway emits no verified signed context; observed ingress=" + ",".join(contexts))
            if not any(k.lower() == "content-disposition" for k in headers):
                gaps.append("M2 proxy does not forward Content-Disposition; archive attachment filename is lost")
            receipt = {"scope": "actual M1/M2/M4 modules; synthetic loopback; no adapter/backend/physical test",
                       "checks": checks, "integration_gaps": gaps, "observed_contexts": contexts,
                       "web_records": web_records}
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps({"checks": len(checks), "integration_gaps": gaps, "urls": {
                "gateway": base, "normal": normal_base, "decoy": decoy_base}}), flush=True)
            if args.serve:
                print("Browser review ready; Ctrl+C stops only these temporary servers", flush=True)
                try:
                    threading.Event().wait()
                except KeyboardInterrupt:
                    pass
        finally:
            for server in reversed(servers):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(5)
                assert not thread.is_alive()


if __name__ == "__main__":
    main()
