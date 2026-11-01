"""Synthetic loopback acceptance against an explicit v1.2 backend checkout.

Real HTTP, ZIP responses and PyMySQL protocol traffic; reference-signed gateway
contexts are synthetic, not records from M2's actual gateway. Events are posted
directly so this checks the producer/backend boundary, not the pending adapter.
"""
import argparse
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.web.app import create_app as create_web
from decoys.database.test_server import running_decoy, client as database_client, records as db_records
from tests.e2e.test_next_bait import signed, KEY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    backend_root = args.backend_root.resolve()
    schema = json.loads((backend_root / "contracts/event.schema.json").read_text())
    if "1.2" not in schema["properties"]["schema_version"]["enum"]:
        parser.error("backend-root must implement contract v1.2; current main may not yet include PRs 19/20")
    sys.path.insert(0, str(backend_root))
    import uvicorn
    import pymysql
    from backend.main import create_app
    from response.router import configure
    from werkzeug.serving import make_server, WSGIRequestHandler

    receipts = {"scope": "synthetic loopback; reference-signed context; direct ingest; no physical lab or adapter",
                "checks": [], "producer_records": []}
    def check(name):
        receipts["checks"].append(name)
        print("PASS", name, flush=True)

    with tempfile.TemporaryDirectory(prefix="m4-next-check-") as directory:
        state = Path(directory)
        config = state / "config"
        shutil.copytree(backend_root / "config", config)
        shutil.copyfile(ROOT / "config/honeytokens.yaml", config / "honeytokens.yaml")
        os.environ["DG_CONFIG_DIR"] = str(config)
        run = "mysql-client-test"
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        env = state / "lab.env"
        env.write_text(f"ATTACKER_IPS=192.168.77.10\nLAB_RUN_ID={run}\nCAPTURE_MODE=live\nBACKEND_URL={base}\n")
        configure(state_dir=str(state / "response"), env_file=str(env))
        backend = create_app(str(state / "backend.db"))
        server = uvicorn.Server(uvicorn.Config(backend, log_level="error", access_log=False))
        worker = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
        worker.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.02)
        if not server.started:
            raise RuntimeError("backend startup failed")
        policy, web_log = state / "response/blocklist.json", state / "web.json"
        policy.parent.mkdir(parents=True, exist_ok=True)
        if not policy.exists():
            policy.write_text('{"version":0,"entries":[]}')
        web = create_web({"LOG_PATH": str(web_log), "BLOCKLIST_PATH": str(policy),
                          "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"),
                          "WEB_EVENT_SCHEMA_VERSION": "1.2", "LAB_RUN_ID": run, "DG_GATEWAY_CONTEXT_KEY": KEY})
        class Quiet(WSGIRequestHandler):
            def log(self, *args, **kwargs):
                pass
        web_server = make_server("127.0.0.1", 0, web, threaded=True, request_handler=Quiet)
        web_worker = threading.Thread(target=web_server.serve_forever, daemon=True)
        web_worker.start()
        web_base = f"http://127.0.0.1:{web_server.server_port}"
        opener = build_opener(ProxyHandler({}))
        seen_web = 0

        def api(path, body=None):
            request = Request(base + path, data=None if body is None else json.dumps(body).encode(),
                              headers={} if body is None else {"Content-Type": "application/json"})
            with opener.open(request, timeout=10) as response:
                return json.load(response)

        def ingest(events):
            result = api("/api/ingest/events", {"events": events})
            assert result["rejected"] == [], result
            receipts["producer_records"].extend(events)
            return result

        def flush_web():
            nonlocal seen_web
            events = [json.loads(line) for line in web_log.read_text().splitlines()]
            fresh, seen_web = events[seen_web:], len(events)
            return fresh

        def get_web(path, gw_id=None):
            gw_id = gw_id or "gw_" + __import__("uuid").uuid4().hex
            header = signed(run=run, gw_req=gw_id)
            try:
                with opener.open(Request(web_base + path, headers={"X-DG-Gateway-Context": header}), timeout=5) as response:
                    return response.status, response.read(), gw_id
            except HTTPError as error:
                return error.code, error.read(), gw_id

        try:
            status, archive, gw_id = get_web("/backup/backup.zip")
            assert status == 200 and archive.startswith(b"PK")
            first_web = flush_web()
            assert ingest(first_web)["accepted"] == 3
            check("actual ZIP response produces three v1.2 records accepted by backend")
            duplicate = api("/api/ingest/events", {"events": first_web})
            assert duplicate["accepted"] == 0 and duplicate["duplicates"] == 3
            check("actual producer event IDs deduplicate")

            # A deliberately synthetic reference decision exercises M3's join.
            stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            decision = {"telemetry_version": "1.0", "record_id": "reference-decision-1", "source_id": "gateway-01",
                        "record_type": "route_decision", "occurred_at": stamp, "lab_run_id": run, "capture_mode": "live",
                        "attributes": {"gateway_request_id": gw_id, "client_ip": "192.168.77.10", "client_port": 51234,
                        "gateway_session_ref": "gws_" + "a" * 32, "method": "GET", "path": "/backup/backup.zip",
                        "decision": "decoy", "upstream_id": "web-decoy-01", "reasons": ["bait_path_requested"],
                        "routing_policy_id": "reference-only", "routing_policy_revision": 1,
                        "pin": {"scope": "session", "pinned_at": stamp, "expires_at": None}, "decided_before_upstream": True}}
            telemetry = api("/api/ingest/telemetry", {"records": [decision]})
            assert telemetry["accepted"] == 1, telemetry
            routing = api("/api/gateway/requests/" + gw_id)
            assert routing["correlation"]["status"] == "observed", routing
            check("reference-signed context correlates grouped request/result/bait records")

            with running_decoy(state) as (db_port, db_log, _):
                connection = database_client(db_port)
                with connection.cursor() as cursor:
                    try:
                        cursor.execute("SELECT 'not retained'")
                    except pymysql.err.OperationalError as error:
                        assert error.args[0] == 1142
                connection.close()
                for _ in range(5):
                    try:
                        pymysql.connect(host="127.0.0.1", port=db_port, user="svc_reports", password="synthetic-wrong",
                                        connect_timeout=2, read_timeout=2)
                    except pymysql.err.OperationalError as error:
                        assert error.args[0] == 1045
                    else:
                        raise AssertionError("Wrong credential accepted")
            database_events = db_records(db_log)
            result = ingest(database_events)
            assert result["accepted"] == len(database_events)
            links = api("/api/links")["items"]
            token_links = [link for link in links if link["to_sensor"] == "db-decoy-01"]
            assert token_links and all(link["attribution"] == "unique" for link in token_links), links
            link = token_links[0]
            check("real PyMySQL proof creates a unique candidate link to the served archive")
            cases = api("/api/incidents")["items"]
            credential_case = next(case for case in cases if case.get("sensor_id") == "db-decoy-01"
                                   and case["case_kind"] == "credential_attempts")
            details = api("/api/incidents/" + credential_case["incident_id"])
            assert any(finding["rule_id"] == "R11" for finding in details["findings"])
            check("five actual failed protocol logins produce an R11 credential-attempt finding")
            api("/api/links/" + link["link_id"] + "/decision", {"decision": "confirm", "rationale": "Synthetic loopback evidence review"})
            assert any(case["case_kind"] == "investigation" for case in api("/api/incidents")["items"])
            api("/api/links/" + link["link_id"] + "/decision", {"decision": "reject", "rationale": "Reverse the synthetic analyst decision"})
            check("analyst confirmation and reversal operate on actual producer relationships")

            assert get_web("/backup/backup.zip")[0] == 200
            ingest(flush_web())
            # The second serving happened AFTER the first login. It can only
            # make a LATER use ambiguous, not retroactively precede that login.
            seen_db = len(db_records(db_log))
            with running_decoy(state) as (db_port, db_log, _):
                connection = database_client(db_port)
                connection.close()
            later_events = db_records(db_log)[seen_db:]
            later_use = next(e for e in later_events if e["event_type"] == "auth_success")
            ingest(later_events)
            later_case = next(e["incident_id"] for e in api("/api/events?limit=100")["items"]
                              if e["source_record_id"] == later_use["source_record_id"])
            links = api("/api/links")["items"]
            later_links = [link for link in links if link["to_incident_id"] == later_case]
            assert later_links and all(link["attribution"] == "ambiguous" and len(link["candidate_issuance_ids"]) == 2
                                       for link in later_links), links
            check("later credential use preserves both prior static-token issuances as ambiguous")

            events = api("/api/events?limit=100")["items"]
            web_case = next(e["incident_id"] for e in events if e["sensor_id"] == "web-decoy-01")
            db_case = next(e["incident_id"] for e in events if e["event_type"] == "auth_success")
            eligibility = api("/api/incidents/" + db_case + "/response-eligibility")
            assert not eligibility["eligible"] and any(r["code"] == "response_unsupported_sensor" for r in eligibility["reasons"])
            check("database case cannot claim the web-only response capability")

            preview = api("/api/response/preview", {"incident_id": web_case})
            applied = api("/api/response/apply", {"preview_id": preview["preview_id"], "reason": "Synthetic M4 loopback response test", "confirm": True})
            assert applied["status"] == "applied"
            assert get_web("/backup/backup.zip")[0] == 403
            denied, = flush_web()
            assert denied["event_type"] == "blocked_request"
            ingest([denied])
            action = next(a for a in api("/api/response/actions")["items"] if a["action_id"] == applied["action_id"])
            assert action["status"] == "verified", action
            api("/api/response/" + applied["action_id"] + "/revoke", {})
            assert get_web("/login")[0] == 200
            ingest(flush_web())
            check("real HTTP denial -> direct backend ingest -> trusted verification -> revoke")
            receipts["routing"] = routing
            receipts["action"] = action
            receipts["event_count"] = len(receipts["producer_records"])
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(receipts, indent=2) + "\n")
        finally:
            web_server.shutdown()
            web_server.server_close()
            web_worker.join(5)
            server.should_exit = True
            worker.join(10)
            sock.close()
            assert not worker.is_alive() and not web_worker.is_alive()
    print(json.dumps({"checks": len(receipts["checks"]), "event_count": receipts.get("event_count"), "scope": receipts["scope"]}))


if __name__ == "__main__":
    main()
