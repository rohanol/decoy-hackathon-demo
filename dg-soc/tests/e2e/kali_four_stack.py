"""Disposable four-sensor acceptance. Synthetic SSH/web peers; real loopback
MySQL/SMB protocol clients; every record passes the actual adapter and backend.
Never contacts the physical lab. No gateway or replacement website.
"""
import argparse
import io
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.main import create_app
from decoys.web.app import create_app as create_web
from decoys.database.test_server import running_decoy, client as mysql_client
from decoys.files.test_server import running_smb, client as smb_client
from decoys.web.backup import SMB_PASSWORD
from response.router import configure
from sensors.adapter import (CowrieMapper, WebMapper, NativeMapper, Sender, Checkpoint,
                             load_honeytokens, process_rotating_source, _heartbeat_payloads)
import uvicorn
import pymysql


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18011)
    parser.add_argument("--control-port", type=int, default=18182)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    os.environ["DG_CORS_ORIGINS"] = "http://127.0.0.1:15173"
    base, run = f"http://127.0.0.1:{args.port}", "kali-four-synthetic"
    opener = build_opener(ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="kali-four-") as directory:
        state = Path(directory)
        env = state / "lab.env"
        env.write_text(f"ATTACKER_IPS=192.168.77.10\nLAB_RUN_ID={run}\nCAPTURE_MODE=live\nBACKEND_URL={base}\n")
        configure(state_dir=str(state / "response"), env_file=str(env))
        policy = state / "response/blocklist.json"
        policy.parent.mkdir(exist_ok=True)
        policy.write_text('{"version":0,"entries":[]}')
        backend = create_app(str(state / "backend.db"))
        server = uvicorn.Server(uvicorn.Config(backend, host="127.0.0.1", port=args.port, log_level="error", access_log=False))
        worker = threading.Thread(target=server.run, daemon=True)
        worker.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.02)
        if not server.started:
            raise RuntimeError("Backend not ready")
        controller = None
        try:
            def api(route, body=None):
                request = Request(base + route, data=None if body is None else json.dumps(body).encode(),
                                  headers={} if body is None else {"Content-Type": "application/json"})
                with opener.open(request, timeout=10) as response:
                    return json.load(response)
            web_log, cowrie = state / "web.json", state / "cowrie.json"
            web = create_web({"TESTING": True, "WEB_EVENT_SCHEMA_VERSION": "1.2", "LAB_RUN_ID": run,
                              "LOG_PATH": str(web_log), "BLOCKLIST_PATH": str(policy),
                              "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml")})
            client = web.test_client()
            peer = {"REMOTE_ADDR": "192.168.77.10"}
            assert client.get("/").status_code == 200
            # The first smoke request above is loopback. Remove it from this
            # disposable file before the labeled synthetic participant sequence.
            web_log.write_text("")
            assert client.post("/login", data={"username": "svc_portal", "password": "DGLAB-Portal-4471"}, environ_overrides=peer).status_code == 200
            assert client.get("/backup/backup.zip", environ_overrides=peer).data.startswith(b"PK")
            assert client.get("/.env", environ_overrides=peer).status_code == 200
            now = datetime.now(timezone.utc).isoformat()
            synthetic_ssh = [
                {"eventid": "cowrie.session.connect"},
                {"eventid": "cowrie.login.success", "username": "backup", "password": "DGLAB-Bkp-2210"},
                {"eventid": "cowrie.command.input", "input": "ls -la"},
            ]
            cowrie.write_text("".join(json.dumps({"timestamp": now, "src_ip": "192.168.77.10",
                "session": "four-ssh", **event}) + "\n" for event in synthetic_ssh))
            with running_decoy(state, run_id=run) as (port, db_log, _):
                connection = mysql_client(port)
                with connection.cursor() as cursor:
                    try:
                        cursor.execute("SELECT 1")
                    except pymysql.err.OperationalError as error:
                        assert error.args[0] == 1142
                connection.close()
                for _ in range(5):
                    try:
                        pymysql.connect(host="127.0.0.1", port=port, user="svc_reports", password="synthetic-wrong", read_timeout=2)
                    except pymysql.err.OperationalError as error:
                        assert error.args[0] == 1045
            with running_smb(state, run_id=run) as (port, file_log, samples):
                connection = smb_client(port)
                connection.login("backup_ops", SMB_PASSWORD, domain="WORKGROUP")
                read = io.BytesIO()
                connection.getFile("backups", "README.txt", read.write)
                connection.putFile("backups", "research-note.txt", io.BytesIO(b"Synthetic harmless report.\n").read)
                connection.logoff()
                connection.close()
            tokens = load_honeytokens(str(ROOT / "config/honeytokens.yaml"))
            sources = [(str(cowrie), CowrieMapper(run, "live", tokens)), (str(web_log), WebMapper(run, "live", tokens)),
                       (str(db_log), NativeMapper("db-decoy-01")), (str(file_log), NativeMapper("file-decoy-01"))]
            checkpoint, sender = Checkpoint(str(state / "checkpoint.json")), Sender(base)
            quarantine = str(state / "rejections.jsonl")
            lock = threading.Lock()
            def collect():
                total = sum(process_rotating_source(path, mapper, checkpoint, sender, quarantine) for path, mapper in sources)
                assert sender.rejected_count == sender.quarantine_count == sender.error_count == 0
                return total
            def heartbeats():
                for payload in _heartbeat_payloads(sources, checkpoint, sender, "four-collector", datetime.now(timezone.utc).isoformat()):
                    assert sender.post_heartbeat(payload)
            delivered = collect()
            assert delivered > 20
            checkpoint = Checkpoint(str(state / "checkpoint.json"))
            assert collect() == 0
            heartbeats()
            events = api("/api/events?limit=200")["items"]
            assert {e["sensor_id"] for e in events} == {mapper.sensor_id for _, mapper in sources}
            cases = api("/api/incidents")["items"]
            status = {"run": run, "physical_capture": False, "source": "synthetic SSH/web + actual loopback database/SMB",
                      "ssh_case": next(e["incident_id"] for e in events if e["sensor_id"] == "ssh-decoy-01"),
                      "web_case": next(e["incident_id"] for e in events if e["event_type"] == "bait_served" and e["attributes"]["asset_id"] == "web:/backup/backup.zip"),
                      "db_case": next(e["incident_id"] for e in events if e["sensor_id"] == "db-decoy-01" and e["event_type"] == "auth_success"),
                      "file_case": next(e["incident_id"] for e in events if e["event_type"] == "file_operation" and e["attributes"]["file"].get("storage") == "quarantined_inert"),
                      "event_count": len(events)}
            findings = [f for case in cases for f in api("/api/incidents/" + case["incident_id"])["findings"]]
            assert {"R11", "R12"}.issubset({f["rule_id"] for f in findings})
            links = api("/api/links")["items"]
            assert {"db-decoy-01", "file-decoy-01"}.issubset({link["to_sensor"] for link in links})
            status["db_link"] = next(link["link_id"] for link in links if link["to_sensor"] == "db-decoy-01")
            receipt = {"status": status, "checks": ["all four actual adapter paths accepted", "restart pass delivers no duplicates",
                "four fresh collector heartbeats", "actual MySQL proof and query refusal", "actual SMB proof/read/inert upload",
                "R11 and R12 from generated records", "ZIP causal links to database and file service"],
                "sender_counts": sender.sensor_totals, "health": api("/api/health"), "events": events}
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps({"ready": status, "backend": base, "checks": len(receipt["checks"])}), flush=True)
            if not args.once:
                class Control(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass
                    def do_GET(self):
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(status).encode())
                    def do_POST(self):
                        with lock:
                            code = client.get("/backup/backup.zip", environ_overrides=peer).status_code
                            collect()
                            heartbeats()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"portal_status": code}).encode())
                controller = ThreadingHTTPServer(("127.0.0.1", args.control_port), Control)
                threading.Thread(target=controller.serve_forever, daemon=True).start()
                try:
                    while worker.is_alive():
                        time.sleep(5)
                        with lock:
                            heartbeats()
                except KeyboardInterrupt:
                    pass
        finally:
            if controller:
                controller.shutdown()
                controller.server_close()
            server.should_exit = True
            worker.join(10)
            assert not worker.is_alive()


if __name__ == "__main__":
    main()
