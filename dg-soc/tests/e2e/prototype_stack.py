"""Temporary loopback prototype for browser acceptance. All sensor input is synthetic."""
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ["DG_CORS_ORIGINS"] = "http://127.0.0.1:15173"
from backend.main import create_app
from decoys.web.app import create_app as web_app
from response.router import configure
from sensors.adapter import CowrieMapper, WebMapper, Checkpoint, Sender, load_honeytokens, process_source, _heartbeat_payloads

BASE = "http://127.0.0.1:18011"
RUN = "prototype-synthetic-browser"
with tempfile.TemporaryDirectory(prefix="prototype-browser-") as directory:
    state = Path(directory)
    env = state / "lab.env"
    env.write_text(f"ATTACKER_IPS=192.168.77.10\nLAB_RUN_ID={RUN}\nCAPTURE_MODE=live\nBACKEND_URL={BASE}\n")
    service = configure(state_dir=str(state / "response"), env_file=str(env))
    policy = state / "response/blocklist.json"
    policy.parent.mkdir(exist_ok=True)
    policy.write_text('{"version":0,"entries":[]}')
    app = create_app(str(state / "backend.db"))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=18011, log_level="warning"))
    worker = threading.Thread(target=server.run, daemon=True)
    worker.start()
    while not server.started:
        time.sleep(.05)

    def api(route, data=None):
        req = Request(BASE + route, data=None if data is None else json.dumps(data).encode(),
                      headers={} if data is None else {"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as response:
            return json.load(response)

    log, cowrie = state / "web.jsonl", state / "cowrie.jsonl"
    cowrie.write_text("")
    portal = web_app({"TESTING": True, "LOG_PATH": str(log), "BLOCKLIST_PATH": str(policy),
        "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"), "WEB_EVENT_SCHEMA_VERSION": "1.1", "LAB_RUN_ID": RUN})
    peer = {"REMOTE_ADDR": "192.168.77.10"}
    client = portal.test_client()
    client.get("/", environ_overrides=peer)
    client.post("/login", data={"username": "svc_portal", "password": "DGLAB-Portal-4471"}, environ_overrides=peer)
    client.get("/.env", environ_overrides=peer)
    client.post("/search", json={"q": "UNION SELECT name FROM users"}, environ_overrides=peer)
    client.get("/download?file=customer_data.csv", environ_overrides=peer)
    other = portal.test_client()
    other.post("/login", data={"username": "svc_portal", "password": "DGLAB-Portal-4471"}, environ_overrides=peer)
    other.get("/dashboard", environ_overrides=peer)
    tokens = load_honeytokens(str(ROOT / "config/honeytokens.yaml"))
    checkpoint, sender = Checkpoint(str(state / "checkpoint.json")), Sender(BASE)
    sources = [(str(log), WebMapper(RUN, "live", tokens)), (str(cowrie), CowrieMapper(RUN, "live", tokens))]

    def collect():
        for path, mapper in sources:
            process_source(path, mapper, checkpoint, sender, str(state / "quarantine.jsonl"))

    collect()
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        {"eventid": "cowrie.session.connect", "src_port": 45000},
        {"eventid": "cowrie.login.success", "username": "backup", "password": "DGLAB-Bkp-2210"},
        {"eventid": "cowrie.command.input", "input": "whoami"},
    ]
    cowrie.write_text("".join(json.dumps({"timestamp": now, "src_ip": "192.168.77.10", "session": "prototype-ssh", **row}) + "\n" for row in rows))
    collect()
    replay = {"schema_version": "1.1", "source_record_id": "synthetic-replay-only", "sensor_id": "ssh-decoy-01",
        "event_type": "connection_open", "occurred_at": now, "src_ip": "192.168.77.10", "session_id": "replay-session",
        "lab_run_id": "prototype-replay", "capture_mode": "replay", "attributes": {}}
    api("/api/ingest/events", {"events": [replay]})

    def heartbeats():
        for payload in _heartbeat_payloads(sources, checkpoint, sender, "prototype-local-collector", datetime.now(timezone.utc).isoformat()):
            assert sender.post_heartbeat(payload)

    heartbeats()
    cases = api("/api/incidents")["items"]
    links = api("/api/links")["items"]
    strong = next(link for link in links if link["kind"] == "strong_candidate")
    status = {"run": RUN, "ssh_case": next(c["incident_id"] for c in cases if c.get("session_id") == "prototype-ssh"),
        "replay_case": next(c["incident_id"] for c in cases if c["lab_run_id"] == "prototype-replay"),
        "link_id": strong["link_id"], "physical_capture": False}

    # Capture the real API shapes for pure frontend regression tests.
    fixture = {"note": "Generated from local synthetic clients and the real integrated backend; not physical captures.",
        "incident": api(f"/api/incidents/{status['ssh_case']}"), "cases": cases,
        "events": api(f"/api/events?lab_run_id={RUN}")["items"],
        "profile": api(f"/api/profiles/192.168.77.10?lab_run_id={RUN}"),
        "eligibility": api(f"/api/incidents/{status['ssh_case']}/response-eligibility"), "health": api("/api/health")}
    if os.environ.get("DG_CAPTURE_FIXTURE"):
        Path(os.environ["DG_CAPTURE_FIXTURE"]).write_text(json.dumps(fixture, indent=2) + "\n")

    class Control(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            data = json.dumps(status).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)
        def do_POST(self):
            code = client.get("/.env", environ_overrides=peer).status_code
            collect(); heartbeats()
            data = json.dumps({"portal_status": code}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)

    controller = ThreadingHTTPServer(("127.0.0.1", 18182), Control)
    control_worker = threading.Thread(target=controller.serve_forever, daemon=True)
    control_worker.start()
    print(json.dumps({"ready": status, "backend": BASE}), flush=True)
    try:
        while worker.is_alive():
            time.sleep(5)
            heartbeats()
    except KeyboardInterrupt:
        pass
    finally:
        controller.shutdown(); controller.server_close()
        server.should_exit = True
        worker.join(timeout=10)
