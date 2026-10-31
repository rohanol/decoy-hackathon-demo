import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "decoys" / "policy"))

from policy import check  # noqa: E402
from response import router as r  # noqa: E402

START = datetime(2026, 11, 1, 5, 0, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.t = START

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += timedelta(seconds=seconds)


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    incidents = {"inc_01": "192.168.77.10", "inc_bad": "10.0.0.5", "inc_host": "192.168.77.20", "inc_lo": "127.0.0.1"}
    live = {"lab_run_id": "run-01", "capture_mode": "live"}
    envfile = tmp_path / "lab.env"
    envfile.write_text("ATTACKER_IPS=192.168.77.10,192.168.77.20,127.0.0.1,10.0.0.5/24\n")  # deliberately bad config
    def eligibility(incident_id):
        if incident_id not in incidents:
            return None
        mode = live["capture_mode"]
        return {"eligible": mode == "live", "target_ip": incidents[incident_id],
                "lab_run_id": live["lab_run_id"], "capture_mode": mode,
                "reasons": [] if mode == "live" else ["case is replay evidence"],
                "last_web_observation_at": r._iso(clock()), "checked_at": r._iso(clock())}

    r.configure(state_dir=str(tmp_path), env_file=str(envfile), eligibility_lookup=eligibility, now=clock,
                live_context=lambda: dict(live))
    app = FastAPI()
    app.include_router(r.router, prefix="/api/response")
    return TestClient(app), clock, tmp_path, live


def preview(c, inc="inc_01", ttl=120):
    return c.post("/api/response/preview", json={"incident_id": inc, "ttl_seconds": ttl})


def apply(c, pid, reason="demo block", confirm=True):
    return c.post("/api/response/apply", json={"preview_id": pid, "reason": reason, "confirm": confirm})


def blocked(tmp, clock, ip="192.168.77.10"):
    try:
        return check(ip, str(tmp / "blocklist.json"), clock())
    except ValueError:  # a missing test policy is unavailable, therefore it cannot claim a block
        return None


def test_preview_returns_contract_fields(env):
    c, _, _, _ = env
    body = preview(c).json()
    assert body["target_ip"] == "192.168.77.10" and body["scope"] == "web-decoy-01 only"
    assert body["ttl_seconds"] == 120 and body["preview_id"].startswith("prv_")


@pytest.mark.parametrize("inc", ["inc_bad", "inc_host", "inc_lo"])
def test_wrong_ip_rejected_even_with_bad_env(env, inc):
    c, _, _, _ = env
    resp = preview(c, inc)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "target_not_allowed"


def test_unknown_incident_404(env):
    c, _, _, _ = env
    assert preview(c, "nope").status_code == 404


def test_expired_preview_rejected(env):
    c, clock, tmp, _ = env
    pid = preview(c).json()["preview_id"]
    clock.advance(61)
    resp = apply(c, pid)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "preview_invalid"
    assert blocked(tmp, clock) is None


def test_apply_needs_confirm_and_reason(env):
    c, _, tmp, _ = env
    pid = preview(c).json()["preview_id"]
    assert apply(c, pid, confirm=False).status_code == 400
    assert apply(c, pid, reason="no").status_code == 400
    assert apply(c, pid).status_code == 200  # preview survives failed attempts


def test_apply_blocks_then_revoke_restores_access(env):
    c, clock, tmp, _ = env
    res = apply(c, preview(c).json()["preview_id"]).json()
    assert res["status"] == "applied"
    assert blocked(tmp, clock) == res["action_id"]
    assert blocked(tmp, clock, "192.168.77.20") is None
    assert c.post(f"/api/response/{res['action_id']}/revoke", json={}).json()["status"] == "revoked"
    assert blocked(tmp, clock) is None
    assert c.post(f"/api/response/{res['action_id']}/revoke", json={}).status_code == 409


def test_preview_single_use_and_duplicate_block(env):
    c, _, _, _ = env
    pid = preview(c).json()["preview_id"]
    assert apply(c, pid).status_code == 200
    assert apply(c, pid).status_code == 400
    assert apply(c, preview(c).json()["preview_id"]).status_code == 409


def test_block_expires_at_ttl(env):
    c, clock, tmp, _ = env
    res = apply(c, preview(c, ttl=30).json()["preview_id"]).json()
    clock.advance(29)
    assert blocked(tmp, clock) == res["action_id"]
    clock.advance(2)
    assert blocked(tmp, clock) is None
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "expired"
    assert json.loads((tmp / "blocklist.json").read_text())["entries"] == []


def test_verified_only_after_blocked_request_event(env):
    c, clock, tmp, _ = env
    res = apply(c, preview(c).json()["preview_id"]).json()
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    action = c.get("/api/response/actions").json()["items"][0]
    base = {"event_type": "blocked_request", "sensor_id": "web-decoy-01", "src_ip": "192.168.77.10",
            "lab_run_id": "run-01", "capture_mode": "live", "occurred_at": action["created_at"],
            "attributes": {"block_action_id": res["action_id"], "policy_revision": 1}, "event_id": "evt_x"}
    received = {"source": "backend_ingest", "persisted_event_id": "evt_x", "received_at": action["created_at"]}
    r.on_event({**base, "event_type": "http_request"}, received)
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    r.on_event({**base, "attributes": {"block_action_id": "act_other", "policy_revision": 1}}, received)
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    unmatched = json.loads((tmp / "response-verification-audit.jsonl").read_text().splitlines()[0])
    assert unmatched["reason"] == "unknown_action_id" and unmatched["event_id"] == "evt_x"
    for field, wrong in (("sensor_id", "ssh-decoy-01"), ("src_ip", "192.168.77.11"),
                         ("lab_run_id", "run-old"), ("capture_mode", "replay")):
        r.on_event({**base, field: wrong, "event_id": "evt_bad_" + field}, received)
        assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    before_apply = (START - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r.on_event({**base, "occurred_at": before_apply, "event_id": "evt_before_apply"},
               {**received, "persisted_event_id": "evt_before_apply"})
    after_expiry = (START + timedelta(seconds=121)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r.on_event({**base, "event_id": "evt_after_expiry"}, {**received,
               "persisted_event_id": "evt_after_expiry", "received_at": after_expiry})
    r.on_event({**base, "attributes": {"block_action_id": res["action_id"], "policy_revision": 99}}, received)
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    r.on_event(base, {})  # no trusted backend ingestion timestamp
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    assert len(json.loads((tmp / "response-actions.json").read_text())["actions"][res["action_id"]]["verification_rejects"]) == 8
    r.on_event({**base, "event_id": "evt_z"}, {**received, "persisted_event_id": "evt_z"})
    item = c.get("/api/response/actions").json()["items"][0]
    assert item["status"] == "verified" and item["verified_by_event_id"] == "evt_z"


def test_apply_requires_live_context(env):
    c, _, _, live = env
    pid = preview(c).json()["preview_id"]
    live["capture_mode"] = "replay"
    response = apply(c, pid)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "not_live"


def test_apply_rechecks_run_and_policy_revision(env):
    c, _, tmp, live = env
    pid = preview(c).json()["preview_id"]
    live["lab_run_id"] = "run-replaced"
    response = apply(c, pid)
    assert response.status_code == 409 and response.json()["error"]["code"] == "preview_stale"
    live["lab_run_id"] = "run-01"
    pid = preview(c).json()["preview_id"]
    (tmp / "blocklist.json").write_text(json.dumps({"version": 99, "entries": []}))
    response = apply(c, pid)
    assert response.status_code == 409 and response.json()["error"]["code"] == "preview_stale"


def test_preview_rejects_replay_mode(env):
    c, _, _, live = env
    live["capture_mode"] = "replay"
    response = preview(c)
    assert response.status_code == 409 and response.json()["error"]["code"] == "not_live"


def test_ttl_bounds_and_bad_body(env):
    c, _, _, _ = env
    assert preview(c, ttl=5).status_code == 400
    assert preview(c, ttl=9999).status_code == 400
    assert c.post("/api/response/preview", json={}).json()["error"]["code"] == "invalid_request"
    assert c.post("/api/response/apply", content="not json").status_code in (400, 422)


def test_blocklist_file_format_matches_contract(env):
    c, _, tmp, _ = env
    res = apply(c, preview(c).json()["preview_id"]).json()
    data = json.loads((tmp / "blocklist.json").read_text())
    assert data["version"] >= 1
    entry = data["entries"][0]
    assert entry["ip"] == "192.168.77.10" and entry["action_id"] == res["action_id"]
    assert entry["expires_at"] == res["until"] and entry["policy_revision"] == data["version"]


def test_restart_reconciles_policy_written_before_action_history(env):
    c, clock, tmp, _ = env
    result = apply(c, preview(c).json()["preview_id"]).json()
    policy = json.loads((tmp / "blocklist.json").read_text())
    history = json.loads((tmp / "response-actions.json").read_text())
    history["actions"].pop(result["action_id"])  # simulates a crash after policy rename
    (tmp / "response-actions.json").write_text(json.dumps(history))
    r.configure(state_dir=str(tmp), eligibility_lookup=lambda _: {"eligible": True, "target_ip": "192.168.77.10",
                "lab_run_id": "run-01", "capture_mode": "live", "reasons": [],
                "last_web_observation_at": r._iso(clock()), "checked_at": r._iso(clock())}, now=clock,
                live_context=lambda: {"lab_run_id": "run-01", "capture_mode": "live"})
    recovered = c.get("/api/response/actions").json()["items"][0]
    assert recovered["action_id"] == result["action_id"]
    assert recovered["status"] == "applied"
    restored = json.loads((tmp / "response-actions.json").read_text())["actions"][result["action_id"]]
    assert restored["recovered_after_restart"] is True
    assert policy["entries"][0]["policy_revision"] == restored["policy_revision"]


def test_restart_audits_active_action_missing_from_policy(env):
    c, clock, tmp, _ = env
    result = apply(c, preview(c).json()["preview_id"]).json()
    policy = json.loads((tmp / "blocklist.json").read_text())
    policy["entries"] = []
    policy["version"] += 1
    (tmp / "blocklist.json").write_text(json.dumps(policy))
    r.configure(state_dir=str(tmp), eligibility_lookup=lambda _: {"eligible": True, "target_ip": "192.168.77.10",
                "lab_run_id": "run-01", "capture_mode": "live", "reasons": [],
                "last_web_observation_at": r._iso(clock()), "checked_at": r._iso(clock())}, now=clock,
                live_context=lambda: {"lab_run_id": "run-01", "capture_mode": "live"})
    action = json.loads((tmp / "response-actions.json").read_text())["actions"][result["action_id"]]
    assert action["status"] == "reconciliation_required"
    assert action["verification_rejects"][-1]["reason"] == "active_action_missing_or_changed_in_policy_after_restart"
    assert c.get("/api/response/actions").json()["items"][0]["verification_rejects"]


class EligibilityBackend:
    def __init__(self, response):
        self.response = response
        self.paths = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.paths.append(self.path)
                if not self.path.endswith("/response-eligibility"):
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(outer.response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def _eligibility(*, eligible=True, mode="live", run="run-01", reasons=None):
    return {"eligible": eligible, "target_ip": "192.168.77.10", "lab_run_id": run,
            "capture_mode": mode, "reasons": reasons or [],
            "last_web_observation_at": r._iso(START), "checked_at": r._iso(START)}


def test_default_wiring_uses_authoritative_eligibility_and_fails_closed(tmp_path):
    clock = Clock()
    backend = EligibilityBackend(_eligibility(eligible=False, mode="replay", run="replay-01",
                                               reasons=["case is replay evidence", "run is not active"]))
    envfile = tmp_path / "lab.env"
    envfile.write_text(f"ATTACKER_IPS=192.168.77.10\nBACKEND_URL={backend.url}\nLAB_RUN_ID=run-01\nCAPTURE_MODE=live\n")
    try:
        r.configure(state_dir=str(tmp_path), env_file=str(envfile), now=clock)
        app = FastAPI()
        app.include_router(r.router, prefix="/api/response")
        client = TestClient(app)
        response = preview(client)
        assert response.status_code == 409 and response.json()["error"]["code"] == "not_eligible"
        assert backend.paths and all(path.endswith("/response-eligibility") for path in backend.paths)
        # In particular, the configured live run does not rescue a replay case.
        assert apply(client, "prv_missing").status_code == 400
        assert not (tmp_path / "blocklist.json").exists()
    finally:
        backend.close()


def test_default_wiring_rechecks_authoritative_eligibility_at_apply(tmp_path):
    clock = Clock()
    backend = EligibilityBackend(_eligibility())
    envfile = tmp_path / "lab.env"
    envfile.write_text(f"ATTACKER_IPS=192.168.77.10\nBACKEND_URL={backend.url}\nLAB_RUN_ID=run-01\nCAPTURE_MODE=live\n")
    try:
        r.configure(state_dir=str(tmp_path), env_file=str(envfile), now=clock)
        app = FastAPI()
        app.include_router(r.router, prefix="/api/response")
        client = TestClient(app)
        pid = preview(client).json()["preview_id"]
        backend.response = _eligibility(eligible=False, mode="replay", run="replay-01",
                                        reasons=["case is replay evidence"])
        response = apply(client, pid)
        assert response.status_code == 409 and response.json()["error"]["code"] == "not_eligible"
        assert len(backend.paths) == 2 and all(path.endswith("/response-eligibility") for path in backend.paths)
        assert not (tmp_path / "blocklist.json").exists()
    finally:
        backend.close()


def test_missing_authoritative_eligibility_fails_closed(tmp_path):
    clock = Clock()
    r.configure(state_dir=str(tmp_path), eligibility_lookup=lambda _incident: {"src_ip": "192.168.77.10"},
                now=clock, live_context=lambda: {"lab_run_id": "run-01", "capture_mode": "live"})
    app = FastAPI()
    app.include_router(r.router, prefix="/api/response")
    response = preview(TestClient(app)).json()
    assert response["error"]["code"] == "eligibility_unavailable"


def test_stale_authoritative_case_is_not_eligible(tmp_path):
    clock = Clock()
    stale = {"eligible": True, "target_ip": "192.168.77.10", "lab_run_id": "run-01",
             "capture_mode": "live", "reasons": [],
             "last_web_observation_at": r._iso(START - timedelta(minutes=10)),
             "checked_at": r._iso(START)}
    r.configure(state_dir=str(tmp_path), eligibility_lookup=lambda _incident: stale, now=clock,
                live_context=lambda: {"lab_run_id": "run-01", "capture_mode": "live"})
    app = FastAPI()
    app.include_router(r.router, prefix="/api/response")
    response = preview(TestClient(app))
    assert response.status_code == 409 and response.json()["error"]["code"] == "not_eligible"
