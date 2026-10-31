import json
import sys
from datetime import datetime, timedelta, timezone
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
    envfile = tmp_path / "lab.env"
    envfile.write_text("ATTACKER_IPS=192.168.77.10,192.168.77.20,127.0.0.1,10.0.0.5/24\n")  # deliberately bad config
    r.configure(state_dir=str(tmp_path), env_file=str(envfile), incident_lookup=incidents.get, now=clock)
    app = FastAPI()
    app.include_router(r.router, prefix="/api/response")
    return TestClient(app), clock, tmp_path


def preview(c, inc="inc_01", ttl=120):
    return c.post("/api/response/preview", json={"incident_id": inc, "ttl_seconds": ttl})


def apply(c, pid, reason="demo block", confirm=True):
    return c.post("/api/response/apply", json={"preview_id": pid, "reason": reason, "confirm": confirm})


def blocked(tmp, clock, ip="192.168.77.10"):
    return check(ip, str(tmp / "blocklist.json"), clock())


def test_preview_returns_contract_fields(env):
    c, _, _ = env
    body = preview(c).json()
    assert body["target_ip"] == "192.168.77.10" and body["scope"] == "web-decoy-01 only"
    assert body["ttl_seconds"] == 120 and body["preview_id"].startswith("prv_")


@pytest.mark.parametrize("inc", ["inc_bad", "inc_host", "inc_lo"])
def test_wrong_ip_rejected_even_with_bad_env(env, inc):
    c, _, _ = env
    resp = preview(c, inc)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "target_not_allowed"


def test_unknown_incident_404(env):
    c, _, _ = env
    assert preview(c, "nope").status_code == 404


def test_expired_preview_rejected(env):
    c, clock, tmp = env
    pid = preview(c).json()["preview_id"]
    clock.advance(61)
    resp = apply(c, pid)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "preview_invalid"
    assert blocked(tmp, clock) is None


def test_apply_needs_confirm_and_reason(env):
    c, _, tmp = env
    pid = preview(c).json()["preview_id"]
    assert apply(c, pid, confirm=False).status_code == 400
    assert apply(c, pid, reason="no").status_code == 400
    assert apply(c, pid).status_code == 200  # preview survives failed attempts


def test_apply_blocks_then_revoke_restores_access(env):
    c, clock, tmp = env
    res = apply(c, preview(c).json()["preview_id"]).json()
    assert res["status"] == "applied"
    assert blocked(tmp, clock) == res["action_id"]
    assert blocked(tmp, clock, "192.168.77.20") is None
    assert c.post(f"/api/response/{res['action_id']}/revoke", json={}).json()["status"] == "revoked"
    assert blocked(tmp, clock) is None
    assert c.post(f"/api/response/{res['action_id']}/revoke", json={}).status_code == 409


def test_preview_single_use_and_duplicate_block(env):
    c, _, _ = env
    pid = preview(c).json()["preview_id"]
    assert apply(c, pid).status_code == 200
    assert apply(c, pid).status_code == 400
    assert apply(c, preview(c).json()["preview_id"]).status_code == 409


def test_block_expires_at_ttl(env):
    c, clock, tmp = env
    res = apply(c, preview(c, ttl=30).json()["preview_id"]).json()
    clock.advance(29)
    assert blocked(tmp, clock) == res["action_id"]
    clock.advance(2)
    assert blocked(tmp, clock) is None
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "expired"
    assert json.loads((tmp / "blocklist.json").read_text())["entries"] == []


def test_verified_only_after_blocked_request_event(env):
    c, _, _ = env
    res = apply(c, preview(c).json()["preview_id"]).json()
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    r.on_event({"event_type": "http_request", "attributes": {"block_action_id": res["action_id"]}, "event_id": "evt_x"})
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    r.on_event({"event_type": "blocked_request", "attributes": {"block_action_id": "act_other"}, "event_id": "evt_y"})
    assert c.get("/api/response/actions").json()["items"][0]["status"] == "applied"
    r.on_event({"event_type": "blocked_request", "attributes": {"block_action_id": res["action_id"]}, "event_id": "evt_z"})
    item = c.get("/api/response/actions").json()["items"][0]
    assert item["status"] == "verified" and item["verified_by_event_id"] == "evt_z"


def test_ttl_bounds_and_bad_body(env):
    c, _, _ = env
    assert preview(c, ttl=5).status_code == 400
    assert preview(c, ttl=9999).status_code == 400
    assert c.post("/api/response/preview", json={}).json()["error"]["code"] == "invalid_request"
    assert c.post("/api/response/apply", content="not json").status_code in (400, 422)


def test_blocklist_file_format_matches_contract(env):
    c, _, tmp = env
    res = apply(c, preview(c).json()["preview_id"]).json()
    data = json.loads((tmp / "blocklist.json").read_text())
    assert data["version"] >= 1
    assert data["entries"] == [{"ip": "192.168.77.10", "action_id": res["action_id"], "expires_at": res["until"]}]
