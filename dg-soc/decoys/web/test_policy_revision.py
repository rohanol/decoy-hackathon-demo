import json
from pathlib import Path

from decoys.web.app import create_app


def test_blocked_request_logs_enforcing_policy_revision(tmp_path):
    expires = "2099-01-01T00:00:00Z"
    blocklist = tmp_path / "blocklist.json"
    blocklist.write_text(json.dumps({"version": 8, "entries": [{"ip": "192.168.77.10", "action_id": "act_test",
        "expires_at": expires, "policy_revision": 7}]}))
    log = tmp_path / "web.json"
    app = create_app({"TESTING": True, "LOG_PATH": str(log), "BLOCKLIST_PATH": str(blocklist),
        "HONEYTOKENS_PATH": str(Path(__file__).parents[2] / "config" / "honeytokens.yaml"),
        "ATTACKER_IPS": "192.168.77.10", "LAB_RUN_ID": "run-test"})
    response = app.test_client().get("/", environ_base={"REMOTE_ADDR": "192.168.77.10"})
    event = json.loads(log.read_text().splitlines()[0])
    assert response.status_code == 403
    assert event["event_type"] == "blocked_request"
    assert event["attributes"]["block_action_id"] == "act_test"
    assert event["attributes"]["policy_revision"] == 7


def test_malformed_canonical_policy_returns_503_not_allow(tmp_path):
    blocklist = tmp_path / "blocklist.json"
    blocklist.write_text('{"version": 8, "entries": "malformed"}')
    app = create_app({"TESTING": True, "LOG_PATH": str(tmp_path / "web.json"),
        "BLOCKLIST_PATH": str(blocklist),
        "HONEYTOKENS_PATH": str(Path(__file__).parents[2] / "config" / "honeytokens.yaml"),
        "ATTACKER_IPS": "192.168.77.10", "LAB_RUN_ID": "run-test"})
    response = app.test_client().get("/", environ_base={"REMOTE_ADDR": "192.168.77.10"})
    assert response.status_code == 503
    assert b"temporarily unavailable" in response.data


def test_malformed_policy_entry_returns_503_before_allow(tmp_path):
    blocklist = tmp_path / "blocklist.json"
    blocklist.write_text(json.dumps({"version": 8, "entries": [{"ip": "bad-ip", "action_id": "act_x",
        "expires_at": "2099-01-01T00:00:00Z", "policy_revision": 7}]}))
    app = create_app({"TESTING": True, "LOG_PATH": str(tmp_path / "web.json"),
        "BLOCKLIST_PATH": str(blocklist),
        "HONEYTOKENS_PATH": str(Path(__file__).parents[2] / "config" / "honeytokens.yaml"),
        "ATTACKER_IPS": "192.168.77.10", "LAB_RUN_ID": "run-test"})
    response = app.test_client().get("/", environ_base={"REMOTE_ADDR": "192.168.77.10"})
    assert response.status_code == 503
