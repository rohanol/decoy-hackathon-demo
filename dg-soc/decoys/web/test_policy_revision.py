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
