"""Producer/collector/backend boundaries exercised with actual module output."""
import json
from datetime import datetime, timezone
from pathlib import Path

from decoys.web.app import create_app as web_app
from sensors.adapter import Checkpoint, Sender, WebMapper, _heartbeat_payloads, validate

ROOT = Path(__file__).resolve().parents[2]


def test_current_adapter_heartbeat_preserves_all_counters(client, tmp_path):
    source = tmp_path / "web.jsonl"
    source.write_text("")
    sender = Sender("http://127.0.0.1:1")
    totals = sender._totals("web-decoy-01")
    totals["error_count"] = 2
    totals["ingest"].update(accepted=21, duplicate=3, rejected=2, quarantined=2, retry=4)
    payload = _heartbeat_payloads([(str(source), WebMapper("prototype", "live", {}))],
        Checkpoint(str(tmp_path / "checkpoint.json")), sender, "prototype-collector", datetime.now(timezone.utc).isoformat())[0]
    response = client.post("/api/ingest/heartbeat", json=payload)
    assert response.status_code == 200 and response.json() == {"ok": True}
    health = client.get("/api/health").json()["sensor_health"]["web-decoy-01"]
    assert health["process_state"] == "running" and health["collection"] == "ok"
    assert health["ingest"] == totals["ingest"] and health["error_count"] == 2
    assert client.get("/api/events").json()["items"] == []
    malformed = dict(payload, ingest={"accepted": 1})
    assert client.post("/api/ingest/heartbeat", json=malformed).status_code == 400
    mixed = dict(payload, sensor_process="up")
    assert client.post("/api/ingest/heartbeat", json=mixed).status_code == 400


def test_actual_web_producer_vectors_survive_adapter_and_ingest(client, tmp_path):
    log, policy = tmp_path / "web.jsonl", tmp_path / "policy.json"
    policy.write_text('{"version":0,"entries":[]}')
    portal = web_app({"TESTING": True, "LOG_PATH": str(log), "BLOCKLIST_PATH": str(policy),
        "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"), "WEB_EVENT_SCHEMA_VERSION": "1.1", "LAB_RUN_ID": "prototype"})
    web = portal.test_client()
    vectors = json.loads((ROOT / "contracts/examples/input_indicator_vectors.json").read_text())["vectors"]
    for vector in vectors:
        web.post("/search", json={"q": vector["value"]}, environ_overrides={"REMOTE_ADDR": "192.168.77.10"})
    mapper = WebMapper("prototype", "live", {})
    mapped = [mapper.map(line) for line in log.read_text().splitlines()]
    assert len(mapped) == len(vectors) == 27
    assert all(validate(event) is None for event in mapped)
    result = client.post("/api/ingest/events", json={"events": mapped}).json()
    assert result == {"accepted": 27, "duplicates": 0, "rejected": []}
    stored = client.get("/api/events").json()["items"]
    by_record = {event["source_record_id"]: event for event in stored}
    for vector, event in zip(vectors, mapped):
        saved = by_record[event["source_record_id"]]
        findings = client.app.state.db.list_findings(saved["incident_id"])
        classes = {c for finding in findings if finding["rule_id"] == "R07"
            and saved["event_id"] in finding["evidence_event_ids"] for c in finding["web_attack_class"]}
        assert classes == set(vector["classes"])
