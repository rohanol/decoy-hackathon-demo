"""Regression boundaries introduced by native challenge-response producers."""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sensors import adapter as ad
from sensors.tests.test_adapter import FakeBackend

FIXTURE = json.loads((ROOT / "contracts/examples/telemetry_v1_2.json").read_text())


def native():
    return copy.deepcopy(next(e for e in FIXTURE["events_valid"] if e["sensor_id"] == "db-decoy-01" and e["event_type"] == "auth_success"))


def test_native_keeps_original_run_mode_and_record_id():
    event = native()
    mapped = ad.NativeMapper("db-decoy-01").map(json.dumps(event))
    assert mapped == event and ad.validate(mapped) is None
    assert ad.NativeMapper("file-decoy-01").map(json.dumps(event)) is None
    assert ad.validate({**event, "schema_version": "1.1"}) is not None


def test_native_forbidden_payload_is_not_retained_in_quarantine(tmp_path):
    event = native()
    event["attributes"]["credential"]["password"] = "private-value-do-not-store"
    path = tmp_path / "db.json"
    path.write_text(json.dumps(event) + "\n")
    rejected = tmp_path / "rejected.json"
    sender = ad.Sender("http://127.0.0.1:9", max_retries=1)
    assert ad.process_source(str(path), ad.NativeMapper("db-decoy-01"), ad.Checkpoint(str(tmp_path / "c.json")), sender, str(rejected)) == 0
    assert "private-value" not in rejected.read_text() and '"event"' not in rejected.read_text()


def test_claimed_proof_without_a_token_cannot_be_sent():
    event = native()
    event["attributes"].pop("honeytoken_id")
    assert ad.validate(event) is not None
    assert ad.NativeMapper("db-decoy-01").map(json.dumps(event)) is None


def test_rotated_records_are_consumed_with_stable_ids(tmp_path):
    first, second = native(), native()
    second["source_record_id"] += "-next"
    path = tmp_path / "db.json"
    path.with_name("db.json.1").write_text(json.dumps(first) + "\n")
    path.write_text(json.dumps(second) + "\n")
    sender = ad.Sender("http://127.0.0.1:9", max_retries=1)
    delivered = []
    sender.post = lambda events: delivered.extend(events) or []
    checkpoint = ad.Checkpoint(str(tmp_path / "checkpoint.json"))
    mapper = ad.NativeMapper("db-decoy-01")
    assert ad.process_rotating_source(str(path), mapper, checkpoint, sender) == 2
    assert [e["source_record_id"] for e in delivered] == [first["source_record_id"], second["source_record_id"]]
    assert ad.process_rotating_source(str(path), mapper, ad.Checkpoint(str(tmp_path / "checkpoint.json")), sender) == 0


def test_mixed_sender_counts_and_ingest_times_stay_per_source():
    backend = FakeBackend(reject_indices=(0,))
    try:
        sender = ad.Sender(backend.url, max_retries=1)
        rejected = sender.post([{"sensor_id": "db-decoy-01", "id": "db-refused"},
                                {"sensor_id": "file-decoy-01", "id": "file-refused"},
                                {"sensor_id": "file-decoy-01", "id": "file-accepted"}])
        assert {item["index"] for item in rejected} == {0, 1}
        database, files = sender._totals("db-decoy-01"), sender._totals("file-decoy-01")
        assert database["ingest"]["accepted"] == 0 and database["ingest"]["rejected"] == 1
        assert database["last_ingest_at"] is None
        assert files["ingest"]["accepted"] == 1 and files["ingest"]["rejected"] == 1
        assert files["last_ingest_at"] is not None
        assert sender._totals("ssh-decoy-01")["last_ingest_at"] is None
    finally:
        backend.stop()
