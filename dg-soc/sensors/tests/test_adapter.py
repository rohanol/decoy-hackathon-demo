"""Run: python -m pytest sensors/tests -q
NOTE: fixtures/cowrie_sample.json is SYNTHETIC but follows Cowrie's JSON field names. Replace/extend it with
20 real sanitised lines from deployment/state/cowrie-log/cowrie.json once Cowrie runs (task 1 and 3)."""
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sensors"))
import adapter as ad  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "cowrie_sample.json"
TOKENS = {"084c235fbf6efc6ab082575c6977c6c7cade5e46a982a9692e2c1e9a8af7a443": "tok_portal_01",
          "aeed687d56b3778fb5b51158ff6005ac65874f3169360258ef18279a6d9751cd": "tok_backup_01"}


def map_all(lines):
    m = ad.CowrieMapper("run-t", "live", TOKENS)
    return [e for e in (m.map(x) for x in lines) if e]


def fixture_lines():
    return FIX.read_text().splitlines()


def test_cowrie_mapping_types_and_validation():
    evs = map_all(fixture_lines())
    assert [e["event_type"] for e in evs] == [
        "connection_open", "auth_failure", "auth_success", "command_input", "command_input", "connection_close"]
    assert all(ad.validate(e) is None for e in evs)
    assert all(e["sensor_id"] == "ssh-decoy-01" and e["src_ip"] == "192.168.77.10" for e in evs)
    assert all(set(e) <= ad.TOP_LEVEL_KEYS for e in evs)
    fixture = FIX.read_text()
    assert '"password"' not in fixture and "123456" not in fixture and "DemoPass-2026" not in fixture


def test_sanitized_web_fixture_maps_request_bait_read_and_block():
    p = FIX.parent / "web_sample.jsonl"
    mapper = ad.WebMapper("run-t", "replay", TOKENS)
    events = [mapper.map(line) for line in p.read_text().splitlines()]
    assert [e["event_type"] for e in events] == ["http_request", "synthetic_file_access", "blocked_request"]
    assert all(ad.validate(event) is None for event in events)
    assert events[1]["attributes"]["outcome"] == "served"
    assert events[2]["attributes"]["policy_revision"] == 3


def test_source_record_id_is_sha256_of_raw_line():
    line = fixture_lines()[0]
    assert map_all([line])[0]["source_record_id"] == hashlib.sha256(line.encode()).hexdigest()


def test_password_hashed_and_never_forwarded():
    line = json.dumps({"eventid": "cowrie.login.failed", "username": "dg_demo", "password": "fixture-only-secret",
                       "timestamp": "2026-11-01T04:30:01Z", "src_ip": "192.168.77.10", "session": "a1b2c3d4"})
    evs = map_all([line])
    blob = json.dumps(evs)
    assert "fixture-only-secret" not in blob and '"password"' not in blob
    fail = evs[0]["attributes"]
    assert fail["password_sha256"] == hashlib.sha256(b"fixture-only-secret").hexdigest() and fail["username"] == "dg_demo"


def test_client_version_attached_to_next_event_once():
    evs = map_all(fixture_lines())
    assert evs[1]["attributes"]["client_version"] == "SSH-2.0-libssh_0.10.6"
    assert "client_version" not in evs[2]["attributes"]


def test_command_and_timestamps():
    evs = map_all(fixture_lines())
    assert evs[3]["attributes"]["command"] == "ls" and evs[4]["attributes"]["command"] == "cat notes.txt"
    assert evs[0]["occurred_at"] == "2026-11-01T04:30:00.100000Z"


def test_only_dispatched_canned_network_handler_marks_denial():
    mapper = ad.CowrieMapper("run-t", "live", {})
    line = json.dumps({"eventid": "dgsoc.network.denied", "command": "curl https://example.invalid",
                       "timestamp": "2026-11-01T04:31:00Z", "src_ip": "192.168.77.10", "session": "s"})
    event = mapper.map(line)
    assert event["event_type"] == "command_input"
    assert event["attributes"]["command"] == "curl https://example.invalid"
    assert event["attributes"]["network_attempt_outcome"] == "denied"
    assert event["attributes"]["real_execution"] is False


def test_honeytoken_match_and_negative():
    m = ad.CowrieMapper("run-t", "live", TOKENS)
    hit = json.dumps({"eventid": "cowrie.login.success", "username": "backup", "password": "DGLAB-Bkp-2210",
                      "timestamp": "2026-11-01T04:31:00.000000Z", "src_ip": "192.168.77.10", "session": "s"})
    assert m.map(hit)["attributes"]["honeytoken_id"] == "tok_backup_01"
    miss = map_all(fixture_lines())
    assert not any("honeytoken_id" in e["attributes"] for e in miss)


def test_bad_lines_skipped():
    m = ad.CowrieMapper("run-t", "live", {})
    assert m.map("not json") is None
    assert m.map(json.dumps({"eventid": "cowrie.login.failed", "src_ip": "not-an-ip", "timestamp": "2026-11-01T04:30:00Z"})) is None
    assert m.map(json.dumps({"eventid": "cowrie.login.failed", "src_ip": "192.168.77.10", "timestamp": "garbage"})) is None


def test_web_mapper_fills_defaults_hashes_passwords_and_flags_tokens():
    m = ad.WebMapper("run-t", "live", TOKENS)
    line = json.dumps({"event_type": "http_request", "occurred_at": "2026-11-01T04:40:00Z", "src_ip": "192.168.77.10",
                       "source_record_id": "uuid-1", "attributes": {"method": "POST", "path": "/login", "password": "DGLAB-Portal-4471"}})
    ev = m.map(line)
    assert ad.validate(ev) is None and ev["sensor_id"] == "web-decoy-01" and ev["source_record_id"] == "uuid-1"
    assert "password" not in ev["attributes"] and ev["attributes"]["honeytoken_id"] == "tok_portal_01"
    assert "DGLAB-Portal-4471" not in json.dumps(ev)


def test_validate_rejects_bad_events():
    ev = map_all(fixture_lines())[0]
    assert ad.validate({**ev, "event_type": "nope"}) == "event_type"
    assert ad.validate({**ev, "sensor_id": "x"}) == "sensor_id"
    assert ad.validate({**ev, "src_ip": "999.1.1.1"}) == "src_ip: not an ipv4"


def test_read_new_lines_partial_line_and_truncation(tmp_path):
    p = tmp_path / "log"
    p.write_bytes(b'{"a":1}\n{"b":2')
    lines, off = ad.read_new_lines(str(p), 0)
    assert lines == ['{"a":1}'] and off == 8
    with open(p, "ab") as fh:
        fh.write(b"}\n")
    lines, off2 = ad.read_new_lines(str(p), off)
    assert lines == ['{"b":2}']
    p.write_bytes(b'{"c":3}\n')  # truncated below offset
    lines, _ = ad.read_new_lines(str(p), off2)
    assert lines == ['{"c":3}']


def test_batching_limits():
    evs = [{"x": i} for i in range(250)]
    sizes = [len(b) for b in ad.batches(evs)]
    assert sizes == [100, 100, 50]


class FakeBackend:
    def __init__(self, fail_first=0, reject_indices=()):
        self.received, self.fail_first, self.calls = [], fail_first, 0
        self.reject_indices = list(reject_indices)
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.calls += 1
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if outer.calls <= outer.fail_first:
                    self.send_response(503)
                    self.end_headers()
                    return
                rejected = [{"index": i, "reason": "synthetic rejection"} for i in outer.reject_indices if i < len(body["events"])]
                outer.received.extend(ev for i, ev in enumerate(body["events"]) if i not in outer.reject_indices)
                out = json.dumps({"accepted": len(body["events"]) - len(rejected), "duplicates": 0, "rejected": rejected}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()


@pytest.fixture
def backend():
    b = FakeBackend()
    yield b
    b.stop()


def run_once(tmp_path, url, extra=()):
    cow = tmp_path / "cowrie.json"
    if not cow.exists():
        cow.write_text(FIX.read_text())
    return ad.main(["--once", "--backend", url, "--cowrie-log", str(cow), "--web-log", str(tmp_path / "web.json"),
                    "--checkpoint", str(tmp_path / "ckpt.json"), "--quarantine", str(tmp_path / "rejected.jsonl"),
                    "--health", str(tmp_path / "health.json"), "--honeytokens", str(ROOT / "config" / "honeytokens.yaml"), *extra])


def test_end_to_end_delivers_and_restart_does_not_resend(tmp_path, backend):
    assert run_once(tmp_path, backend.url) == 0
    assert len(backend.received) == 6
    run_once(tmp_path, backend.url)  # restart: checkpoint must prevent resend
    assert len(backend.received) == 6
    with open(tmp_path / "cowrie.json", "a") as fh:
        fh.write(json.dumps({"eventid": "cowrie.command.input", "input": "id", "timestamp": "2026-11-01T04:31:00.000000Z",
                             "src_ip": "192.168.77.10", "session": "a1b2c3d4"}) + "\n")
    run_once(tmp_path, backend.url)
    assert len(backend.received) == 7 and backend.received[-1]["attributes"]["command"] == "id"


def test_pending_client_version_survives_collector_restart(tmp_path, backend):
    cow = tmp_path / "cowrie.json"
    version = {"eventid": "cowrie.client.version", "version": "SSH-2.0-fixture", "timestamp": "2026-11-01T04:30:00Z",
               "src_ip": "192.168.77.10", "session": "restart-session"}
    cow.write_text(json.dumps(version) + "\n")
    assert run_once(tmp_path, backend.url) == 0
    login = {"eventid": "cowrie.login.failed", "username": "demo", "password": "in-memory-secret",
             "timestamp": "2026-11-01T04:30:01Z", "src_ip": "192.168.77.10", "session": "restart-session"}
    with cow.open("a") as stream:
        stream.write(json.dumps(login) + "\n")
    assert run_once(tmp_path, backend.url) == 0
    assert backend.received[0]["attributes"]["client_version"] == "SSH-2.0-fixture"
    assert "in-memory-secret" not in json.dumps(backend.received)


def test_retry_then_success(tmp_path, monkeypatch):
    b = FakeBackend(fail_first=2)
    try:
        monkeypatch.setattr(ad.time, "sleep", lambda s: None)  # no real backoff in tests
        run_once(tmp_path, b.url)
        assert len(b.received) == 6 and b.calls == 3
    finally:
        b.stop()


def test_backend_down_keeps_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(ad.time, "sleep", lambda s: None)
    run_once(tmp_path, "http://127.0.0.1:9")  # nothing listens on port 9
    ck = json.loads((tmp_path / "ckpt.json").read_text()) if (tmp_path / "ckpt.json").exists() else {}
    assert ck.get(str(tmp_path / "cowrie.json"), {}).get("offset", 0) == 0
    assert json.loads((tmp_path / "health.json").read_text())["status"] == "degraded"
    b = FakeBackend()
    try:
        run_once(tmp_path, b.url)
        assert len(b.received) == 6  # nothing was lost
    finally:
        b.stop()


def test_backend_rejection_is_sanitized_and_durable_before_checkpoint(tmp_path):
    b = FakeBackend(reject_indices=(1,))
    try:
        assert run_once(tmp_path, b.url) == 0
        records = [json.loads(line) for line in (tmp_path / "rejected.jsonl").read_text().splitlines()]
        rejection = next(record for record in records if record["reason"] == "synthetic rejection")
        assert rejection["event"]["event_type"] == "auth_failure"
        serialized = json.dumps(records)
        assert "123456" not in serialized and "DemoPass-2026" not in serialized
        checkpoint = json.loads((tmp_path / "ckpt.json").read_text())
        assert checkpoint[str(tmp_path / "cowrie.json")]["offset"] > 0
    finally:
        b.stop()


def test_collector_health_updates_without_attack_activity(tmp_path):
    empty = tmp_path / "cowrie.json"
    empty.write_text("")
    assert run_once(tmp_path, "http://127.0.0.1:9") == 0
    health = json.loads((tmp_path / "health.json").read_text())
    assert health["status"] == "healthy" and health["last_poll_at"]
    assert health["last_poll_delivered"] == 0
