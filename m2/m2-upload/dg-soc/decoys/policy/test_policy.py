import json
from datetime import datetime, timedelta, timezone

from policy import check

NOW = datetime(2026, 11, 1, 5, 0, 0, tzinfo=timezone.utc)


def write(tmp_path, entries):
    p = tmp_path / "blocklist.json"
    p.write_text(json.dumps({"version": 1, "entries": entries}))
    return str(p)


def entry(ip, minutes, action="act_01"):
    return {"ip": ip, "action_id": action, "expires_at": (NOW + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}


def test_active_entry_blocks(tmp_path):
    assert check("192.168.77.10", write(tmp_path, [entry("192.168.77.10", 2)]), NOW) == "act_01"


def test_expired_entry_ignored(tmp_path):
    assert check("192.168.77.10", write(tmp_path, [entry("192.168.77.10", -1)]), NOW) is None


def test_other_ip_not_blocked(tmp_path):
    assert check("192.168.77.11", write(tmp_path, [entry("192.168.77.10", 2)]), NOW) is None


def test_missing_file_and_garbage_fail_open(tmp_path):
    assert check("192.168.77.10", str(tmp_path / "nope.json"), NOW) is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert check("192.168.77.10", str(bad), NOW) is None


def test_entry_without_expiry_ignored(tmp_path):
    p = write(tmp_path, [{"ip": "192.168.77.10", "action_id": "act_01"}])
    assert check("192.168.77.10", p, NOW) is None
