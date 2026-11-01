import json
from datetime import datetime, timedelta, timezone

from policy import check, check_with_revision

NOW = datetime(2026, 11, 1, 5, 0, 0, tzinfo=timezone.utc)


def write(tmp_path, entries):
    p = tmp_path / "blocklist.json"
    p.write_text(json.dumps({"version": 1, "entries": entries}))
    return str(p)


def entry(ip, minutes, action="act_01"):
    return {"ip": ip, "action_id": action, "expires_at": (NOW + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"), "policy_revision": 3}


def test_active_entry_blocks(tmp_path):
    assert check("192.168.77.10", write(tmp_path, [entry("192.168.77.10", 2)]), NOW) == "act_01"


def test_expired_entry_ignored(tmp_path):
    assert check("192.168.77.10", write(tmp_path, [entry("192.168.77.10", -1)]), NOW) is None


def test_other_ip_not_blocked(tmp_path):
    assert check("192.168.77.11", write(tmp_path, [entry("192.168.77.10", 2)]), NOW) is None


def test_missing_file_and_garbage_raise_for_web_fail_closed(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        check("192.168.77.10", str(tmp_path / "nope.json"), NOW)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError):
        check("192.168.77.10", str(bad), NOW)


def test_entry_without_expiry_fails_closed(tmp_path):
    p = write(tmp_path, [{"ip": "192.168.77.10", "action_id": "act_01"}])
    import pytest
    with pytest.raises(ValueError):
        check("192.168.77.10", p, NOW)


def test_action_and_policy_revision_come_from_same_snapshot(tmp_path):
    path = write(tmp_path, [entry("192.168.77.10", 2)])
    assert check_with_revision("192.168.77.10", path, NOW) == ("act_01", 3)
