from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cowrie_image
import lab_checks


def test_clean_native_host(monkeypatch):
    monkeypatch.setattr(lab_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(lab_checks.platform, "release", lambda: "6.8.0-generic")
    monkeypatch.setattr(lab_checks, "output", lambda args: "Ubuntu 24.04" if args[0] == "docker" else "")
    assert not lab_checks.host_errors()


def test_desktop_and_ipv6_gateway_are_blockers(monkeypatch):
    monkeypatch.setattr(lab_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(lab_checks.platform, "release", lambda: "6.6-microsoft-standard-WSL2")
    monkeypatch.setattr(lab_checks, "output", lambda args: "Docker Desktop" if args[0] == "docker" else "default via fe80::1" if "-6" in args else "")
    errors = lab_checks.host_errors()
    assert any("Docker Desktop" in e for e in errors)
    assert any("-6 default" in e for e in errors)


def test_windows_is_not_mistaken_for_offline_linux(monkeypatch):
    monkeypatch.setattr(lab_checks.platform, "system", lambda: "Windows")
    assert lab_checks.host_errors()


def test_source_check_requires_recent_expected_peer(tmp_path, capsys):
    path = tmp_path / "raw.json"
    now = datetime.now(timezone.utc)
    def write(ip, at):
        path.write_text(json.dumps({"timestamp": at.isoformat(), "src_ip": ip, "message": "PRIVATE-PASSWORD"}) + "\n")
    write("172.21.0.1", now)
    assert lab_checks.source_errors({"ssh": path}, {"192.168.77.10"}, now)
    write("192.168.77.10", now - timedelta(minutes=6))
    assert lab_checks.source_errors({"ssh": path}, {"192.168.77.10"}, now)
    write("192.168.77.10", now)
    assert not lab_checks.source_errors({"ssh": path}, {"192.168.77.10"}, now)
    assert "PRIVATE-PASSWORD" not in capsys.readouterr().out


def test_missing_or_malformed_evidence_cannot_pass(tmp_path):
    path = tmp_path / "not-there"
    assert lab_checks.source_errors({"ssh": path}, {"192.168.77.10"})
    path.write_text('not json\n{"src_ip":"192.168.77.10"}\n')
    assert lab_checks.source_errors({"ssh": path}, {"192.168.77.10"})


def test_replay_events_do_not_establish_lab_readiness(tmp_path):
    path = tmp_path / "replay.json"
    path.write_text(json.dumps({"occurred_at": datetime.now(timezone.utc).isoformat(),
                                "src_ip": "192.168.77.10", "capture_mode": "replay"}))
    assert lab_checks.source_errors({"web": path}, {"192.168.77.10"})


def test_gateway_cannot_be_allowed_by_changing_expected_ips(tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "src_ip": "172.21.0.1"}))
    assert lab_checks.source_errors({"ssh": path}, {"172.21.0.1"})


def test_config_validation_handles_commented_supported_options(tmp_path):
    dist, config = tmp_path / "dist", tmp_path / "cfg"
    dist.write_text('[shell]\n#filesystem = fs.pickle\n')
    config.write_text('[shell]\nfilesystem = /custom/fs.pickle\n')
    cowrie_image.validate_config(dist, config)
    config.write_text('[shell]\nunknown_typo = x\n')
    import pytest
    with pytest.raises(ValueError):
        cowrie_image.validate_config(dist, config)


def test_profile_requires_readonly_registry_and_pickle_mounts(monkeypatch):
    monkeypatch.setattr(lab_checks, "output", lambda args: "[]")
    assert len(lab_checks.profile_errors()) == 3
    destinations = ["/cowrie/cowrie-git/src/cowrie/commands/__init__.py",
                    "/cowrie/cowrie-git/src/cowrie/commands/lab_network.py",
                    "/cowrie/cowrie-git/custom/fs.pickle"]
    monkeypatch.setattr(lab_checks, "output", lambda args: json.dumps([{"Destination": path, "RW": False} for path in destinations]))
    assert not lab_checks.profile_errors()
