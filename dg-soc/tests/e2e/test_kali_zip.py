"""Direct Kali web flow; no replacement portal or gateway."""
import hashlib
import io
import json
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.web.app import create_app
from decoys.web.backup import ASSET_ID, DB_PASSWORD, SMB_PASSWORD


@pytest.fixture
def portal(tmp_path):
    log, state = tmp_path / "web.json", tmp_path / "policy.json"
    state.write_text('{"version":0,"entries":[]}')
    app = create_app({"TESTING": True, "LOG_PATH": str(log), "BLOCKLIST_PATH": str(state),
                      "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"),
                      "LAB_RUN_ID": "kali-zip", "WEB_EVENT_SCHEMA_VERSION": "1.2"})
    yield app, app.test_client(), log, state
    if log.exists():
        schema = json.loads((ROOT / "contracts/event.schema.json").read_text())
        for event in records(log):
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(event)
        for secret in (DB_PASSWORD, SMB_PASSWORD):
            assert secret not in log.read_text()


def records(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_existing_portal_and_source_attribution_stay_direct(portal):
    _, client, log, _ = portal
    response = client.get("/", headers={"X-Forwarded-For": "192.168.77.10"})
    assert b"Operations Portal" in response.data and b"Research Portal" not in response.data
    assert records(log)[0]["src_ip"] == "127.0.0.1"


def test_inert_archive_and_actual_metadata(portal):
    _, client, log, _ = portal
    response = client.get("/backup/backup.zip")
    assert response.status_code == 200 and response.mimetype == "application/zip"
    assert response.headers["Content-Disposition"] == 'attachment; filename="backup.zip"'
    request, result, bait = records(log)
    assert [e["event_type"] for e in (request, result, bait)] == ["http_request", "synthetic_file_access", "bait_served"]
    attrs = bait["attributes"]
    assert attrs["sha256"] == hashlib.sha256(response.data).hexdigest()
    assert attrs["asset_id"] == ASSET_ID and attrs["size_bytes"] == len(response.data)
    assert attrs["transfer"]["completion"] == "unknown"
    assert "bytes_written" not in attrs["transfer"]
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.testzip() is None
        assert len(archive.infolist()) == 5
        for entry, item in zip(archive.infolist(), attrs["archive"]["entries"]):
            assert stat.S_ISREG(entry.external_attr >> 16)
            assert not any(x in entry.filename for x in ("/", "\\", ".."))
            data = archive.read(entry)
            data.decode("utf-8")
            assert item["sha256"] == hashlib.sha256(data).hexdigest()
        assert DB_PASSWORD.encode() in archive.read("db_settings.txt")
        assert SMB_PASSWORD.encode() in archive.read("share_accounts.csv")


def test_head_failed_path_and_repeated_servings(portal):
    _, client, log, _ = portal
    assert client.head("/backup/backup.zip").data == b""
    assert client.get("/backup/other.zip").status_code == 404
    assert all(e["event_type"] == "http_request" for e in records(log))
    client.get("/backup/backup.zip")
    client.get("/backup/backup.zip")
    bait = [e for e in records(log) if e["event_type"] == "bait_served"]
    assert bait[0]["attributes"]["issuance_id"] != bait[1]["attributes"]["issuance_id"]
    assert bait[0]["attributes"]["honeytoken_ids"] == bait[1]["attributes"]["honeytoken_ids"]


def test_log_failure_cannot_serve_archive(portal, tmp_path):
    app, client, log, _ = portal
    app.config["LOG_PATH"] = str(tmp_path)
    response = client.get("/backup/backup.zip")
    assert response.status_code == 503 and not response.data.startswith(b"PK")
    assert not log.exists()


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_old_versions_do_not_activate_zip(tmp_path, version):
    app = create_app({"TESTING": True, "LOG_PATH": str(tmp_path / "legacy.json"),
                      "WEB_EVENT_SCHEMA_VERSION": version}, policy_check=lambda _: None)
    assert app.test_client().get("/backup/backup.zip").status_code == 404


@pytest.mark.parametrize("target", ["127.0.0.1", "example.com", "192.168.77.0/24"])
def test_manual_probe_refuses_nonlab_target(target):
    result = subprocess.run([sys.executable, str(ROOT / "scenarios/next_bait.py"), target], capture_output=True, text=True)
    assert result.returncode == 2 and "only isolated lab target" in result.stderr
