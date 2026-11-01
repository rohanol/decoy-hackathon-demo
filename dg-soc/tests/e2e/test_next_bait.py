"""M4 producer checks against M3 eb2a94e. No traffic leaves loopback/test clients."""
import base64
import hashlib
import hmac
import io
import json
import os
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.web.app import create_app
from decoys.web.backup import ASSET_ID, DB_PASSWORD, SMB_PASSWORD, build_backup
from decoys.web.gateway_context import verify

CONTRACT = json.loads((Path(__file__).parent / "fixtures/event.schema.v1_2.eb2a94e.json").read_text())
VALIDATOR = Draft202012Validator(CONTRACT, format_checker=FormatChecker())
KEY = "DGLAB-GWCTX-" + "ab" * 32
RUN = "m4-producer-test"


def signed(**changes):
    data = {"gw_req": "gw_0123456789abcdef", "gw_sess": "gws_" + "a" * 32,
            "client_ip": "192.168.77.10", "client_port": 51234, "run": RUN,
            "upstream": "web-decoy-01", "iat": time.time(), **changes}
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    body = encode(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())
    mac = hmac.new(KEY.encode(), ("v1." + body).encode(), hashlib.sha256).digest()
    return "v1." + body + "." + encode(mac)


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def portal(tmp_path):
    log, state = tmp_path / "web.json", tmp_path / "policy.json"
    state.write_text('{"version":0,"entries":[]}')
    app = create_app({"TESTING": True, "LOG_PATH": str(log), "BLOCKLIST_PATH": str(state),
                      "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"),
                      "LAB_RUN_ID": RUN, "WEB_EVENT_SCHEMA_VERSION": "1.2", "DG_GATEWAY_CONTEXT_KEY": KEY})
    yield app, app.test_client(), log, state
    if log.exists():
        for event in rows(log):
            VALIDATOR.validate(event)
        text = log.read_text()
        for secret in (KEY, DB_PASSWORD, SMB_PASSWORD, "DGLAB-Bkp-2210"):
            assert secret not in text


def test_contract_snapshot_matches_published_version():
    current = json.loads((ROOT / "contracts/event.schema.json").read_text())
    if "1.2" in current["properties"]["schema_version"]["enum"]:
        assert current == CONTRACT, "M3 contract changed: review producer compatibility before updating snapshot"


def test_zip_is_fixed_inert_and_metadata_matches(portal):
    app, client, log, _ = portal
    response = client.get("/backup/backup.zip")
    assert response.status_code == 200
    assert response.mimetype == "application/zip"
    assert response.headers["Content-Disposition"] == 'attachment; filename="backup.zip"'
    request, serving, bait = rows(log)
    assert [e["event_type"] for e in (request, serving, bait)] == ["http_request", "synthetic_file_access", "bait_served"]
    attrs = bait["attributes"]
    assert attrs["sha256"] == hashlib.sha256(response.data).hexdigest()
    assert attrs["size_bytes"] == len(response.data)
    assert attrs["asset_id"] == ASSET_ID
    assert attrs["transfer"]["completion"] == "unknown"
    assert "bytes_written" not in attrs["transfer"]
    assert len({e["attributes"]["request_id"] for e in rows(log)}) == 1
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.testzip() is None
        assert set(archive.namelist()) == {"README.txt", "admin-secrets.txt", "customer_data.csv", "db_settings.txt", "share_accounts.csv"}
        for entry, metadata in zip(archive.infolist(), attrs["archive"]["entries"]):
            assert "/" not in entry.filename and "\\" not in entry.filename and ".." not in entry.filename
            assert stat.S_ISREG(entry.external_attr >> 16)
            content = archive.read(entry)
            content.decode("utf-8")
            assert metadata["name"] == entry.filename
            assert metadata["size_bytes"] == len(content)
            assert metadata["sha256"] == hashlib.sha256(content).hexdigest()
        assert DB_PASSWORD.encode() in archive.read("db_settings.txt")
        assert SMB_PASSWORD.encode() in archive.read("share_accounts.csv")
    assert build_backup(b"x")[0] == build_backup(b"x")[0]


def test_repeated_static_bait_has_distinct_issuances_same_tokens(portal):
    _, client, log, _ = portal
    client.get("/backup/backup.zip")
    client.get("/backup/backup.zip")
    bait = [e["attributes"] for e in rows(log) if e["event_type"] == "bait_served"]
    assert bait[0]["issuance_id"] != bait[1]["issuance_id"]
    assert bait[0]["honeytoken_ids"] == bait[1]["honeytoken_ids"] == ["tok_db_01", "tok_smb_01"]


def test_head_and_unknown_archive_do_not_issue_bait(portal):
    _, client, log, _ = portal
    assert client.head("/backup/backup.zip").data == b""
    assert client.get("/backup/other.zip").status_code == 404
    assert all(e["event_type"] == "http_request" for e in rows(log))


def test_signed_context_overrides_only_with_valid_envelope(portal):
    _, client, log, _ = portal
    client.get("/backup/backup.zip", headers={"X-DG-Gateway-Context": signed(),
               "X-Forwarded-For": "203.0.113.1", "X-Gateway-Session": "client-spoof"})
    for event in rows(log):
        assert event["src_ip"] == "192.168.77.10" and event["src_port"] == 51234
        assert event["attributes"]["ingress"]["gateway_context"] == "verified"
    assert "client-spoof" not in log.read_text()


def test_unsigned_headers_never_change_source(portal):
    _, client, log, _ = portal
    client.get("/login", headers={"X-Forwarded-For": "192.168.77.10", "X-Real-IP": "192.168.77.10"})
    assert rows(log)[0]["src_ip"] == "127.0.0.1"
    assert rows(log)[0]["attributes"]["ingress"] == {"gateway_context": "absent"}


@pytest.mark.parametrize("changes,reason", [
    ({"run": "other"}, "wrong_run"), ({"upstream": "demo-app-01"}, "wrong_upstream"),
    ({"iat": time.time() - 600}, "expired"), ({"iat": float("nan")}, "malformed"),
    ({"iat": float("inf")}, "malformed"), ({"iat": True}, "malformed"),
    ({"client_port": -1}, "malformed"), ({"client_port": True}, "malformed"),
    ({"client_ip": "::1"}, "malformed"), ({"gw_sess": "bearer-cookie"}, "malformed"),
    ({"gw_req": "short"}, "malformed"), ({"extra": "no"}, "malformed"),
])
def test_invalid_signed_context_cannot_serve_archive(portal, changes, reason):
    _, client, log, _ = portal
    response = client.get("/backup/backup.zip", headers={"X-DG-Gateway-Context": signed(**changes)})
    assert response.status_code == 400
    event, = rows(log)
    assert event["src_ip"] == "127.0.0.1"
    assert event["attributes"]["ingress"] == {"gateway_context": "invalid", "invalid_reason": reason}


def test_bad_mac_missing_key_and_oversized_header():
    assert verify(signed(), None, RUN)[0]["invalid_reason"] == "bad_signature"
    assert verify(signed()[:-2] + "aa", KEY, RUN)[0]["gateway_context"] == "invalid"
    assert verify("x" * 4097, KEY, RUN)[0]["invalid_reason"] == "malformed"
    assert verify(None, KEY, RUN)[0] == {"gateway_context": "absent"}


def test_policy_runs_on_verified_source_before_archive(portal):
    from datetime import datetime, timedelta, timezone
    _, client, log, state = portal
    state.write_text(json.dumps({"version": 4, "entries": [{"ip": "192.168.77.10", "action_id": "act_test",
                     "policy_revision": 4, "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()}]}))
    assert client.get("/backup/backup.zip", headers={"X-DG-Gateway-Context": signed()}).status_code == 403
    event, = rows(log)
    assert event["event_type"] == "blocked_request" and event["src_ip"] == "192.168.77.10"
    assert event["attributes"]["policy_revision"] == 4


def test_log_failure_cannot_return_zip_or_issue_success(portal, tmp_path):
    app, client, log, _ = portal
    app.config["LOG_PATH"] = str(tmp_path)  # a directory, guaranteed write failure
    result = client.get("/backup/backup.zip")
    assert result.status_code == 503 and result.mimetype == "text/html"
    assert b"PK\x03\x04" not in result.data and not log.exists()


def test_secrets_redacted_before_write_and_theme_has_no_external_assets(portal):
    _, client, log, _ = portal
    response = client.get("/", query_string={"q": DB_PASSWORD, "password": "not-a-real-password"})
    text = response.data.decode()
    assert "DeceptionGraph Research Portal" in text
    assert "http://" not in text and "https://" not in text
    assert "ISOLATED LAB DECOY" not in text
    assert "not-a-real-password" not in log.read_text()
    for route in ("/reports", "/reports/coastal-sensor-calibration", "/resources", "/login"):
        assert client.get(route).status_code == 200
    assert client.get("/reports/%3Cscript%3E").status_code == 404


def test_token_inventory_matches_archive_and_database():
    from decoys.database.server import NATIVE_VERIFIER
    assert NATIVE_VERIFIER == hashlib.sha1(hashlib.sha1(DB_PASSWORD.encode()).digest()).digest()
    cfg = yaml.safe_load((ROOT / "config/honeytokens.yaml").read_text())
    tokens = {t["id"]: t for t in cfg["tokens"]}
    for token_id, value in (("tok_db_01", DB_PASSWORD), ("tok_smb_01", SMB_PASSWORD)):
        assert tokens[token_id]["value_sha256"] == hashlib.sha256(value.encode()).hexdigest()
    assert any(a["asset_id"] == ASSET_ID for a in cfg["bait_assets"])


def test_legacy_versions_do_not_enable_archive(tmp_path):
    for version in ("1.0", "1.1"):
        app = create_app({"TESTING": True, "LOG_PATH": str(tmp_path / "old.json"),
                          "WEB_EVENT_SCHEMA_VERSION": version}, policy_check=lambda _: None)
        assert app.test_client().get("/backup/backup.zip").status_code == 404


@pytest.mark.parametrize("target", ["127.0.0.1", "example.com", "192.168.77.0/24"])
def test_new_scenario_refuses_every_nonlab_target_before_network(target):
    result = subprocess.run([sys.executable, str(ROOT / "scenarios/next_bait.py"), target],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and "only isolated lab target" in result.stderr
