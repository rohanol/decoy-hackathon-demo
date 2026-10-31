"""M4 depth regressions; in-process clients and temporary state only."""
import base64
import hashlib
import io
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.web.app import ASSET, COOKIE, create_app
from decoys.web.sessions import SessionStore


@pytest.fixture
def portal(tmp_path):
    log, state = tmp_path / "web.json", tmp_path / "blocklist.json"
    state.write_text(json.dumps({"version": 0, "entries": []}))
    now = [100.0]
    app = create_app({"TESTING": True, "LOG_PATH": str(log), "BLOCKLIST_PATH": str(state),
                      "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"),
                      "LAB_RUN_ID": "depth-run", "SESSION_CLOCK": lambda: now[0]})
    yield app, app.test_client(), log, state, now
    if log.exists():
        validator = Draft202012Validator(json.loads((ROOT / "contracts/event.schema.json").read_text()),
                                        format_checker=FormatChecker())
        from backend.models import IngestEvent
        for row in events(log):
            validator.validate(row)
            IngestEvent.model_validate(row)


def events(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def login(client):
    response = client.post("/login", data={"username": "svc_portal", "password": "DGLAB-Portal-4471"})
    assert response.status_code == 200
    return response


def test_authenticated_workflow_rotation_logout_and_secret_cookie(portal):
    _, client, log, _, _ = portal
    assert client.get("/dashboard").status_code == 401
    old = client.get_cookie(COOKIE).value
    anonymous = events(log)[-1]["session_id"]
    response = login(client)
    cookie = client.get_cookie(COOKIE).value
    assert cookie != old
    assert "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Lax" in response.headers["Set-Cookie"]
    assert events(log)[-1]["attributes"]["previous_session_id"] == anonymous
    sid = events(log)[-1]["session_id"]
    assert sid != anonymous and cookie not in sid
    assert client.get("/dashboard").status_code == 200
    download = client.get("/download?file=customer_data.csv")
    assert download.data == ASSET.read_bytes()
    assert events(log)[-1]["session_id"] == sid
    assert client.post("/logout").status_code == 200
    assert client.get("/dashboard").status_code == 401
    assert client.get("/download?file=customer_data.csv").status_code == 401
    # Reusing the old privileged cookie cannot resurrect a revoked session.
    client.set_cookie(COOKIE, cookie)
    assert client.get("/dashboard").status_code == 401
    assert cookie not in log.read_text() and old not in log.read_text()


def test_expiry_run_boundary_failed_login_and_restart(portal):
    app, client, log, _, now = portal
    login(client)
    cookie = client.get_cookie(COOKIE).value
    now[0] += 901
    assert client.get("/dashboard").status_code == 401
    login(client)
    app.config["LAB_RUN_ID"] = "next-run"
    assert client.get("/dashboard").status_code == 401
    login(client)
    assert client.post("/login", data={"username": "svc_portal", "password": "wrong"}).status_code == 401
    assert client.get("/dashboard").status_code == 401
    assert SessionStore(clock=lambda: now[0]).get(cookie, "depth-run") is None


def test_two_clients_one_ip_have_distinct_sessions(portal):
    app, first, log, _, _ = portal
    first.get("/")
    sid_a = events(log)[-1]["session_id"]
    first.get("/search?q=report")
    assert events(log)[-1]["session_id"] == sid_a
    second = app.test_client()
    second.get("/")
    assert events(log)[-1]["src_ip"] == "127.0.0.1"
    assert events(log)[-1]["session_id"] != sid_a


def test_session_capacity_and_ttl_are_bounded():
    now = [0]
    store = SessionStore(capacity=2, ttl=5, clock=lambda: now[0])
    old, _ = store.create("r")
    store.create("r")
    current, _ = store.create("r")
    assert store.get(old, "r") is None
    assert store.get(current, "other") is None
    now[0] = 5
    assert store.get(current, "r") is None
    assert store.get("x" * 1000, "r") is None


@pytest.mark.parametrize("location", ["query", "form", "json"])
def test_search_inputs_remain_observable_without_real_queries(portal, location):
    _, client, log, _, _ = portal
    payload = "x' UNION SELECT name FROM users--"
    if location == "query":
        response = client.get("/search", query_string={"q": payload})
    elif location == "form":
        response = client.post("/search", data={"q": payload})
    else:
        response = client.post("/search", json={"q": payload})
    assert response.status_code == 500 and b"SQLSTATE" in response.data
    row = events(log)[-1]
    assert row["event_type"] == "http_request"
    assert row["attributes"]["input_features"] == [{"location": location, "field": "q", "value": payload}]
    assert row["attributes"]["response_class"] == "fake_error"
    assert "web_attack_class" not in row["attributes"]  # M3 owns classification.


def test_login_and_download_keep_http_companions_and_unique_record_ids(portal):
    _, client, log, _, _ = portal
    login(client)
    response = client.get("/download?file=customer_data.csv&q=%3Cscript%3Eexample%3C/script%3E")
    rows = events(log)
    assert [r["event_type"] for r in rows] == ["http_request", "auth_success", "http_request", "synthetic_file_access"]
    assert len({r["source_record_id"] for r in rows}) == 4
    for http, semantic in (rows[:2], rows[2:]):
        assert http["attributes"]["request_id"] == semantic["attributes"]["request_id"]
        assert http["session_id"] == semantic["session_id"]
    assert rows[-1]["attributes"]["request_id"] == response.headers["X-Request-ID"]
    assert "<script>" in rows[-2]["attributes"]["query_redacted"]


def test_bait_proof_is_for_a_real_get_not_head_or_connection(portal):
    _, client, log, _, _ = portal
    client.get("/")
    client.head("/.env")
    assert all(r["event_type"] == "http_request" for r in events(log))
    response = client.get("/.env")
    proof = events(log)[-1]
    attrs = proof["attributes"]
    assert proof["event_type"] == "synthetic_file_access"
    assert attrs["evidence_kind"] == "bait_served"
    assert attrs["asset_id"] == "backup_env" and attrs["honeytoken_id"] == "tok_backup_01"
    assert attrs["sha256"] == hashlib.sha256(response.data).hexdigest()
    assert attrs["size_bytes"] == len(response.data)
    assert attrs["digest_scope"] == "full_response"
    client.get("/.env")
    assert events(log)[-1]["attributes"]["issuance_id"] != attrs["issuance_id"]
    assert "DGLAB-Bkp-2210" not in log.read_text()


@pytest.mark.parametrize("url", ["/", "/dashboard", "/upload", "/download?file=customer_data.csv", "/.env", "/static/missing.css"])
def test_blocked_paths_never_claim_auth_or_bait_results(portal, url):
    _, client, log, state, _ = portal
    state.write_text(json.dumps({"version": 2, "entries": [{"ip": "192.168.77.10", "action_id": "act_depth", "expires_at": "2099-01-01T00:00:00Z"}]}))
    assert client.get(url, environ_overrides={"REMOTE_ADDR": "192.168.77.10"}).status_code == 403
    row, = events(log)
    assert row["event_type"] == "blocked_request"
    assert row["attributes"]["block_action_id"] == "act_depth"
    assert "issuance_id" not in row["attributes"]


@pytest.mark.parametrize("blocked", [False, True])
def test_nested_json_secret_copies_are_redacted_before_any_logging(portal, blocked):
    _, client, log, state, _ = portal
    secret = "private-json-phrase"
    if blocked:
        state.write_text(json.dumps({"version": 1, "entries": [{"ip": "127.0.0.1", "action_id": "act_x", "expires_at": "2099-01-01T00:00:00Z"}]}))
        # Direct loopback is intentionally not allowed by the actual checker.
        # Use the configured allowed lab source for this blocked case.
        state.write_text(state.read_text().replace("127.0.0.1", "192.168.77.10"))
    response = client.post("/search", json={"q": secret, "nested": {"password": secret}},
                           query_string={"q": secret}, headers={"User-Agent": secret},
                           environ_overrides={"REMOTE_ADDR": "192.168.77.10"})
    assert response.status_code == (403 if blocked else 200)
    assert secret not in log.read_text()


def test_cookie_authorization_basic_and_encoded_secret_copies(portal):
    _, client, log, _, _ = portal
    client.set_cookie(COOKIE, "private-cookie")
    encoded = base64.b64encode(b"user:private-basic").decode()
    client.post("/search?q=private-cookie", json={"q": "private-basic", "token": "private-token"},
                headers={"Authorization": "Basic " + encoded, "User-Agent": "private-token private-basic private-cookie"})
    for secret in ["private-cookie", "private-basic", "private-token", encoded]:
        assert secret not in log.read_text()
    client.post("/search", data={"q": "private-field", "%70assword": "private-field"})
    assert "private-field" not in log.read_text()


def test_redaction_precedes_query_encoding_and_partial_feature_clipping(portal):
    _, client, log, _, _ = portal
    secret = "private phrase with spaces"
    client.post("/search", query_string={"q": secret, "password": secret},
                data={"q": secret}, headers={"User-Agent": secret})
    text = log.read_text()
    assert secret not in text and secret.replace(" ", "+") not in text
    large = "private-long-phrase" * 40
    client.post("/login", data={"username": large, "q": large, "password": large})
    assert large[:100] not in log.read_text()


def test_manifest_matches_the_only_fixed_download():
    manifest = json.loads((ASSET.parent / "manifest.json").read_text())
    fixture = manifest["assets"][0]
    assert fixture["access"] == "authenticated_decoy_session"
    assert fixture["sha256"] == hashlib.sha256(ASSET.read_bytes()).hexdigest()
    assert fixture["size_bytes"] == ASSET.stat().st_size


@pytest.mark.parametrize("data,mimetype", [(b'{"password":"hidden",', "application/json"),
                                          (b"opaque-body", "text/plain"),
                                          (b"x" * 17000, "application/json")])
def test_uninspectable_body_suppresses_cross_location_free_text(portal, data, mimetype):
    _, client, log, _, _ = portal
    client.post("/search?q=hidden", data=data, content_type=mimetype, headers={"User-Agent": "hidden"})
    attrs = events(log)[-1]["attributes"]
    assert attrs["input_features"] == []
    assert attrs["query_redacted"] == "<not retained>"
    assert attrs["user_agent"] == "<not retained>"


def test_truncated_or_deep_json_cannot_leak_unvisited_secrets(portal):
    _, client, log, _, _ = portal
    deep = {"password": "private-deep"}
    for _ in range(8):
        deep = {"child": deep}
    client.post("/search?q=private-deep", json={"q": "private-deep", "deep": deep}, headers={"User-Agent": "private-deep"})
    assert "private-deep" not in log.read_text()
    client.post("/search", json={"q": "a" * 14000})
    assert events(log)[-1]["attributes"]["input_truncated"]


def test_unknown_routes_and_wrong_methods_still_capture_form_context(portal):
    _, client, log, _, _ = portal
    assert client.post("/unknown", data={"q": "<script>example</script>"}).status_code == 404
    assert client.post("/download", json={"q": "<script>example</script>"}).status_code == 405
    assert all(row["attributes"]["input_features"] for row in events(log))


def test_upload_requires_login_and_discards_complete_text(portal, tmp_path):
    _, client, log, _, _ = portal
    assert client.get("/upload").status_code == 401
    login(client)
    before = set(tmp_path.iterdir())
    data = b"synthetic report; never execute this text"
    response = client.post("/upload", data={"report": (io.BytesIO(data), "../../report.txt", "text/plain")})
    assert response.status_code == 200
    attrs = events(log)[-1]["attributes"]
    assert attrs["upload_outcome"] == "accepted_discarded"
    assert attrs["sha256"] == hashlib.sha256(data).hexdigest()
    assert attrs["digest_scope"] == "full_accepted_file" and attrs["size_bytes"] == len(data)
    assert data.decode() not in log.read_text() and b"never execute" not in response.data
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("data,mime,status", [(b"x" * 8192, "text/plain", 200),
                                            (b"x" * 8193, "text/plain", 413),
                                            (b"\x00\xff", "text/plain", 415),
                                            (b"text", "application/octet-stream", 415)])
def test_upload_limits_and_rejection_hash_scope(portal, data, mime, status):
    _, client, log, _, _ = portal
    login(client)
    assert client.post("/upload", data={"report": (io.BytesIO(data), "report.txt", mime)}).status_code == status
    attrs = events(log)[-1]["attributes"]
    if status != 200:
        assert "sha256" not in attrs


def test_policy_precedes_upload_and_never_hashes_blocked_file(portal):
    _, client, log, state, _ = portal
    state.write_text(json.dumps({"version": 1, "entries": [{"ip": "192.168.77.10", "action_id": "act_upload", "expires_at": "2099-01-01T00:00:00Z"}]}))
    assert client.post("/upload", data={"report": (io.BytesIO(b"lab"), "report.txt", "text/plain")},
                       environ_overrides={"REMOTE_ADDR": "192.168.77.10"}).status_code == 403
    assert "sha256" not in events(log)[-1]["attributes"]


def test_concurrent_semantic_pairs_are_contiguous_and_distinct(portal):
    app, _, log, _, _ = portal
    def fetch(_):
        with app.test_client() as client:
            return client.get("/.env").status_code
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(fetch, range(24))) == [200] * 24
    rows = events(log)
    assert len(rows) == len({r["source_record_id"] for r in rows}) == 48
    for index in range(0, len(rows), 2):
        assert rows[index]["event_type"] == "http_request"
        assert rows[index + 1]["event_type"] == "synthetic_file_access"
        assert rows[index]["attributes"]["request_id"] == rows[index + 1]["attributes"]["request_id"]


def test_real_adapter_backend_accept_new_observations_without_contract_changes(portal, tmp_path):
    from fastapi.testclient import TestClient
    from backend.main import create_app as backend_app
    from sensors.adapter import WebMapper, validate
    _, client, log, _, _ = portal
    login(client)
    client.post("/search", json={"q": "<script>example</script>", "password": "private-interop"})
    client.get("/download?file=customer_data.csv")
    client.get("/.env")
    mapper = WebMapper("depth-run", "live", {})
    mapped = [mapper.map(line) for line in log.read_text().splitlines()]
    assert all(validate(event) is None for event in mapped)
    backend = backend_app(str(tmp_path / "integration.db"))
    # This test covers producer -> adapter -> API/storage, not M2 action state.
    backend.state.hooks._on_event = None
    with TestClient(backend) as api:
        response = api.post("/api/ingest/events", json={"events": mapped})
        assert response.status_code == 200
        assert response.json() == {"accepted": len(mapped), "duplicates": 0, "rejected": []}
        assert api.post("/api/ingest/events", json={"events": mapped}).json()["duplicates"] == len(mapped)
        stored = api.get("/api/events").json()["items"]
        assert len(stored) == len(mapped)
        assert all(e["session_id"] for e in stored)
        assert {e["attributes"]["request_id"] for e in stored} == {e["attributes"]["request_id"] for e in mapped}
        assert "private-interop" not in json.dumps(stored)
        assert any(e["attributes"].get("evidence_kind") == "bait_served" for e in stored)
        assert any(e["attributes"].get("input_features") for e in stored)


def test_payloads_never_open_networks_or_run_processes(portal, monkeypatch):
    import os
    import socket
    import subprocess
    import urllib.request
    _, client, _, _, _ = portal
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected network/process side effect")
    for module, name in ((os, "system"), (subprocess, "Popen"), (socket, "getaddrinfo"),
                         (socket, "create_connection"), (urllib.request, "urlopen")):
        monkeypatch.setattr(module, name, forbidden)
    login(client)
    for route in ["/search", "/download", "/ping", "/unknown"]:
        response = client.post(route, json={"q": "$(id); curl https://example.invalid/never", "file": "/etc/passwd"})
        assert b"$(id)" not in response.data and b"example.invalid" not in response.data
    assert client.post("/upload", data={"report": (io.BytesIO(b"synthetic text"), "report.txt", "text/plain")}).status_code == 200
