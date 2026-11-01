"""Routes, accounts, escaping, redaction and telemetry shape of the normal demo app."""
import time

from jsonschema import Draft202012Validator, FormatChecker

from portal.context import sign
from tests.conftest import KEY, RUN, schema

PAGES = ["/", "/login", "/search", "/search?q=sensor", "/reports", "/reports/coastal-sensor-calibration", "/resources"]
GOOD = {"username": "researcher@example.com", "password": "DGLAB-Portal-Researcher-2026"}


def ctx(**over):
    payload = {"gw_req": "gw_0000000000000a", "gw_sess": "gws_3f9a1c2b4d5e6f70", "client_ip": "192.168.77.10",
               "client_port": 51544, "run": RUN, "upstream": "demo-app-01", "iat": int(time.time())}
    payload.update(over)
    return {"X-DG-Gateway-Context": sign(payload, KEY)}


def test_readiness(portal):
    _, client, records, _ = portal
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.get_json() == {"ok": True, "source_id": "demo-app-01", "lab_run_id": RUN}
    assert records() == []  # probes are not participant traffic


def test_fixed_pages_render(portal):
    _, client, _, _ = portal
    for path in PAGES:
        response = client.get(path)
        assert response.status_code == 200, path
        assert b"DeceptionGraph" in response.data


def test_no_bait_no_gateway_controls(portal):
    _, client, _, _ = portal
    assert client.get("/backup/backup.zip").status_code == 404
    assert client.get("/backup/").status_code == 404
    html = b"".join(client.get(path).data for path in PAGES).lower()
    for word in (b"gateway", b"decoy", b"honeypot", b"upstream", b"divert", b"backup.zip", b"x-dg-"):
        assert word not in html, word


def test_login_dashboard_logout(portal):
    _, client, records, _ = portal
    assert client.get("/dashboard").status_code == 302
    bad = client.post("/login", data={**GOOD, "password": "DGLAB-wrong"})
    assert bad.status_code == 401
    ok = client.post("/login", data=GOOD)
    assert ok.status_code == 302 and ok.headers["Location"].endswith("/dashboard")
    assert b"Dr. Asha Verma" in client.get("/dashboard").data
    client.post("/logout")
    assert client.get("/dashboard").status_code == 302
    logins = [r["attributes"]["login"] for r in records() if "login" in r["attributes"]]
    assert logins == [{"username": "researcher@example.com", "outcome": "failed"},
                      {"username": "researcher@example.com", "outcome": "emulated_success"}]


def test_open_redirect_refused(portal):
    _, client, _, _ = portal
    response = client.post("/login?next=//evil.example.com/x", data=GOOD)
    assert response.headers["Location"].endswith("/dashboard")


def test_search_escapes_attacker_text(portal):
    _, client, _, _ = portal
    html = client.get("/search?q=<script>alert(1)</script>").data
    assert b"<script>alert(1)</script>" not in html
    assert b"&lt;script&gt;" in html


def test_no_secret_reaches_disk(portal):
    _, client, _, log = portal
    client.post("/login", data={"username": "x@example.com", "password": "DGLAB-SECRET-PW-1"})
    client.post("/login", data=GOOD)
    client.get("/dashboard")
    client.get("/search?q=DGLAB-TOKEN-IN-QUERY&api_key=hunter2&password=p4ss")
    client.get("/DGLAB-PATH-SECRET")
    text = log.read_text()
    for secret in ("DGLAB-SECRET-PW-1", "DGLAB-Portal-Researcher-2026", "DGLAB-TOKEN-IN-QUERY", "hunter2", "p4ss",
                   "DGLAB-PATH-SECRET", "portal_session"):
        assert secret not in text, secret
    assert "<redacted>" in text


def test_every_record_matches_published_schema(portal):
    _, client, records, _ = portal
    for path in PAGES + ["/nope", "/dashboard", "/static/portal.css", "/search?q=a?b#c"]:
        client.get(path)
    client.get("/", headers=ctx())
    client.get("/", headers=ctx(run="run-other"))
    client.post("/login", data=GOOD)
    validator = Draft202012Validator(schema(), format_checker=FormatChecker())
    got = records()
    assert len(got) >= len(PAGES) + 6
    for record in got:
        errors = sorted(validator.iter_errors(record), key=str)
        assert not errors, (record, errors[0].message)
    classes = {r["attributes"]["route_class"] for r in got}
    assert {"page", "static", "login", "not_found"} <= classes


def test_verified_context_sets_client_and_ids(portal):
    _, client, records, _ = portal
    client.get("/", headers={**ctx(), "X-Forwarded-For": "10.9.9.9"})
    attributes = records()[-1]["attributes"]
    assert attributes["gateway_context"] == "verified"
    assert attributes["src_ip"] == "192.168.77.10"
    assert attributes["gateway_request_id"] == "gw_0000000000000a"
    assert attributes["gateway_session_ref"] == "gws_3f9a1c2b4d5e6f70"


def test_spoofed_forwarding_headers_never_name_the_client(portal):
    _, client, records, _ = portal
    client.get("/", headers={"X-Forwarded-For": "192.168.77.10", "X-Real-IP": "192.168.77.10"})
    attributes = records()[-1]["attributes"]
    assert attributes["gateway_context"] == "absent"
    assert attributes["src_ip"] == "127.0.0.1"
    assert "gateway_request_id" not in attributes


def test_invalid_contexts_carry_reason_and_no_ids(portal):
    _, client, records, _ = portal
    cases = {
        "bad_signature": {"X-DG-Gateway-Context": ctx()["X-DG-Gateway-Context"][:-4] + "AAAA"},
        "wrong_run": ctx(run="run-other"),
        "wrong_upstream": ctx(upstream="web-decoy-01"),
        "expired": ctx(iat=int(time.time()) - 120),
        "malformed": {"X-DG-Gateway-Context": "v1.not-base64!.x"},
    }
    for reason, headers in cases.items():
        client.get("/", headers=headers)
        attributes = records()[-1]["attributes"]
        assert attributes["gateway_context"] == "invalid", reason
        assert attributes["invalid_reason"] == reason
        assert "gateway_request_id" not in attributes and "gateway_session_ref" not in attributes
        assert attributes["src_ip"] == "127.0.0.1"


def test_header_without_configured_key_is_never_trusted(tmp_path):
    from portal.app import create_app
    app = create_app({"TESTING": True, "LAB_RUN_ID": RUN, "GATEWAY_CONTEXT_KEY": "", "TELEMETRY_PATH": str(tmp_path / "a.jsonl")})
    app.test_client().get("/", headers=ctx())
    line = (tmp_path / "a.jsonl").read_text()
    assert '"gateway_context":"invalid"' in line and '"src_ip":"127.0.0.1"' in line
