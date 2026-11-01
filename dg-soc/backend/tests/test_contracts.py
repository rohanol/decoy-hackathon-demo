"""Contract v1.1 checks (PR m3/evidence-boundaries, step 1).

1. Every example in contracts/examples validates against the JSON Schemas, and every
   deliberately invalid example is rejected.
2. The review's gaps (1 Nov 2026) reproduced against today's backend as strict xfails.
   Each one flips to XPASS, and so fails this suite, once the PR that fixes it lands;
   that PR then removes the xfail mark on purpose.
"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"


def load(name):
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


EVENT_SCHEMA = load("event.schema.json")
FINDING_SCHEMA = load("finding.schema.json")
EVENTS_V11 = load("examples/events_v1_1.json")
API_V11 = load("examples/api_v1_1.json")
EVENTS_P3 = load("examples/events_p3.json")


def validator(schema):
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


EVENT_V = validator(EVENT_SCHEMA)
FINDING_V = validator(FINDING_SCHEMA)


def errors(v, doc):
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in v.iter_errors(doc)]


# ---- 1. examples ----
@pytest.mark.parametrize("ev", EVENTS_V11["events"], ids=lambda e: e["source_record_id"])
def test_v11_examples_validate(ev):
    assert errors(EVENT_V, ev) == []


@pytest.mark.parametrize("ev", EVENTS_P3["events"], ids=lambda e: e["source_record_id"][:12])
def test_v10_fixture_still_validates(ev):
    """v1.1 is additive: the existing 1.0 fixture stays valid unchanged."""
    assert errors(EVENT_V, ev) == []


@pytest.mark.parametrize("case", EVENTS_V11["invalid"], ids=lambda c: c["_why"])
def test_invalid_examples_rejected(case):
    assert errors(EVENT_V, case["event"]), case["_why"]


@pytest.mark.parametrize("f", API_V11["findings"], ids=lambda f: f["finding_id"])
def test_finding_examples_validate(f):
    assert errors(FINDING_V, f) == []


def test_finding_technique_ids_match_mapping():
    for f in API_V11["findings"]:
        assert f["technique_ids"] == [m["technique_id"] for m in f["mapping"] if m["technique_id"]]


def test_examples_cover_the_cases_the_contract_names():
    evs = EVENTS_V11["events"]
    ssh_sessions_on_one_ip = {e["session_id"] for e in evs if e["sensor_id"] == "ssh-decoy-01"
                              and e["event_type"] == "auth_success" and e["src_ip"] == "192.168.77.10"}
    assert len(ssh_sessions_on_one_ip) >= 2                                   # two sessions, one IP
    bait = [e for e in evs if e["event_type"] == "bait_served"]
    assert {b["attributes"]["evidence_basis"] for b in bait} == {"sensor_response", "session_output_log"}
    requested = [e for e in evs if e["attributes"].get("requested_asset_id")]
    assert requested and all(e["event_type"] == "command_input" for e in requested)  # a command stays a request
    env_issuances = {b["attributes"]["issuance_id"] for b in bait if b["attributes"]["asset_id"] == "web:/.env"}
    assert len(env_issuances) >= 2                                            # static credential served twice
    assert any("input_features" in e["attributes"] for e in evs)
    record_ids = {e["source_record_id"] for e in evs}
    modes = {(e["lab_run_id"], e["capture_mode"]) for e in evs}
    assert len({run for run, _ in modes}) == len(modes)                       # no run mixes modes
    assert any(e.get("origin_record_id") in record_ids for e in evs if e["capture_mode"] == "replay")
    assert any(f.get("token_relation") == "orphan" for f in API_V11["findings"])


V10_SCHEMA_V = validator(load("history/event.schema.v1.0.json"))


def v10_event(**attrs_and_top):
    attrs = attrs_and_top.pop("attributes", {})
    ev = {"schema_version": "1.0", "source_record_id": "compat-1", "sensor_id": "web-decoy-01",
          "event_type": "synthetic_file_access", "occurred_at": "2026-11-01T04:31:30Z", "src_ip": "192.168.77.10",
          "lab_run_id": "run-01", "capture_mode": "live", "attributes": attrs}
    ev.update(attrs_and_top)
    return ev


V10_EDGE_CASES = [
    # the reported counterexamples: extensible 1.0 attributes the 1.1 rules would reject
    v10_event(attributes={"asset_id": "customer_data.csv", "fixture_version": 1, "digest_scope": "full_response"}),
    v10_event(attributes={"observation_kind": 7, "request_id": {"nested": True}, "honeytoken_ids": []}),
    v10_event(attributes={"evidence_basis": "derived_from_command", "input_features": "anything"}),
    v10_event(attributes={"method": "X" * 100, "password_sha256": "p" * 300, "block_action_id": "a" * 200}),
    # top-level values 1.0 never bounded
    v10_event(source_record_id="", lab_run_id="r" * 300, session_id="s" * 500, src_port=99999),
    v10_event(lab_run_id=""),
]


@pytest.mark.parametrize("ev", V10_EDGE_CASES)
def test_every_v10_edge_case_valid_under_old_schema_stays_valid(ev):
    assert errors(V10_SCHEMA_V, ev) == []            # it really was valid under 1.0
    assert errors(EVENT_V, ev) == []                 # and still is


@pytest.mark.parametrize("ev", V10_EDGE_CASES[:3])
def test_same_attributes_are_checked_strictly_under_v11(ev):
    assert errors(EVENT_V, dict(ev, schema_version="1.1"))


@pytest.mark.parametrize("ev", [
    v10_event(event_type="bait_served", attributes={"asset_id": "web:/.env", "honeytoken_ids": ["tok_backup_01"],
                                                     "issuance_id": "i", "evidence_basis": "sensor_response"}),
    v10_event(origin_record_id=None),
    v10_event(attributes={"outcome": "attempted"}),
])
def test_v10_rejections_unchanged(ev):
    """Things 1.0 rejected are still rejected for 1.0 events."""
    assert errors(V10_SCHEMA_V, ev) and errors(EVENT_V, ev)


def test_bait_assets_name_known_tokens():
    import yaml
    tokens = {t["id"]: t for t in yaml.safe_load((ROOT / "config/honeytokens.yaml").read_text(encoding="utf-8"))["tokens"]}
    for e in EVENTS_V11["events"]:
        if e["event_type"] == "bait_served":
            for tok in e["attributes"]["honeytoken_ids"]:
                assert tokens[tok]["planted_on"] == e["sensor_id"]            # bait served where it was planted


def test_no_raw_secrets_in_examples():
    text = (CONTRACTS / "examples/events_v1_1.json").read_text(encoding="utf-8")
    assert "DGLAB-" not in text and "DemoPass" not in text


INDICATOR_VECTORS = load("examples/input_indicator_vectors.json")["vectors"]
INDICATOR_ENUM = set(EVENT_SCHEMA["$defs"]["input_features"]["properties"]["indicators"]["items"]["enum"])


@pytest.mark.parametrize("vec", INDICATOR_VECTORS, ids=lambda v: v["value"][:32])
def test_indicator_vectors_match_written_semantics(vec):
    """The table in API.md, read literally (tests/indicator_reference.py), gives exactly the labelled indicators."""
    from backend.tests.indicator_reference import indicators
    assert set(vec["indicators"]) <= INDICATOR_ENUM
    assert indicators(vec["value"]) == set(vec["indicators"])


def test_indicator_vectors_cover_both_review_cases():
    by_value = {v["value"]: v for v in INDICATOR_VECTORS}
    assert by_value["John's quarterly report--"]["classes"] == []
    assert by_value["UNION SELECT name FROM users"]["classes"] == ["sqli"]
    assert sum(1 for v in INDICATOR_VECTORS if not v["classes"]) >= 10   # benign inputs dominate


# ---- 2. review gaps, reproduced against today's backend ----
def v10(ev):
    """The v1.1 example rewritten to 1.0 so today's backend accepts it (gap tests only)."""
    out = {k: v for k, v in ev.items() if k != "origin_record_id"}
    out["schema_version"] = "1.0"
    out["attributes"] = {k: v for k, v in ev["attributes"].items()
                         if k not in ("observation_kind", "evidence_role", "request_id", "digest_scope",
                                      "fixture_version", "issued_expires_at")}
    if out["attributes"].get("outcome") not in (None, "served", "denied", "not_found"):
        out["attributes"].pop("outcome")
    return out


def by_id(record_id):
    return next(e for e in EVENTS_V11["events"] if e["source_record_id"] == record_id)


def post(client, *events):
    r = client.post("/api/ingest/events", json={"events": list(events)})
    assert r.status_code == 200, r.text
    return r.json()


def test_backend_accepts_every_v11_example(client):
    """Was a strict xfail in PR 1; fixed by PR 2 (ingest v1.1)."""
    r = post(client, *EVENTS_V11["events"])
    assert r["rejected"] == [] and r["accepted"] == len(EVENTS_V11["events"])


def test_two_sessions_one_ip_stay_separate(client):
    """Review F1/T01. Was a strict xfail in PR 1; fixed by PR 3 (session cases)."""
    post(client, *[v10(by_id(r)) for r in ("a-ssh-s1-login", "a-ssh-s1-ls", "a-ssh-s2-login", "a-ssh-s2-uptime")])
    incidents = {e["session_id"]: e["incident_id"] for e in client.get("/api/events").json()["items"]}
    assert incidents["sess01"] != incidents["sess02"]
    cases = {c["session_id"]: c for c in client.get("/api/incidents").json()["items"]}
    assert cases["sess01"]["case_kind"] == cases["sess02"]["case_kind"] == "ssh_session"
    assert cases["sess01"]["src_ip"] == cases["sess02"]["src_ip"]  # same address, still two cases


def test_web_not_absorbed_before_confirmation(client):
    """Review F1. Was a strict xfail in PR 1; fixed by PR 3 (session cases)."""
    post(client, v10(by_id("a-ssh-s1-login")), v10(by_id("a-ssh-s1-ls")), v10(by_id("a-web-req-3")))
    ids = {e["sensor_id"]: e["incident_id"] for e in client.get("/api/events").json()["items"]}
    assert ids["ssh-decoy-01"] != ids["web-decoy-01"]
    assert all(c["parent_id"] is None for c in client.get("/api/incidents").json()["items"])


def test_password_guessing_across_sessions_without_absorbing_web(client):
    """Hydra's one-session-per-attempt guessing is still R01, in its own case, citing only SSH evidence."""
    hydra = [v10(by_id(f"a-ssh-h{i}-fail")) for i in range(1, 6)]
    web = v10(by_id("a-web-req-3"))
    post(client, *hydra, web)
    cases = client.get("/api/incidents").json()["items"]
    cred = [c for c in cases if c["case_kind"] == "credential_attempts"]
    assert len(cred) == 1 and cred[0]["event_count"] == 0 and cred[0]["sensor_id"] is None
    r01 = client.app.state.db.list_findings(cred[0]["incident_id"])
    assert [f["rule_id"] for f in r01] == ["R01"]
    events = {e["event_id"]: e for e in client.get("/api/events").json()["items"]}
    assert {events[i]["sensor_id"] for i in r01[0]["evidence_event_ids"]} == {"ssh-decoy-01"}
    web_case = next(c for c in cases if c["case_kind"] == "web_activity")
    assert web_case["parent_id"] is None
    assert all(e["incident_id"] != cred[0]["incident_id"] for e in events.values())  # it takes no events


def test_mixed_live_replay_rejected(client):
    """Review F2/T02. Was a strict xfail in PR 1; fixed by PR 2 (one capture mode per run)."""
    live = v10(by_id("a-ssh-h1-fail"))
    replay = dict(live, source_record_id="mixed-replay-1", capture_mode="replay")
    r = post(client, live, replay)
    assert r["accepted"] == 1 and r["rejected"] and "lab_run_id" in r["rejected"][0]["reason"]


def test_token_use_without_bait_read_has_no_strong_link(client):
    post(client, v10(by_id("a-ssh-h1-open")), v10(by_id("a-web-req-1")))
    kinds = [l["kind"] for l in client.get("/api/links").json()["items"]]
    assert "strong_candidate" not in kinds


def test_web_lure_not_t1005(client):
    post(client, v10(by_id("a-web-req-5")))
    findings = client.app.state.db.list_findings("inc_01")
    assert all("T1005" not in f["technique_ids"] for f in findings)


def test_xss_string_not_t1059_007(client):
    ev = dict(v10(by_id("a-web-req-4")), source_record_id="xss-1")
    ev["attributes"] = dict(ev["attributes"], query_redacted="q=<script>alert(1)</script>")
    post(client, ev)
    assert all("T1059.007" not in f["technique_ids"] for f in client.app.state.db.list_findings("inc_01"))


def test_quoted_command_not_discovery(client):
    post(client, v10(by_id("a-ssh-s1-login")), v10(by_id("a-ssh-s1-echo")))
    assert all(f["rule_id"] != "R03" for f in client.app.state.db.list_findings("inc_01"))


@pytest.mark.xfail(strict=True, reason="gap F11/T10: ordinary trailing dashes flagged as SQLi (fixed in PR 4)")
def test_gap_benign_trailing_dashes_not_sqli(client):
    post(client, v10(by_id("a-web-req-4")))
    assert all(f["rule_id"] != "R07" for f in client.app.state.db.list_findings("inc_01"))


def test_link_reversal_keeps_every_event(client):
    """Must stay true: confirm then reject dissolves the investigation and removes R05, but no event."""
    post(client, v10(by_id("a-ssh-s1-login")), v10(by_id("a-web-req-3")))
    before = client.get("/api/events").json()["items"]
    link = client.get("/api/links").json()["items"][0]["link_id"]
    for decision in ("confirm", "reject"):
        r = client.post(f"/api/links/{link}/decision", json={"decision": decision, "rationale": "checking reversal"})
        assert r.status_code == 200
    assert client.get("/api/events").json()["items"] == before
    cases = client.get("/api/incidents").json()["items"]
    inv = next(c for c in cases if c["case_kind"] == "investigation")
    assert inv["status"] == "dissolved" and inv["score"] == 0
    db = client.app.state.db
    assert all(f["rule_id"] != "R05" for c in cases for f in db.list_findings(c["incident_id"]))
