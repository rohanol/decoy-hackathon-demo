"""Runtime for contract v1.2: four honeypots, the HTTP gateway and the normal demo app.

Fixtures: contracts/examples/telemetry_v1_2.json (PROVISIONAL synthetic; no producer exists yet).
The two new tokens and the backup.zip asset are M4's to add to config/honeytokens.yaml, so these
tests run on a copy of config/ with exactly the additions the fixture names.
"""
import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from backend.main import create_app

ROOT = Path(__file__).resolve().parents[2]
FX = json.loads((ROOT / "contracts/examples/telemetry_v1_2.json").read_text(encoding="utf-8"))
EXP = FX["expected_reads"]
FINDING = Draft202012Validator(json.loads((ROOT / "contracts/finding.schema.json").read_text()),
                               format_checker=FormatChecker())
RUN = "run-2026-11-02-01"


@pytest.fixture
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    shutil.copytree(ROOT / "config", cfg)
    tokens = yaml.safe_load((cfg / "honeytokens.yaml").read_text(encoding="utf-8"))
    add = FX["honeytokens_yaml_additions"]
    tokens["bait_assets"] += add["bait_assets"]
    tokens["tokens"] += [dict(t, value_sha256="0" * 64) for t in add["tokens"]]
    (cfg / "honeytokens.yaml").write_text(yaml.safe_dump(tokens), encoding="utf-8")
    monkeypatch.setenv("DG_CONFIG_DIR", str(cfg))
    with TestClient(create_app(str(tmp_path / "t.db"))) as c:
        yield c


def events(client, *evs):
    r = client.post("/api/ingest/events", json={"events": list(evs)})
    assert r.status_code == 200, r.text
    return r.json()


def telemetry(client, *recs):
    r = client.post("/api/ingest/telemetry", json={"records": list(recs)})
    assert r.status_code == 200, r.text
    return r.json()


def load_all(client):
    assert events(client, *FX["events_valid"]) == EXP["ingest_events_response"]
    assert telemetry(client, *FX["telemetry_valid"]) == EXP["ingest_telemetry_response"]


def case_of(client, **match):
    return next(i for i in client.get("/api/incidents").json()["items"]
                if all(i.get(k) == v for k, v in match.items()))


def event_by_record(client, rid):
    return next(e for e in client.get("/api/events?limit=1000").json()["items"] if e["source_record_id"] == rid)


def tel(base_index, **attrs):
    r = copy.deepcopy(FX["telemetry_valid"][base_index])
    r["attributes"].update(attrs)
    return r


def ev(base_index, rid, **attrs):
    e = copy.deepcopy(FX["events_valid"][base_index])
    e["source_record_id"] = rid
    e["attributes"].update(attrs)
    return e


# ---- ingest: validation, versions, dedup, modes ----
def test_fixtures_ingest_and_deduplicate(client):
    load_all(client)
    assert events(client, *FX["events_valid"]) == EXP["ingest_events_again_response"]
    assert telemetry(client, *FX["telemetry_valid"]) == {"accepted": 0, "duplicates": 7, "rejected": []}


@pytest.mark.parametrize("case", FX["events_invalid"], ids=lambda c: c["why"][:40])
def test_invalid_events_rejected_with_field(client, case):
    out = events(client, case["record"])
    assert out["accepted"] == 0 and len(out["rejected"]) == 1, case["why"]
    assert case["expect_rejected_field"].split(".")[0] in out["rejected"][0]["reason"]


@pytest.mark.parametrize("case", FX["telemetry_invalid"], ids=lambda c: c["why"][:40])
def test_invalid_telemetry_rejected_with_field(client, case):
    out = telemetry(client, case["record"])
    assert out["accepted"] == 0 and len(out["rejected"]) == 1, case["why"]
    assert case["expect_rejected_field"].split(".")[0] in out["rejected"][0]["reason"]


def test_interfaces_never_cross(client):
    assert events(client, FX["telemetry_valid"][0])["rejected"]
    assert telemetry(client, FX["events_valid"][0])["rejected"]
    r = client.post("/api/ingest/telemetry", json={"events": []})
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"
    r = client.post("/api/ingest/telemetry", content=b"x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415
    r = client.post("/api/ingest/telemetry", json={"records": [FX["telemetry_valid"][0]] * 101})
    assert r.status_code == 413


def test_telemetry_never_becomes_an_event_case_or_run(client):
    telemetry(client, *FX["telemetry_valid"])
    assert client.get("/api/events").json()["items"] == []
    assert client.get("/api/incidents").json()["items"] == []
    assert client.get("/api/runs").json()["items"] == []  # telemetry never creates or activates a run
    assert len(client.get("/api/telemetry").json()["items"]) == 7


def test_mixed_modes_rejected_both_ways(client):
    load_all(client)
    replay = dict(copy.deepcopy(FX["telemetry_valid"][0]), record_id="r-1", capture_mode="replay", origin_record_id="gw-dec-0001")
    assert "is live" in telemetry(client, replay)["rejected"][0]["reason"]
    # A run first seen through telemetry keeps that mode for events too.
    tel_first = dict(copy.deepcopy(FX["telemetry_valid"][0]), record_id="r-2", lab_run_id="replay-only",
                     capture_mode="replay", origin_record_id="gw-dec-0001")
    assert telemetry(client, tel_first)["accepted"] == 1
    live_event = dict(copy.deepcopy(FX["events_valid"][4]), lab_run_id="replay-only")
    assert "is replay" in events(client, live_event)["rejected"][0]["reason"]


def test_replay_telemetry_has_its_own_dedup_namespace(client):
    base = dict(copy.deepcopy(FX["telemetry_valid"][0]), capture_mode="replay", origin_record_id="gw-dec-0001")
    assert telemetry(client, dict(base, lab_run_id="replay-a"), dict(base, lab_run_id="replay-b"))["accepted"] == 2
    assert telemetry(client, dict(base, lab_run_id="replay-a"))["duplicates"] == 1


def test_old_versions_unchanged_and_unknown_version_rejected(client):
    v11 = json.loads((ROOT / "contracts/examples/events_v1_1.json").read_text(encoding="utf-8"))["events"]
    assert events(client, *v11)["rejected"] == []
    assert "schema_version" in events(client, dict(FX["events_valid"][0], schema_version="1.3"))["rejected"][0]["reason"]


def test_websocket_sends_telemetry_after_commit(client):
    with client.websocket_connect("/ws/events") as ws:
        telemetry(client, FX["telemetry_valid"][0])
        msg = ws.receive_json()
        assert msg["type"] == "telemetry" and msg["data"]["record_id"] == "gw-dec-0001"
        assert msg["seq"] == 0 and msg["data"]["telemetry_seq"] == 1  # seq stays the event seq


# ---- requested routing versus observed handling ----
def strip_ids(x):
    if isinstance(x, dict):
        return {k: ("<id>" if k in ("event_id", "incident_id") else strip_ids(v)) for k, v in x.items()}
    if isinstance(x, list):
        return [strip_ids(v) for v in x]
    return x


def test_gateway_request_observed_matches_expected_read(client):
    load_all(client)
    got = client.get("/api/gateway/requests/gw_00000000000002").json()
    assert strip_ids(got) == strip_ids(EXP["gateway_request"])


def test_normal_app_request_observed_through_its_own_record(client):
    load_all(client)
    got = client.get("/api/gateway/requests/gw_00000000000001").json()
    assert got["correlation"] == {"status": "observed", "reasons": []}
    assert got["upstream_handling"] == [{"kind": "telemetry", "record_id": "app-0001", "source_id": "demo-app-01",
                                         "app_request_id": "app-req-0001", "occurred_at": "2026-11-02T05:00:05Z"}]
    assert got["gateway_observed_upstream"]["status_code"] == 200


def test_decision_alone_is_not_handling(client):
    telemetry(client, FX["telemetry_valid"][3], FX["telemetry_valid"][4])
    got = client.get("/api/gateway/requests/gw_00000000000002").json()
    assert got["correlation"]["status"] == "gateway_only" and got["upstream_handling"] == []
    assert got["gateway_observed_upstream"]["outcome"] == "response_received"  # the gateway's view only


def test_upstream_record_without_decision(client):
    events(client, FX["events_valid"][0])
    got = client.get("/api/gateway/requests/gw_00000000000002").json()
    assert got["correlation"]["status"] == "upstream_only" and got["decision"] is None


def test_unknown_gateway_request_is_404(client):
    r = client.get("/api/gateway/requests/gw_00000000009999")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


@pytest.mark.parametrize("mutate,reason", [
    (lambda recs: recs[1]["attributes"].update(src_ip="192.168.77.11"), "client_mismatch"),
    (lambda recs: recs[1].update(occurred_at="2026-11-02T05:01:05Z"), "time_skew"),
])
def test_app_conflicts(client, mutate, reason):
    recs = copy.deepcopy(FX["telemetry_valid"][:3])
    mutate(recs)
    telemetry(client, *recs)
    got = client.get("/api/gateway/requests/gw_00000000000001").json()
    assert got["correlation"] == {"status": "conflict", "reasons": [reason]}


def test_decoy_record_under_a_normal_app_decision_conflicts(client):
    telemetry(client, FX["telemetry_valid"][0])
    events(client, ev(0, "web-x", ingress={"gateway_context": "verified", "gateway_request_id": "gw_00000000000001",
                                           "gateway_session_ref": "gws_3f9a1c2b4d5e6f70"}, request_id="req-x"))
    got = client.get("/api/gateway/requests/gw_00000000000001").json()
    assert got["correlation"]["status"] == "conflict" and "wrong_upstream" in got["correlation"]["reasons"]


def test_one_context_on_two_decoy_requests_is_reuse(client):
    load_all(client)
    events(client, ev(0, "web-replayed", request_id="req-other"))
    got = client.get("/api/gateway/requests/gw_00000000000002").json()
    assert got["correlation"] == {"status": "conflict", "reasons": ["context_reused"]}


def test_several_records_of_one_decoy_request_are_not_reuse(client):
    load_all(client)  # web-0003 and web-0003-bait share req-0003 and gw_..03
    got = client.get("/api/gateway/requests/gw_00000000000003").json()
    assert got["correlation"]["status"] == "observed" and len(got["upstream_handling"]) == 2


def test_case_routing_view_matches_expected_read(client):
    load_all(client)
    web = case_of(client, case_kind="web_activity")
    got = client.get(f"/api/incidents/{web['incident_id']}/routing").json()
    want = dict(EXP["incident_routing_web_case"], incident_id=web["incident_id"])
    assert got == want


def test_normal_app_contact_is_never_joined_by_ip(client):
    """A normal-app record from the same address but another gateway session is not this case's contact."""
    load_all(client)
    other = tel(1, gateway_session_ref="gws_00000000000000ff", app_request_id="app-req-2", gateway_request_id="gw_00000000000077")
    other["record_id"] = "app-0002"
    telemetry(client, other)
    web = case_of(client, case_kind="web_activity")
    contact = client.get(f"/api/incidents/{web['incident_id']}/routing").json()["normal_app_contact"]
    assert [r["record_id"] for r in contact["records"]] == ["app-0001"]
    assert contact["coverage"]["records_in_run"] == 2


def test_direct_traffic_only_case_has_no_gateway_claims(client):
    events(client, FX["events_valid"][3])
    web = case_of(client, case_kind="web_activity")
    got = client.get(f"/api/incidents/{web['incident_id']}/routing").json()
    assert got["gateway_requests"] == [] and got["ingress"] == {"verified": 0, "absent": 1, "invalid": 0}
    assert got["normal_app_contact"]["records"] == []
    assert "Missing records do not show" in got["normal_app_contact"]["statement"]


def test_routing_on_unknown_case_is_404(client):
    assert client.get("/api/incidents/inc_404/routing").status_code == 404


# ---- cases, rules, tokens, scores ----
def findings(client, incident_id):
    out = client.app.state.db.list_findings(incident_id)
    for f in out:
        assert not list(FINDING.iter_errors(f)), f
    return out


def test_new_sensors_get_their_own_session_cases(client):
    load_all(client)
    kinds = {(i["case_kind"], i["sensor_id"]) for i in client.get("/api/incidents").json()["items"]}
    assert {("db_session", "db-decoy-01"), ("file_session", "file-decoy-01"), ("web_activity", "web-decoy-01")} <= kinds
    assert not any(l["kind"] == "candidate" and "db-decoy-01" in (l["from_sensor"], l["to_sensor"])
                   for l in client.get("/api/links").json()["items"])  # no IP/time links for new sensors


def test_archive_serving_links_planted_db_credential(client):
    load_all(client)
    db_case = case_of(client, case_kind="db_session", session_id="db-conn-18")
    link = next(l for l in client.get("/api/links").json()["items"] if l["to_sensor"] == "db-decoy-01")
    assert {k: link[k] for k in EXP["token_link_db"]} == EXP["token_link_db"]
    r09 = [f for f in findings(client, db_case["incident_id"]) if f["rule_id"] == "R09"]
    want = EXP["findings_db_case"][0]
    assert len(r09) == 1 and {k: r09[0][k] for k in want} == want


def test_repeated_zip_serving_keeps_static_token_ambiguous(client):
    load_all(client)
    again = copy.deepcopy(FX["events_valid"][2])
    again.update(source_record_id="web-0005-bait", occurred_at="2026-11-02T05:00:40Z")
    again["attributes"].update(issuance_id="iss-zip-0002", request_id="req-0005")
    again["attributes"]["ingress"] = {"gateway_context": "absent"}
    events(client, again)
    link = next(l for l in client.get("/api/links").json()["items"] if l["to_sensor"] == "db-decoy-01")
    assert link["attribution"] == "ambiguous" and link["candidate_issuance_ids"] == ["iss-zip-0001", "iss-zip-0002"]


def test_planted_credential_without_serving_is_orphan(client):
    events(client, FX["events_valid"][6])
    db_case = case_of(client, case_kind="db_session")
    r09 = next(f for f in findings(client, db_case["incident_id"]) if f["rule_id"] == "R09")
    assert r09["token_relation"] == "orphan" and r09["points"] == 0 and db_case["score"] == 0


def test_confirming_the_zip_link_counts_once(client):
    load_all(client)
    link = next(l for l in client.get("/api/links").json()["items"] if l["to_sensor"] == "db-decoy-01")
    client.post(f"/api/links/{link['link_id']}/decision", json={"decision": "confirm", "rationale": "zip served then used"})
    db_case = case_of(client, case_kind="db_session", session_id="db-conn-18")
    assert db_case["score"] == 15  # R09 only; db_request is shown, not scored
    events(client, *FX["events_valid"])  # duplicates
    telemetry(client, *FX["telemetry_valid"])  # gateway records
    assert case_of(client, incident_id=db_case["incident_id"])["score"] == 15


def test_gateway_records_change_no_score(client):
    events(client, *FX["events_valid"])
    before = {i["incident_id"]: i["score"] for i in client.get("/api/incidents").json()["items"]}
    telemetry(client, *FX["telemetry_valid"])
    after = {i["incident_id"]: i["score"] for i in client.get("/api/incidents").json()["items"]}
    assert before == after


def test_file_upload_and_rules(client):
    load_all(client)
    smb = case_of(client, case_kind="file_session")
    rules = sorted(f["rule_id"] for f in findings(client, smb["incident_id"]))
    assert rules == EXP["findings_file_case_rules"]
    r12 = next(f for f in findings(client, smb["incident_id"]) if f["rule_id"] == "R12")
    assert r12["technique_ids"] == [] and "verdict" in r12["mapping"][0]["rationale"]
    assert "malware" not in r12["label"].lower()


def test_smb_synthetic_file_is_lure_access(client):
    read = {"schema_version": "1.2", "source_record_id": "smb-lure", "sensor_id": "file-decoy-01",
            "event_type": "synthetic_file_access", "occurred_at": "2026-11-02T05:02:05Z", "src_ip": "192.168.77.10",
            "session_id": "smb-5f2e", "lab_run_id": RUN, "capture_mode": "live",
            "attributes": {"protocol": "smb", "asset_id": "smb:/archive/staff.csv", "outcome": "served"}}
    events(client, read)
    r04 = next(f for f in findings(client, case_of(client, case_kind="file_session")["incident_id"]) if f["rule_id"] == "R04")
    assert (r04["rule_version"], r04["stage"], r04["technique_ids"]) == ("R04@3", "lure_access", [])


def db_fail(i, conn, user="root"):
    e = copy.deepcopy(FX["events_valid"][5])
    e.update(source_record_id=f"db-f{i}", session_id=conn, occurred_at=f"2026-11-02T05:03:{10 + i:02d}Z")
    e["attributes"]["username"] = user
    return e


def test_r11_counts_attempts_across_connections(client):
    events(client, *[db_fail(i, f"c{i}") for i in range(5)])
    cred = case_of(client, case_kind="credential_attempts")
    assert cred["sensor_id"] == "db-decoy-01"
    (f,) = findings(client, cred["incident_id"])
    assert f["rule_id"] == "R11" and f["technique_ids"] == ["T1110"] and "5 in 60 s" in f["label"]
    assert "distinct" not in f["label"]  # salted proofs cannot show distinct passwords
    assert cred["score"] == 20


def test_r11_needs_five_and_r01_never_runs_on_db(client):
    events(client, *[db_fail(i, f"c{i}") for i in range(4)])
    assert not any(i["case_kind"] == "credential_attempts" for i in client.get("/api/incidents").json()["items"])
    assert all(f["rule_id"] != "R01" for i in client.get("/api/incidents").json()["items"]
               for f in client.app.state.db.list_findings(i["incident_id"]))


# ---- health, capabilities, eligibility ----
def test_health_has_four_honeypots_and_separate_telemetry(client):
    load_all(client)
    for hb in FX["heartbeats"]["valid"]:
        assert client.post("/api/ingest/heartbeat", json=hb).json() == {"ok": True}
    h = client.get("/api/health").json()
    assert list(h["sensor_health"]) == EXP["health_excerpt"]["sensor_health_keys"]
    assert list(h["telemetry_health"]) == EXP["health_excerpt"]["telemetry_health_keys"]
    assert h["sensor_health"]["db-decoy-01"]["collection"] == "ok"
    gw = h["telemetry_health"]["gateway-01"]
    assert gw["collection"] == "ok" and gw["collector_id"] == "gateway-collector" and gw["counted_as_honeypot"] is False
    assert gw["last_record_at"] == "2026-11-02T05:00:20Z"


def test_telemetry_row_without_heartbeat(client):
    load_all(client)
    row = client.get("/api/health").json()["telemetry_health"]["gateway-01"]
    want = EXP["health_excerpt"]["telemetry_health_row"]
    assert {k: row[k] for k in want} == want


@pytest.mark.parametrize("case", FX["heartbeats"]["invalid"], ids=lambda c: c["why"][:40])
def test_bad_heartbeats_rejected(client, case):
    r = client.post("/api/ingest/heartbeat", json=case["body"])
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"


def test_existing_adapter_heartbeat_unchanged(client):
    hb = {k: v for k, v in FX["heartbeats"]["valid"][0].items()}
    hb["sensor_id"] = "web-decoy-01"
    assert client.post("/api/ingest/heartbeat", json=hb).json() == {"ok": True}
    assert client.get("/api/health").json()["telemetry_health"]["gateway-01"]["collection"] == "never"


def test_sources_registry(client):
    s = client.get("/api/sources").json()
    assert [x["source_id"] for x in s["honeypots"]] == EXP["sources_excerpt"]["honeypots"]
    assert [x["source_id"] for x in s["telemetry_sources"]] == EXP["sources_excerpt"]["telemetry_sources"]
    assert s["honeypot_count"] == 4


def test_db_case_has_no_response_capability(client):
    load_all(client)
    db_case = case_of(client, case_kind="db_session", session_id="db-conn-18")
    e = client.get(f"/api/incidents/{db_case['incident_id']}/response-eligibility").json()
    want = EXP["eligibility_db_case"]
    assert e["eligible"] is False and all(r in e["reasons"] for r in want["reasons_include"])
    assert e["response_scope"] == want["response_scope"]


def test_web_case_eligibility_keeps_its_shape(client):
    load_all(client)
    web = case_of(client, case_kind="web_activity")
    e = client.get(f"/api/incidents/{web['incident_id']}/response-eligibility").json()
    assert {"incident_id", "eligible", "target_ip", "lab_run_id", "capture_mode", "reasons",
            "last_web_observation_at", "checked_at", "response_scope"} <= set(e)
    assert all(r["code"] != "response_unsupported_sensor" for r in e["reasons"])


# ---- migration 3 -> 4 ----
def test_migration_v3_to_v4_backs_up_and_keeps_ids(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    with TestClient(create_app(str(path))) as c:
        v11 = json.loads((ROOT / "contracts/examples/events_v1_1.json").read_text(encoding="utf-8"))["events"]
        c.post("/api/ingest/events", json={"events": v11})
        before = {e["event_id"]: e["incident_id"] for e in c.get("/api/events?limit=1000").json()["items"]}
        cases = [i["incident_id"] for i in c.get("/api/incidents").json()["items"]]
    con = sqlite3.connect(path)  # make it a v3 file: no telemetry tables
    con.executescript("DROP TABLE telemetry; DROP TABLE telemetry_heartbeats; PRAGMA user_version = 3;")
    con.close()
    with TestClient(create_app(str(path))) as c:
        after = {e["event_id"]: e["incident_id"] for e in c.get("/api/events?limit=1000").json()["items"]}
        assert after == before and [i["incident_id"] for i in c.get("/api/incidents").json()["items"]] == cases
        assert c.post("/api/ingest/telemetry", json={"records": [FX["telemetry_valid"][0]]}).json()["accepted"] == 1
        assert c.app.state.db._writer.execute("PRAGMA user_version").fetchone()[0] == 4
    assert (tmp_path / "old.db.v3.bak").exists()
    old = sqlite3.connect(tmp_path / "old.db.v3.bak")
    assert old.execute("PRAGMA user_version").fetchone()[0] == 3
    assert old.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(before)
    old.close()
