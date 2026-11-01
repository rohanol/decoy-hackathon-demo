from datetime import datetime, timedelta, timezone

import pytest

from backend.config import load_config
from backend.scoring import severity_for

CFG = load_config()
T0 = datetime(2026, 11, 1, 4, 30, 0, tzinfo=timezone.utc)
_n = 0


def raw(sensor="ssh-decoy-01", etype="auth_failure", at=0, session="s1", src_ip="192.168.77.10", **attrs):
    global _n
    _n += 1
    return {
        "schema_version": "1.0", "source_record_id": f"rec-{_n}", "sensor_id": sensor, "event_type": etype,
        "occurred_at": (T0 + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip, "session_id": session, "lab_run_id": "run-t", "capture_mode": "replay",
        "attributes": attrs,
    }


def webreq(at, path, query=None, etype="http_request", **attrs):
    a = {"method": "GET", "path": path, **attrs}
    if query is not None:
        a["query_redacted"] = query
    return raw("web-decoy-01", etype, at=at, session=None, **a)




def send(client, *events):
    r = client.post("/api/ingest/events", json={"events": list(events)})
    assert r.status_code == 200 and not r.json()["rejected"], r.text
    return r.json()


def incident(client, inc="inc_01"):
    return client.get(f"/api/incidents/{inc}").json()


def score(client, inc="inc_01"):
    return incident(client, inc)["score"]


def bait(at, session="sess01", issuance="iss_notes_1", token="tok_portal_01", sensor="ssh-decoy-01",
         asset="ssh:/home/dg_demo/notes.txt", basis="session_output_log", **over):
    """Schema 1.1 bait_served: the result record that proves the token was shown (contract v1.1)."""
    e = raw(sensor, "bait_served", at=at, session=session, asset_id=asset, honeytoken_ids=[token],
            issuance_id=issuance, evidence_basis=basis, evidence_role="bait")
    e["schema_version"] = "1.1"
    e.update(over)
    return e


def strong_link(client):
    return next(l for l in client.get("/api/links").json()["items"] if l["kind"] == "strong_candidate")


def decide(client, link_id, decision, rationale="checked the evidence"):
    return client.post(f"/api/links/{link_id}/decision", json={"decision": decision, "rationale": rationale})


def cases(client, **match) -> list:
    items = client.get("/api/incidents").json()["items"]
    return [i for i in items if all(i[k] == v for k, v in match.items())]


def case_id(client, **match) -> str:
    found = cases(client, **match)
    assert len(found) == 1, found
    return found[0]["incident_id"]


def ssh_case(client):
    return case_id(client, case_kind="ssh_session", session_id="sess01")


def web_case(client):
    return case_id(client, case_kind="web_activity")


def cred_case(client):
    return case_id(client, case_kind="credential_attempts")


def run_demo_until_token(client):
    # Hydra: one session per attempt, a different password each time
    send(client, *[raw(at=i, session=f"h{i}", username="dg_demo", password_sha256=f"{i:02d}" * 32)
                   for i in range(5)])
    assert score(client, cred_case(client)) == 25
    send(client, raw(etype="auth_success", at=20, session="sess01", username="dg_demo"),
         raw(etype="command_input", at=22, session="sess01", command="whoami"))
    assert score(client, ssh_case(client)) == 15
    send(client, raw(etype="command_input", at=25, session="sess01", command="ls -la"))
    assert score(client, ssh_case(client)) == 25
    send(client, raw(etype="command_input", at=30, session="sess01", command="cat notes.txt"),
         bait(at=30))  # the sensor's own record that the bait was shown, not the command
    send(client, webreq(70, "/login", "username=svc_portal&password=<redacted>", method="POST",
                        honeytoken_id="tok_portal_01", username="svc_portal"))
    assert score(client, web_case(client)) == 0  # R09 waits for confirmation
    assert score(client, cred_case(client)) == 25 and score(client, ssh_case(client)) == 25


# ---- task 4: the demo path order, as session cases plus one investigation ----
def test_demo_path_cases_then_investigation(client):
    run_demo_until_token(client)
    web = incident(client, web_case(client))
    r09 = next(f for f in web["findings"] if f["rule_id"] == "R09")
    assert r09["pending_confirmation"] is True and r09["points"] == 0

    send(client, webreq(80, "/search", "q=x%27+UNION+SELECT+username%2Cpassword+FROM+users--"))
    assert score(client, web_case(client)) == 15
    assert cases(client, case_kind="investigation") == []  # nothing joins cases before the analyst does

    assert decide(client, strong_link(client)["link_id"], "confirm").status_code == 200
    inv = incident(client, case_id(client, case_kind="investigation"))
    assert inv["status"] == "open" and inv["grouping_basis"] == "analyst_confirmed_link"
    assert sorted(inv["children"]) == sorted([ssh_case(client), web_case(client)])
    # R02 15 + R03 10 + R09 15 + R07 15 + R05 15; the credential case is not part of it
    assert inv["score"] == 70 and inv["severity"] == "high"
    assert {"R05", "R09"} <= {r["rule_id"] for r in inv["score_breakdown"] if r["counted"]}
    assert score(client, web_case(client)) == 30 and score(client, ssh_case(client)) == 25
    assert all(incident(client, c)["parent_id"] == inv["incident_id"] for c in inv["children"])

    send(client, webreq(90, "/download", "file=customer_data.csv", status_code=200),
         raw("web-decoy-01", "synthetic_file_access", at=90, session=None,
             asset_id="customer_data.csv", outcome="served"))
    inv = incident(client, inv["incident_id"])
    assert inv["score"] == 100 and inv["severity"] == "critical"
    # every finding has exactly one explaining row
    assert sorted(r["finding_id"] for r in inv["score_breakdown"]) == sorted(f["finding_id"] for f in inv["findings"])
    assert sum(r["points"] for r in inv["score_breakdown"]) == 100
    # children keep their own scores; neither becomes critical because of the other (review T01)
    children = [incident(client, c) for c in inv["children"]]
    assert sorted(c["score"] for c in children) == [25, 60]
    assert all(c["severity"] != "critical" for c in children)


def test_reject_after_confirm_dissolves_investigation_and_keeps_evidence(client):
    run_demo_until_token(client)
    before = len(client.get("/api/events?limit=1000").json()["items"])
    link = strong_link(client)["link_id"]
    decide(client, link, "confirm")
    inv_id = case_id(client, case_kind="investigation")
    assert score(client, inv_id) == 55 and score(client, web_case(client)) == 15
    rejected = decide(client, link, "reject", "wrong call, different actor").json()
    assert rejected["status"] == "rejected" and rejected["rationale"] == "wrong call, different actor"
    inv = incident(client, inv_id)
    assert inv["status"] == "dissolved" and inv["score"] == 0 and inv["findings"] == []
    web = incident(client, web_case(client))
    assert web["score"] == 0 and web["parent_id"] is None
    assert next(f for f in web["findings"] if f["rule_id"] == "R09")["pending_confirmation"] is True
    assert incident(client, ssh_case(client))["parent_id"] is None
    assert len(client.get("/api/events?limit=1000").json()["items"]) == before  # nothing deleted
    # confirming again re-opens the same investigation
    decide(client, link, "confirm", "second look, same actor")
    assert incident(client, inv_id)["status"] == "open" and score(client, inv_id) == 55


def test_confirming_plain_candidate_adds_r05_only(client):
    send(client, raw(etype="auth_success", at=0, username="u"), webreq(100, "/login"))
    link = client.get("/api/links").json()["items"][0]
    assert link["kind"] == "candidate" and link["status"] == "open"
    assert link["from_incident_id"] != link["to_incident_id"]
    decide(client, link["link_id"], "confirm")
    rows = incident(client, case_id(client, case_kind="investigation"))["score_breakdown"]
    assert [(r["rule_id"], r["points"]) for r in rows if r["counted"]] == [("R05", 15)]
    assert score(client, link["from_incident_id"]) == 0 and score(client, link["to_incident_id"]) == 0


def test_each_rule_counts_once(client):
    send(client, webreq(0, "/search", "q=' OR '1'='1"), webreq(5, "/search", "q=<script>alert(1)</script>"))
    rows = incident(client)["score_breakdown"]
    assert [r["counted"] for r in rows] == [True, False]
    assert rows[1]["reason"] == "R07 already counted for this incident" and score(client) == 15


def test_blocked_request_adds_no_points(client):
    send(client, webreq(0, "/search", "q=' OR '1'='1", etype="blocked_request",
                        status_code=403, block_action_id="act_1"))
    assert score(client) == 0 and incident(client)["findings"] == []


def test_duplicates_change_nothing(client):
    evs = [raw(at=i, username="dg_demo") for i in range(5)]
    send(client, *evs)
    before = incident(client)
    assert send(client, *evs)["duplicates"] == 5
    assert incident(client) == before


@pytest.mark.parametrize("value,expected", [(0, "low"), (24, "low"), (25, "medium"),
                                            (49, "medium"), (50, "high"), (79, "high"), (80, "critical")])
def test_severity_thresholds(value, expected):
    assert severity_for(value, CFG) == expected


# ---- task 5: links ----
def test_candidate_needs_both_sensors_within_300s(client):
    send(client, raw(etype="auth_success", at=0, username="u"), webreq(301, "/login"))
    assert client.get("/api/links").json()["items"] == []
    send(client, webreq(300, "/"))
    items = client.get("/api/links").json()["items"]
    assert len(items) == 1 and items[0]["basis"] == "same src_ip within 5 min"


def test_candidate_never_links_sessions_that_only_failed(client):
    """Hydra's one-attempt sessions hold no activity to compare, so they are not linked."""
    send(client, *[raw(at=i, session=f"h{i}", username="u") for i in range(5)], webreq(10, "/login"))
    assert client.get("/api/links").json()["items"] == []


def test_strong_link_from_planted_sensor(client):
    run_demo_until_token(client)
    link = strong_link(client)
    assert link["from_sensor"] == "ssh-decoy-01" and link["to_sensor"] == "web-decoy-01"
    assert link["basis"] == "honeytoken tok_portal_01 served by ssh:/home/dg_demo/notes.txt (session output log)"
    assert link["status"] == "open" and link["attribution"] == "unique" and link["candidate_issuance_ids"] == []
    served = [e for e in client.get("/api/events").json()["items"] if e["event_type"] == "bait_served"][0]
    assert link["from_event_id"] == served["event_id"]  # the bait record, never the shell command


def test_token_on_planting_sensor_is_not_r09(client):
    # tok_backup_01 is planted on the web decoy; presenting it there is not reuse (PRD S17)
    send(client, webreq(0, "/login", honeytoken_id="tok_backup_01"))
    assert incident(client)["findings"] == []
    assert all(l["kind"] != "strong_candidate" for l in client.get("/api/links").json()["items"])


def test_decision_validation(client):
    run_demo_until_token(client)
    lid = strong_link(client)["link_id"]
    short = decide(client, lid, "confirm", "ok")
    assert short.status_code == 400 and short.json()["error"]["code"] == "bad_request"
    assert decide(client, lid, "maybe").status_code == 400
    assert decide(client, lid, "confirm", "    ok    ").status_code == 400  # spaces do not count
    missing = decide(client, "lnk_nope", "confirm")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"


def test_websocket_gets_link_and_decision_updates(client):
    with client.websocket_connect("/ws/events") as ws:
        send(client, raw(etype="auth_success", at=0, username="u"), webreq(10, "/login"))
        types = [ws.receive_json()["type"] for _ in range(5)]
        assert types == ["event", "event", "link", "incident", "incident"]  # the SSH case and the web case
        lid = client.get("/api/links").json()["items"][0]["link_id"]
        decide(client, lid, "confirm")
        msg = ws.receive_json()
        assert msg["type"] == "link" and msg["data"]["status"] == "confirmed"
        r05 = ws.receive_json()
        assert r05["data"]["rule_id"] == "R05" and r05["data"]["incident_id"].startswith("inv_")


# ---- task 6: reads ----
def test_incident_list_newest_first_and_detail_shape(client):
    run_demo_until_token(client)
    send(client, raw(at=200, username="u", src_ip="192.168.77.11"))
    items = client.get("/api/incidents").json()["items"]
    assert items[0]["src_ip"] == "192.168.77.11"  # newest activity first
    assert [i["last_seen"] for i in items] == sorted((i["last_seen"] for i in items), reverse=True)
    v11 = {"case_kind", "grouping_basis", "sensor_id", "session_id", "capture_mode", "parent_id",
           "children", "status", "quiet"}
    assert all(v11 <= set(i) for i in items)
    quiet = [i for i in items if i["quiet"]]
    assert len(quiet) == 6 and all(i["case_kind"] == "ssh_session" for i in quiet)  # 5 Hydra + one from .11
    shown = client.get("/api/incidents?include_quiet=false").json()["items"]
    assert len(shown) == len(items) - 6 and not any(i["quiet"] for i in shown)
    inc = incident(client, ssh_case(client))
    assert {"findings", "score_breakdown", "links", "sessions", "summary", "active_block"} <= set(inc)
    assert inc["active_block"] is None and inc["summary"]["source"] == "rules"
    # Whichever summariser runs (M4's analyst/summarise.py or the fallback), it cites real evidence.
    event_ids = {e["event_id"] for e in client.get("/api/events?limit=1000").json()["items"]}
    assert inc["summary"]["text"] and set(inc["summary"]["cited_event_ids"]) <= event_ids
    assert inc["summary"]["cited_event_ids"] and inc["summary"]["stale"] is False
    assert [(s["session_id"], s["commands"], s["sensor_id"]) for s in inc["sessions"]] == [
        ("sess01", 3, "ssh-decoy-01")]
    assert client.get("/api/incidents/inc_99").status_code == 404


def test_transcript(client):
    run_demo_until_token(client)
    sess = ssh_case(client)
    t = client.get(f"/api/incidents/{sess}/transcript").json()
    assert t["session_id"] == "sess01"
    assert [(l["kind"], l["text"]) for l in t["lines"]] == [
        ("login_ok", "login accepted for user 'dg_demo'"),
        ("command", "whoami"), ("command", "ls -la"), ("command", "cat notes.txt")]
    h0 = case_id(client, case_kind="ssh_session", session_id="h0")
    s1 = client.get(f"/api/incidents/{h0}/transcript").json()
    assert {l["kind"] for l in s1["lines"]} == {"login_failed"} and "00" * 32 not in str(s1)
    # another case's session is not this case's transcript
    assert client.get(f"/api/incidents/{sess}/transcript?session_id=h0").status_code == 404


def test_stats_overview(client):
    run_demo_until_token(client)
    send(client, raw(at=0, username="x", src_ip="192.168.77.12"))
    s = client.get("/api/stats/overview").json()
    # 5 Hydra sessions, credential, sess01, web, the .12 session; only sess01 and credential reach 25
    assert s["raw_events"] == 12 and s["incidents"] == 9 and s["low_priority_incidents"] == 7  # incl. bait record
    assert s["findings_by_rule"] == {"R01": 1, "R02": 1, "R03": 1, "R09": 1}
    assert isinstance(s["first_alert_seconds"], float) and s["first_alert_seconds"] >= 0


def test_stats_empty(client):
    assert client.get("/api/stats/overview").json() == {
        "raw_events": 0, "incidents": 0, "low_priority_incidents": 0,
        "findings_by_rule": {}, "first_alert_seconds": None}


def test_export_has_no_password_hashes(client):
    run_demo_until_token(client)
    h0 = case_id(client, case_kind="ssh_session", session_id="h0")
    r = client.get(f"/api/incidents/{h0}/export")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == f'attachment; filename="{h0}.json"'
    body = r.json()
    assert len(body["events"]) == 1 and "Simulated lab data" in body["note"]
    assert "password_sha256" not in r.text and "00" * 32 not in r.text
    assert len(client.get(f"/api/incidents/{ssh_case(client)}/export").json()["events"]) == 5  # + bait_served


# ---- task 7: response hooks ----
def test_response_placeholder_when_m2_module_absent(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import backend.integrations as integrations
    from backend.main import create_app

    real = integrations._optional_import
    monkeypatch.setattr(integrations, "_optional_import",
                        lambda name: None if name == "response.router" else real(name))
    with TestClient(create_app(str(tmp_path / "t.db"))) as c:
        r = c.post("/api/response/preview", json={"incident_id": "inc_01", "ttl_seconds": 120})
    assert r.status_code == 503 and r.json()["error"]["code"] == "response_unavailable"


def test_response_router_mounted_now_that_m2_landed(client, tmp_path):
    from response import router as response_router

    response_router.configure(state_dir=str(tmp_path / "state"), env_file=str(tmp_path / "absent.env"),
                              incident_lookup=lambda incident_id: None)
    r = client.get("/api/response/actions")
    assert r.status_code == 200 and r.json() == {"items": []}
    r = client.post("/api/response/preview", json={"incident_id": "inc_404", "ttl_seconds": 120})
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_on_event_hook_called_once_per_new_event(client):
    seen = []
    client.app.state.hooks._on_event = lambda ev: seen.append(ev["event_id"])
    evs = [raw(at=0, username="u"), raw(at=1, username="u")]
    send(client, *evs)
    send(client, *evs)  # duplicates: no second call
    assert len(seen) == 2


def test_on_event_failure_never_breaks_ingest(client):
    def boom(ev):
        raise RuntimeError("bug in response module")
    client.app.state.hooks._on_event = boom
    assert send(client, raw(at=0, username="u"))["accepted"] == 1


def test_analyst_summary_used_when_present_and_fallback_on_error(client):
    send(client, *[raw(at=i, username="u") for i in range(5)])
    cred = cred_case(client)
    hooks = client.app.state.hooks
    hooks._summarise = lambda inc: {"source": "rules", "text": "custom", "cited_event_ids": []}
    assert incident(client, cred)["summary"]["text"] == "custom"
    hooks._summarise = lambda inc: 1 / 0
    assert incident(client, cred)["summary"]["text"].startswith("Repeated SSH password guessing")
    hooks._summarise = None  # M4 module absent
    assert incident(client, cred)["summary"]["text"].startswith("Repeated SSH password guessing")


def test_websocket_seq_rule_from_api_md(client):
    """contracts/API.md: seq = newest event seq at send time; finding/link/incident reuse it,
    and a decision sends messages with no new event."""
    with client.websocket_connect("/ws/events") as ws:
        send(client, raw(etype="auth_success", at=0, username="u"), webreq(10, "/login"))
        msgs = [ws.receive_json() for _ in range(5)]
        assert [m["type"] for m in msgs] == ["event", "event", "link", "incident", "incident"]
        last_event_seq = msgs[1]["seq"]
        assert msgs[0]["seq"] < last_event_seq
        assert all(m["seq"] == last_event_seq for m in msgs[2:])  # same seq: never drop these by seq
        decide(client, msgs[2]["data"]["link_id"], "confirm")
        after = [ws.receive_json() for _ in range(5)]  # link, R05, both children, then the investigation
        assert [m["type"] for m in after] == ["link", "finding", "incident", "incident", "incident"]
        assert all(m["seq"] == last_event_seq for m in after)  # no new event, same seq
        assert after[-1]["data"]["case_kind"] == "investigation" and after[-1]["data"]["score"] == 15
