"""PR 3 (m3/case-model): session cases, credential cases, investigations, source profiles
(contracts/API.md, Session cases versus source profiles)."""
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 11, 1, 4, 30, 0, tzinfo=timezone.utc)
_n = 0


def ev(sensor="ssh-decoy-01", etype="auth_success", at=0, session="s1", src_ip="192.168.77.10",
       run="run-c", mode="replay", **attrs):
    global _n
    _n += 1
    return {"schema_version": "1.0", "source_record_id": f"c-{_n}", "sensor_id": sensor, "event_type": etype,
            "occurred_at": (T0 + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%SZ"), "src_ip": src_ip,
            "session_id": session, "lab_run_id": run, "capture_mode": mode, "attributes": attrs}


def web(at, path="/", session=None, **kw):
    return ev("web-decoy-01", "http_request", at=at, session=session, method="GET", path=path, **kw)


def send(client, *events):
    r = client.post("/api/ingest/events", json={"events": list(events)})
    assert r.status_code == 200 and not r.json()["rejected"], r.text
    return r.json()


def cases(client, **match):
    return [i for i in client.get("/api/incidents").json()["items"] if all(i[k] == v for k, v in match.items())]


def decide(client, link_id, decision):
    r = client.post(f"/api/links/{link_id}/decision", json={"decision": decision, "rationale": "checked evidence"})
    assert r.status_code == 200
    return r.json()


# ---- grouping ----
def test_web_activity_splits_after_five_quiet_minutes(client):
    send(client, web(0), web(240), web(240 + 301), web(240 + 301 + 299))
    found = cases(client, case_kind="web_activity")
    assert sorted(c["event_count"] for c in found) == [2, 2]
    assert all(c["grouping_basis"] == "inactivity_5min" and c["session_id"] is None for c in found)


def test_web_session_groups_by_derived_session_id(client):
    send(client, web(0, session="wsr_a"), web(1000, session="wsr_a"), web(5, session="wsr_b"))
    found = {c["session_id"]: c for c in cases(client, case_kind="web_session")}
    assert found["wsr_a"]["event_count"] == 2 and found["wsr_b"]["event_count"] == 1  # no time split in a session
    assert found["wsr_a"]["grouping_basis"] == "sensor_session"


def test_ssh_event_without_session_gets_unsessioned_case(client):
    send(client, ev(etype="connection_open", session=None), ev(etype="connection_open", at=10, session=None))
    [c] = cases(client)
    assert c["case_kind"] == "ssh_unsessioned" and c["event_count"] == 2


def test_runs_and_modes_never_share_a_case(client):
    send(client, ev(at=0), ev(at=1, run="run-d"), ev(at=2, run="run-live", mode="live"))
    assert len({c["incident_id"] for c in cases(client)}) == 3


def test_quiet_case_turns_visible_once_it_has_a_finding(client):
    send(client, ev(at=0))
    assert cases(client)[0]["quiet"] is True
    assert client.get("/api/incidents?include_quiet=false").json()["items"] == []
    send(client, ev(etype="command_input", at=1, command="whoami"))
    assert cases(client)[0]["quiet"] is False


# ---- credential cases ----
def test_credential_case_per_user_never_takes_events(client):
    send(client, *[ev(etype="auth_failure", at=i, session=f"h{i}", username="root") for i in range(5)],
         *[ev(etype="auth_failure", at=i, session=f"g{i}", username="admin") for i in range(5)])
    cred = {c["incident_id"]: c for c in cases(client, case_kind="credential_attempts")}
    assert len(cred) == 2 and all(c["event_count"] == 0 and c["score"] == 25 for c in cred.values())
    owners = {e["incident_id"] for e in client.get("/api/events?limit=1000").json()["items"]}
    assert not owners & set(cred)


def test_four_failures_make_no_credential_case(client):
    send(client, *[ev(etype="auth_failure", at=i, session=f"h{i}", username="root") for i in range(4)])
    assert cases(client, case_kind="credential_attempts") == []


# ---- investigations ----
def two_sessions_and_web(client):
    send(client, ev(at=0, session="A", username="u"), ev(at=5, session="B", username="u"), web(30, "/login"))
    links = client.get("/api/links").json()["items"]
    assert len(links) == 2 and all(l["kind"] == "candidate" for l in links)
    return links


def test_second_confirmed_link_extends_the_same_investigation(client):
    l1, l2 = two_sessions_and_web(client)
    decide(client, l1["link_id"], "confirm")
    decide(client, l2["link_id"], "confirm")
    [inv] = cases(client, case_kind="investigation")
    assert inv["status"] == "open" and len(inv["children"]) == 3
    decide(client, l1["link_id"], "reject")
    [inv] = cases(client, case_kind="investigation")
    # still stands on the other link: session B and the web case; session A leaves
    assert inv["status"] == "open" and sorted(inv["children"]) == sorted([l2["from_incident_id"], l2["to_incident_id"]])
    session_a = next(c for c in cases(client) if c["incident_id"] == l1["from_incident_id"])
    assert session_a["session_id"] == "A" and session_a["parent_id"] is None
    decide(client, l2["link_id"], "reject")
    [inv] = cases(client, case_kind="investigation")
    assert inv["status"] == "dissolved" and inv["score"] == 0
    assert all(c["parent_id"] is None for c in cases(client) if c["case_kind"] != "investigation")


def test_investigation_detail_and_events_come_from_children(client):
    l1, _ = two_sessions_and_web(client)
    decide(client, l1["link_id"], "confirm")
    [inv] = cases(client, case_kind="investigation")
    detail = client.get(f"/api/incidents/{inv['incident_id']}").json()
    assert {l["link_id"] for l in detail["links"]} == {l1["link_id"]}
    owned = client.get(f"/api/events?incident_id={inv['incident_id']}").json()["items"]
    assert {e["incident_id"] for e in owned} == set(inv["children"])
    assert detail["event_count"] == len(owned)


def test_links_name_the_cases_they_join(client):
    for l in two_sessions_and_web(client):
        assert l["from_incident_id"] != l["to_incident_id"]


# ---- source profiles ----
def test_profile_is_a_view_without_score(client):
    send(client, *[ev(etype="auth_failure", at=i, session=f"h{i}", username=f"user{i}", client_version="SSH-2.0-x")
                   for i in range(5)], web(10, "/login", user_agent="curl/8"))
    [p] = client.get("/api/profiles?lab_run_id=run-c").json()["items"]
    assert "score" not in p and "severity" not in p and "NAT" in p["note"]
    assert p["sensors"]["ssh-decoy-01"] == {"cases": 5, "events": 5}
    assert p["attempted_usernames"] == [f"user{i}" for i in range(5)]
    assert {"sensor_id": "web-decoy-01", "user_agent": "curl/8"} in p["client_claims"]
    assert len(p["case_ids"]) == 6  # five sessions and the web activity; no credential case for 5 users
    one = client.get("/api/profiles/192.168.77.10?lab_run_id=run-c").json()
    assert one == p


def test_profile_errors(client):
    assert client.get("/api/profiles/192.168.77.10?lab_run_id=run-none").status_code == 404
    r = client.get("/api/profiles/192.168.77.10")
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"
    assert client.get("/api/profiles").json() == {"items": []}
