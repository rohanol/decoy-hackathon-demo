"""PR 5 (m3/eligibility-health): response eligibility, collector heartbeat, sensor_health
(contracts/API.md, Response eligibility and verification; Health)."""
from datetime import datetime, timedelta, timezone

import pytest

_n = 0
KEYS = {"eligible", "target_ip", "lab_run_id", "capture_mode", "reasons", "last_web_observation_at", "checked_at"}


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(sensor="web-decoy-01", etype="http_request", ago=0, session=None, src_ip="192.168.77.10",
       run="run-live", mode="live", **attrs):
    global _n
    _n += 1
    attrs = attrs or ({"method": "GET", "path": "/login"} if sensor == "web-decoy-01" else {})
    return {"schema_version": "1.0", "source_record_id": f"h-{_n}", "sensor_id": sensor, "event_type": etype,
            "occurred_at": stamp(datetime.now(timezone.utc) - timedelta(seconds=ago)), "src_ip": src_ip,
            "session_id": session, "lab_run_id": run, "capture_mode": mode, "attributes": attrs}


def send(client, *events):
    r = client.post("/api/ingest/events", json={"events": list(events)})
    assert r.status_code == 200 and not r.json()["rejected"], r.text
    return r.json()


def case_of(client, **match):
    return next(i["incident_id"] for i in client.get("/api/incidents").json()["items"]
                if all(i[k] == v for k, v in match.items()))


def eligibility(client, incident_id):
    r = client.get(f"/api/incidents/{incident_id}/response-eligibility")
    assert r.status_code == 200, r.text
    body = r.json()
    assert KEYS <= set(body)  # M2 fails closed on a missing key: every key is always present
    return body


def codes(body):
    return [r["code"] for r in body["reasons"]]


# ---- eligibility ----
def test_fresh_live_web_case_is_eligible(client):
    send(client, ev(ago=30))
    e = eligibility(client, case_of(client, case_kind="web_activity"))
    assert e["eligible"] is True and e["reasons"] == [] and e["target_ip"] == "192.168.77.10"
    assert e["capture_mode"] == "live" and e["lab_run_id"] == "run-live"
    checked = datetime.fromisoformat(e["checked_at"].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - checked).total_seconds()) < 5  # M2 refuses if older than 30 s


def test_replay_case_is_never_eligible(client):
    send(client, ev(ago=30, run="replay-x", mode="replay"))
    e = eligibility(client, case_of(client, capture_mode="replay"))
    assert e["eligible"] is False and codes(e)[:2] == ["replay_data", "no_live_run"]


def test_case_in_an_older_live_run_is_not_eligible(client):
    send(client, ev(ago=30, run="run-old"))
    send(client, ev(ago=20, run="run-new", src_ip="192.168.77.11"))
    e = eligibility(client, case_of(client, lab_run_id="run-old"))
    assert codes(e) == ["no_live_run"]


def test_stale_web_observation_is_not_eligible(client):
    send(client, ev(ago=11 * 60))
    e = eligibility(client, case_of(client, case_kind="web_activity"))
    assert codes(e) == ["stale_observation"] and e["last_web_observation_at"] is not None


def test_ssh_only_address_has_no_web_observation(client):
    send(client, ev("ssh-decoy-01", "auth_success", ago=5, session="s1", username="u"))
    e = eligibility(client, case_of(client, case_kind="ssh_session"))
    assert codes(e) == ["stale_observation"] and e["last_web_observation_at"] is None


def test_sensor_clock_ahead_cannot_make_old_traffic_fresh(client):
    """The observation time is capped at the backend receive time."""
    send(client, ev(ago=-3600))  # sensor clock one hour ahead
    e = eligibility(client, case_of(client, case_kind="web_activity"))
    observed = datetime.fromisoformat(e["last_web_observation_at"].replace("Z", "+00:00"))
    assert observed <= datetime.now(timezone.utc) + timedelta(seconds=1)


def test_dissolved_investigation_is_not_eligible(client):
    send(client, ev("ssh-decoy-01", "auth_success", ago=40, session="s1", username="u"), ev(ago=30))
    link = client.get("/api/links").json()["items"][0]["link_id"]
    for d in ("confirm", "reject"):
        client.post(f"/api/links/{link}/decision", json={"decision": d, "rationale": "checked evidence"})
    e = eligibility(client, case_of(client, case_kind="investigation"))
    assert "case_dissolved" in codes(e) and e["eligible"] is False


def test_unknown_case_is_404_with_error_shape(client):
    r = client.get("/api/incidents/inc_404/response-eligibility")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


# ---- heartbeat ----
def adapter_payload(**over):
    """Exactly what M2's adapter builds (sensors/adapter.py `_heartbeat_payloads`, PR #8)."""
    now = datetime.now(timezone.utc).isoformat()
    body = {"collector_id": "adapter-laptop-b", "sensor_id": "ssh-decoy-01", "sent_at": now,
            "sensor_process": "up", "last_read_at": now, "last_ingest_ok_at": now, "backlog_lines": 0,
            "oldest_backlog_age_s": 0, "errors_total": 0, "rejected_total": 1, "quarantined_total": 1}
    body.update(over)
    return body


def test_adapter_heartbeat_accepted_and_translated(client):
    once = ev("ssh-decoy-01", "auth_failure", ago=5, session="s1", username="u")
    send(client, once)
    assert send(client, once)["duplicates"] == 1
    r = client.post("/api/ingest/heartbeat", json=adapter_payload(backlog_lines=3, errors_total=2))
    assert r.status_code == 200 and r.json() == {"ok": True}  # the adapter checks exactly this
    h = client.get("/api/health").json()["sensor_health"]["ssh-decoy-01"]
    assert (h["service"], h["collection"], h["activity"]) == ("up", "ok", "recent")
    assert h["process_state"] == "running" and h["collector_id"] == "adapter-laptop-b"
    assert h["backlog_records"] == 3 and h["error_count"] == 2
    assert h["ingest"] == {"accepted": 1, "duplicate": 1, "rejected": 1, "quarantined": 1, "retry": None}
    assert abs(h["clock_skew_s"]) < 5


def test_sensor_without_heartbeat_reports_never(client):
    send(client, ev(ago=5))
    h = client.get("/api/health").json()["sensor_health"]["web-decoy-01"]
    assert (h["service"], h["collection"], h["activity"]) == ("unknown", "never", "recent")
    assert h["process_state"] is None and h["ingest"] is None and h["last_event_at"] is not None


def test_stopped_process_and_stale_heartbeat(client):
    client.post("/api/ingest/heartbeat", json=adapter_payload(sensor_process="down"))
    assert client.get("/api/health").json()["sensor_health"]["ssh-decoy-01"]["service"] == "down"
    db = client.app.state.db
    db._write(lambda c: c.execute("UPDATE collector_heartbeats SET received_at='2026-01-01T00:00:00.000Z'"))
    h = client.get("/api/health").json()["sensor_health"]["ssh-decoy-01"]
    assert (h["service"], h["collection"], h["activity"]) == ("unknown", "stale", "none")


def test_quiet_sensor_is_not_a_broken_one(client):
    client.post("/api/ingest/heartbeat", json=adapter_payload())
    send(client, ev("ssh-decoy-01", "auth_failure", ago=5, session="s1", username="u"))
    client.app.state.db._write(lambda c: c.execute("UPDATE events SET ingested_at='2026-01-01T00:00:00.000Z'"))
    h = client.get("/api/health").json()["sensor_health"]["ssh-decoy-01"]
    assert (h["service"], h["collection"], h["activity"]) == ("up", "ok", "quiet")


def test_skew_is_sensor_minus_backend(client):
    ahead = (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat()
    client.post("/api/ingest/heartbeat", json=adapter_payload(sent_at=ahead))
    assert 290 < client.get("/api/health").json()["sensor_health"]["ssh-decoy-01"]["clock_skew_s"] < 310


def test_heartbeats_never_become_events(client):
    client.post("/api/ingest/heartbeat", json=adapter_payload())
    assert client.get("/api/events").json()["items"] == [] and client.get("/api/incidents").json()["items"] == []


@pytest.mark.parametrize("bad", [
    {"surprise": 1},
    {"sensor_id": "api-decoy-01"},
    {"sensor_process": "maybe"},
    {"errors_total": -1},
    {"backlog_lines": 10 ** 10},
    {"collector_id": ""},
    {"sent_at": "2026-11-01T04:31:40"},  # no offset
])
def test_bad_heartbeat_rejected_with_error_shape(client, bad):
    r = client.post("/api/ingest/heartbeat", json=adapter_payload(**bad))
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"


def test_heartbeat_needs_json(client):
    r = client.post("/api/ingest/heartbeat", content=b"x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415
