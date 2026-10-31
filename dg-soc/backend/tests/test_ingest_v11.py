"""PR 2 (m3/ingest-v1.1): schema 1.1 ingest, one capture mode per run, replay dedup
namespace, derived observation kinds, /api/runs, M4 input features in R07, DB migration."""
import copy
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.db import Database
from backend.main import create_app

ROOT = Path(__file__).resolve().parents[2]
V11 = json.loads((ROOT / "contracts/examples/events_v1_1.json").read_text(encoding="utf-8"))


def ex(record_id: str) -> dict:
    return copy.deepcopy(next(e for e in V11["events"] if e["source_record_id"] == record_id))


def post(client, *events):
    r = client.post("/api/ingest/events", json={"events": list(events)})
    assert r.status_code == 200, r.text
    return r.json()


def events(client, **params):
    return client.get("/api/events", params={"limit": 1000, **params}).json()["items"]


# ---- version-gated validation ----
@pytest.mark.parametrize("case", V11["invalid"], ids=lambda c: c["_why"])
def test_backend_rejects_what_the_schema_rejects(client, case):
    r = post(client, case["event"])
    assert r["accepted"] == 0 and r["rejected"][0]["index"] == 0


def test_v10_event_keeps_v10_rules(client):
    """The compatibility counterexample: free-form 1.0 attributes still pass."""
    ev = ex("a-web-req-5")
    ev["schema_version"] = "1.0"
    ev["attributes"] = {"asset_id": "customer_data.csv", "outcome": "served",
                        "fixture_version": 1, "digest_scope": "full_response", "input_features": "free text"}
    assert post(client, ev)["accepted"] == 1
    stored = events(client)[0]
    assert stored["schema_version"] == "1.0" and stored["attributes"]["fixture_version"] == 1


def test_v10_cannot_send_v11_only_things(client):
    bait = ex("a-web-req-2-bait")
    bait["schema_version"] = "1.0"
    del bait["attributes"]["outcome"]   # a 1.1-only value; drop it so the bait_served check is what fails
    replay = ex("replay-a-ssh-h1-fail")
    replay["schema_version"] = "1.0"
    del replay["attributes"]["outcome"]
    r = post(client, bait, replay)
    assert [x["index"] for x in r["rejected"]] == [0, 1]
    assert "bait_served" in r["rejected"][0]["reason"] and "origin_record_id" in r["rejected"][1]["reason"]


def test_command_cannot_claim_bait_was_served(client):
    ev = ex("a-ssh-s1-bait")
    ev["attributes"]["evidence_basis"] = "derived_from_command"
    assert post(client, ev)["rejected"]


def test_input_features_bounded(client):
    base = ex("a-web-post-search")
    too_many = copy.deepcopy(base)
    too_many["source_record_id"] = "feat-1"
    too_many["attributes"]["input_features"]["field_names"] = [f"f{i}" for i in range(33)]
    unknown = copy.deepcopy(base)
    unknown["source_record_id"] = "feat-2"
    unknown["attributes"]["input_features"]["indicators"] = ["sql_quote", "rm_rf_everything"]
    with_value = copy.deepcopy(base)
    with_value["source_record_id"] = "feat-3"
    with_value["attributes"]["processing"]["raw_body"] = "x' or 1=1"
    r = post(client, too_many, unknown, with_value)
    assert [x["index"] for x in r["rejected"]] == [0, 1, 2]


# ---- derived evidence fields ----
def test_observation_kind_and_role_on_reads(client):
    post(client, *V11["events"])
    by_id = {e["source_record_id"]: e for e in events(client)}
    assert (by_id["a-ssh-s1-cat"]["observation_kind"], by_id["a-ssh-s1-cat"]["evidence_role"]) == ("command_input", "request")
    assert (by_id["a-web-req-5"]["observation_kind"], by_id["a-web-req-5"]["evidence_role"]) == ("emulated_result", "result")
    assert by_id["a-web-req-2-bait"]["evidence_role"] == "bait"
    assert by_id["a-ssh-h2-fail"]["observation_kind"] == "network_input"           # derived, not sent
    assert by_id["a-ssh-h2-fail"]["schema_version"] == "1.1"
    assert by_id["replay-a-ssh-h1-fail"]["origin_record_id"] == "a-ssh-h1-fail"
    assert by_id["replay-a-ssh-h1-fail"]["ingest_namespace"] == "replay:replay-2026-11-01-a"
    assert by_id["a-ssh-h1-fail"]["ingest_namespace"] == "live"


def test_stored_attributes_are_what_was_sent(client):
    """Derived fields live next to the event; the producer's attributes are stored as sent."""
    ev = ex("a-ssh-h2-fail")
    post(client, ev)
    assert events(client)[0]["attributes"] == ev["attributes"]


# ---- one capture mode per run ----
def test_run_mode_fixed_by_first_event_both_directions(client):
    replay_first = ex("replay-a-ssh-h1-fail")
    live_into_replay_run = dict(ex("a-ssh-h2-fail"), lab_run_id="replay-2026-11-01-a")
    r = post(client, replay_first, live_into_replay_run)
    assert r["accepted"] == 1
    assert r["rejected"] == [{"index": 1, "reason": "lab_run_id: run replay-2026-11-01-a is replay; live events need their own run"}]


def test_mixed_batch_keeps_indexes(client):
    bad_ip = dict(ex("a-ssh-h3-fail"), src_ip="not-an-ip")
    live = ex("a-ssh-h1-fail")
    replay_same_run = dict(ex("a-ssh-h2-fail"), capture_mode="replay", source_record_id="r-x")
    ok = ex("a-ssh-h4-fail")
    r = post(client, bad_ip, live, replay_same_run, ok)
    assert r["accepted"] == 2 and [x["index"] for x in r["rejected"]] == [0, 2]


def test_rejected_first_event_does_not_fix_the_mode(client):
    bad = dict(ex("a-ssh-h1-fail"), capture_mode="replay", src_ip="999.0.0.1")
    assert post(client, bad)["accepted"] == 0
    assert post(client, ex("a-ssh-h1-fail"))["accepted"] == 1
    assert [r["capture_mode"] for r in client.get("/api/runs").json()["items"]] == ["live"]


# ---- replay namespace ----
def test_replay_namespace_dedup(client):
    live = ex("a-ssh-h1-fail")
    replay_a = dict(live, capture_mode="replay", lab_run_id="replay-a", origin_record_id="a-ssh-h1-fail")
    replay_b = dict(replay_a, lab_run_id="replay-b")
    assert post(client, live, replay_a, replay_b)["accepted"] == 3       # same source id, three namespaces
    assert post(client, replay_a)["duplicates"] == 1                      # same replay run: deduplicated
    assert post(client, live)["duplicates"] == 1
    assert len(events(client)) == 3


def test_replay_never_joins_a_live_incident(client):
    live = ex("a-ssh-h1-fail")
    replay = dict(live, capture_mode="replay", lab_run_id="replay-a", source_record_id="r1")
    post(client, live, replay)
    incidents = {e["capture_mode"]: e["incident_id"] for e in events(client)}
    assert incidents["live"] != incidents["replay"]
    summaries = {i["incident_id"]: i for i in client.get("/api/incidents").json()["items"]}
    assert summaries[incidents["live"]]["capture_mode"] == "live"
    assert summaries[incidents["replay"]]["capture_mode"] == "replay"


def test_events_filter_by_run_and_mode(client):
    post(client, *V11["events"])
    replay = events(client, capture_mode="replay")
    assert replay and all(e["capture_mode"] == "replay" for e in replay)
    orphan_run = events(client, lab_run_id="run-2026-11-01-02")
    assert [e["source_record_id"] for e in orphan_run] == ["b-web-orphan"]


# ---- /api/runs ----
def test_runs_route_and_single_active_live_run(client):
    post(client, *V11["events"])
    runs = {r["lab_run_id"]: r for r in client.get("/api/runs").json()["items"]}
    assert runs["replay-2026-11-01-a"]["capture_mode"] == "replay" and not runs["replay-2026-11-01-a"]["active"]
    assert sum(r["active"] for r in runs.values()) == 1
    assert runs["run-2026-11-01-02"]["active"]                  # received the newest live event
    assert not runs["run-2026-11-01-01"]["active"]
    assert runs["run-2026-11-01-01"]["events"] == sum(1 for e in V11["events"] if e["lab_run_id"] == "run-2026-11-01-01")


def test_live_run_goes_inactive_after_15_minutes(client):
    post(client, ex("a-ssh-h1-fail"))
    old = (datetime.now(timezone.utc) - timedelta(minutes=16)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    db = client.app.state.db
    with db._write_lock:
        db._writer.execute("UPDATE runs SET last_ingested_at=?", (old,))
    assert client.get("/api/runs").json()["items"][0]["active"] is False


# ---- R07 consumes M4 body indicators ----
def test_r07_classifies_body_indicators(client):
    post(client, ex("a-web-post-search"))
    findings = client.app.state.db.list_findings(events(client)[0]["incident_id"])
    r07 = [f for f in findings if f["rule_id"] == "R07"]
    assert len(r07) == 1 and r07[0]["web_attack_class"] == ["sqli"] and r07[0]["rule_version"] == "R07@3"
    assert "request body" in r07[0]["label"]


@pytest.mark.parametrize("indicators", [["sql_quote"], ["null_byte", "encoded_payload"], ["sql_keyword", "sql_comment"]])
def test_r07_supporting_indicators_alone_do_not_fire(client, indicators):
    ev = ex("a-web-post-search")
    ev["attributes"]["input_features"]["indicators"] = indicators
    post(client, ev)
    assert all(f["rule_id"] != "R07" for f in client.app.state.db.list_findings(events(client)[0]["incident_id"]))


def test_r07_ignores_unvalidated_features_on_v10_events(client):
    ev = ex("a-web-post-search")
    ev["schema_version"] = "1.0"
    ev["attributes"]["input_features"] = {"indicators": ["sql_quote", "sql_keyword"]}
    del ev["attributes"]["processing"]
    post(client, ev)
    assert all(f["rule_id"] != "R07" for f in client.app.state.db.list_findings(events(client)[0]["incident_id"]))


# ---- DB migration v0 -> v1 ----
V0_SCHEMA = """
CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, src_ip TEXT NOT NULL, lab_run_id TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT 'low', first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, event_count INTEGER NOT NULL DEFAULT 0, UNIQUE (src_ip, lab_run_id));
CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    sensor_id TEXT NOT NULL, source_record_id TEXT NOT NULL, event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL, ingested_at TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER,
    session_id TEXT, lab_run_id TEXT NOT NULL, capture_mode TEXT NOT NULL, attributes TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id), UNIQUE (sensor_id, source_record_id));
CREATE INDEX idx_events_incident ON events(incident_id, seq);
CREATE TABLE findings (finding_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, rule_id TEXT NOT NULL,
    data TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE links (link_id TEXT PRIMARY KEY, from_event_id TEXT NOT NULL, to_event_id TEXT NOT NULL,
    from_sensor TEXT NOT NULL, to_sensor TEXT NOT NULL, kind TEXT NOT NULL, basis TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', decided_at TEXT, rationale TEXT, from_incident_id TEXT NOT NULL,
    to_incident_id TEXT NOT NULL, created_at TEXT NOT NULL);
"""


def make_v0_db(path: Path) -> list[tuple]:
    conn = sqlite3.connect(path)
    conn.executescript(V0_SCHEMA)
    conn.execute("INSERT INTO incidents VALUES ('inc_01','192.168.77.10','run-old',25,'medium','2026-10-31T10:00:00Z','2026-10-31T10:00:09Z',3)")
    rows = [
        (5, "evt_a", "ssh-decoy-01", "rec-1", "auth_failure", "2026-10-31T10:00:00Z", "2026-10-31T10:00:01.000Z",
         "192.168.77.10", 50001, "s1", "run-old", "live", '{"username": "dg_demo"}', "inc_01"),
        (6, "evt_b", "ssh-decoy-01", "rec-2", "command_input", "2026-10-31T10:00:05Z", "2026-10-31T10:00:06.000Z",
         "192.168.77.10", 50001, "s1", "run-old", "live", '{"command": "ls"}', "inc_01"),
        (9, "evt_c", "web-decoy-01", "rec-3", "blocked_request", "2026-10-31T10:00:09Z", "2026-10-31T10:00:10.000Z",
         "192.168.77.10", None, None, "run-old", "replay", '{"block_action_id": "act_1"}', "inc_01"),
    ]
    conn.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return rows


def test_migration_from_v10_database(tmp_path):
    path = tmp_path / "old.db"
    rows = make_v0_db(path)
    db = Database(str(path))
    try:
        assert db._writer.execute("PRAGMA user_version").fetchone()[0] == 1
        assert os.path.exists(f"{path}.v0.bak")
        migrated = db._writer.execute(
            "SELECT seq, event_id, sensor_id, source_record_id, event_type, occurred_at, ingested_at, src_ip, "
            "src_port, session_id, lab_run_id, capture_mode, attributes, incident_id FROM events ORDER BY seq").fetchall()
        assert [tuple(r) for r in migrated] == rows                       # every row copied unchanged, seq included
        kinds = [r[0] for r in db._writer.execute("SELECT observation_kind FROM events ORDER BY seq")]
        assert kinds == ["network_input", "command_input", "policy_result"]
        run = dict(db._writer.execute("SELECT * FROM runs").fetchone())
        assert run["capture_mode"] == "live" and run["legacy_mixed"] == 1 and run["events"] == 3
        backup = sqlite3.connect(f"{path}.v0.bak")
        assert backup.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3   # rollback copy is complete
        backup.close()
    finally:
        db.close()


def test_migrated_database_keeps_working(tmp_path):
    path = tmp_path / "old.db"
    make_v0_db(path)
    with TestClient(create_app(str(path))) as c:
        dup = {"schema_version": "1.0", "source_record_id": "rec-1", "sensor_id": "ssh-decoy-01",
               "event_type": "auth_failure", "occurred_at": "2026-10-31T10:00:00Z", "src_ip": "192.168.77.10",
               "session_id": "s1", "lab_run_id": "run-old", "capture_mode": "live", "attributes": {"username": "dg_demo"}}
        assert post(c, dup)["duplicates"] == 1                            # old dedup keys still hold
        new = dict(dup, source_record_id="rec-4", occurred_at="2026-10-31T10:00:11Z")
        assert post(c, new)["accepted"] == 1
        seqs = [e["seq"] for e in events(c)]
        assert seqs == [5, 6, 9, 10]                                       # numbering continues after the max
        assert next(r for r in c.get("/api/runs").json()["items"])["legacy_mixed"] is True


def test_migration_runs_once(tmp_path):
    path = tmp_path / "old.db"
    make_v0_db(path)
    Database(str(path)).close()
    os.remove(f"{path}.v0.bak")
    Database(str(path)).close()                                          # already v1: no new backup, no rebuild
    assert not os.path.exists(f"{path}.v0.bak")
