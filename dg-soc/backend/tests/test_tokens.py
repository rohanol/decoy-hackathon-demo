"""PR 4 (m3/token-mapping): causal token matching and corrected mappings
(contracts/API.md, Causal token matching; Corrected mappings)."""
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from backend.main import create_app

ROOT = Path(__file__).resolve().parents[2]
FINDING_V = Draft202012Validator(json.loads((ROOT / "contracts/finding.schema.json").read_text(encoding="utf-8")),
                                 format_checker=FormatChecker())
T0 = datetime(2026, 11, 1, 4, 30, 0, tzinfo=timezone.utc)
_n = 0


def ev(sensor="ssh-decoy-01", etype="auth_success", at=0, session="s1", src_ip="192.168.77.10",
       run="run-k", mode="live", version="1.1", **attrs):
    global _n
    _n += 1
    return {"schema_version": version, "source_record_id": f"k-{_n}", "sensor_id": sensor, "event_type": etype,
            "occurred_at": (T0 + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%SZ"), "src_ip": src_ip,
            "session_id": session, "lab_run_id": run, "capture_mode": mode, "attributes": attrs}


def portal_login(at, **kw):
    """tok_portal_01 (planted on SSH) presented on the web portal."""
    return ev("web-decoy-01", "http_request", at=at, session=None, method="POST", path="/login",
              honeytoken_id="tok_portal_01", username="svc_portal", **kw)


def notes_served(at, issuance, session="sess01", **kw):
    return ev("ssh-decoy-01", "bait_served", at=at, session=session, asset_id="ssh:/home/dg_demo/notes.txt",
              honeytoken_ids=["tok_portal_01"], issuance_id=issuance, evidence_basis="session_output_log",
              evidence_role="bait", **kw)


def send(client, *events):
    r = client.post("/api/ingest/events", json={"events": list(events)})
    assert r.status_code == 200 and not r.json()["rejected"], r.text
    return r.json()


def r09(client):
    db = client.app.state.db
    found = [f for c in db.list_incidents() for f in db.list_findings(c["incident_id"]) if f["rule_id"] == "R09"]
    assert len(found) == 1, found
    assert not list(FINDING_V.iter_errors(found[0]))
    return found[0]


def token_links(client):
    return [l for l in client.get("/api/links").json()["items"] if l["attribution"]]


def decide(client, link_id, decision="confirm"):
    r = client.post(f"/api/links/{link_id}/decision", json={"decision": decision, "rationale": "checked the evidence"})
    assert r.status_code == 200


# ---- orphan: token use without any bait read ----
def test_token_use_without_bait_read_is_orphan_and_never_scored(client):
    send(client, ev(at=0, session="sess01"), ev(etype="command_input", at=5, session="sess01", command="id"),
         portal_login(60))
    assert [l for l in client.get("/api/links").json()["items"] if l["kind"] == "strong_candidate"] == []
    f = r09(client)
    assert f["token_relation"] == "orphan" and "attribution" not in f
    assert f["points"] == 0 and f["pending_confirmation"] is False
    assert "no record of it being served" in f["label"]
    assert set(f["evidence_event_ids"]) == {e["event_id"] for e in client.get("/api/events").json()["items"]
                                             if e["sensor_id"] == "web-decoy-01"}  # nothing invented


def test_a_command_is_not_bait_proof(client):
    """`cat notes.txt` without the sensor's output record never makes a strong link."""
    send(client, ev(at=0, session="sess01"), ev(etype="command_input", at=5, session="sess01", command="cat notes.txt"),
         portal_login(60))
    assert r09(client)["token_relation"] == "orphan" and token_links(client) == []


# ---- linked ----
def test_unique_serving_gives_strong_unique_link(client):
    send(client, ev(at=0, session="sess01"), notes_served(5, "iss_1"), portal_login(60))
    [link] = token_links(client)
    assert link["kind"] == "strong_candidate" and link["attribution"] == "unique"
    f = r09(client)
    assert f["token_relation"] == "linked" and f["attribution"] == "unique" and f["pending_confirmation"] is True
    assert f["evidence_roles"][link["from_event_id"]] == "bait"
    decide(client, link["link_id"])
    f = r09(client)
    assert f["points"] == 15 and f["pending_confirmation"] is False


def test_static_credential_served_twice_stays_ambiguous(client):
    send(client, ev(at=0, session="sess01"), notes_served(5, "iss_1"),
         ev(at=10, session="sess02"), notes_served(15, "iss_2", session="sess02"), portal_login(60))
    links = token_links(client)
    assert len(links) == 2 and {l["attribution"] for l in links} == {"ambiguous"}
    assert all(sorted(l["candidate_issuance_ids"]) == ["iss_1", "iss_2"] for l in links)
    assert len({l["from_incident_id"] for l in links}) == 2  # one per source case; none is picked
    f = r09(client)
    assert f["attribution"] == "ambiguous" and "which serving was reused is not known" in f["label"]
    decide(client, links[0]["link_id"])
    statuses = {l["link_id"]: l["status"] for l in token_links(client)}
    assert statuses[links[0]["link_id"]] == "confirmed" and statuses[links[1]["link_id"]] == "open"


def test_later_serving_turns_unique_into_ambiguous(client):
    send(client, ev(at=0, session="sess01"), notes_served(5, "iss_1"), portal_login(60))
    assert token_links(client)[0]["attribution"] == "unique"
    send(client, notes_served(6, "iss_1b"))  # arrives late, but was served before the presentation
    [link] = token_links(client)  # same case: the same link, now ambiguous
    assert link["attribution"] == "ambiguous" and sorted(link["candidate_issuance_ids"]) == ["iss_1", "iss_1b"]


def test_serving_ingested_after_the_presentation_still_links(client):
    send(client, ev(at=0, session="sess01"), portal_login(60))
    assert r09(client)["token_relation"] == "orphan"
    send(client, notes_served(5, "iss_1"))
    assert token_links(client)[0]["attribution"] == "unique" and r09(client)["token_relation"] == "linked"


@pytest.mark.parametrize("why,serving", [
    ("after the presentation", lambda: notes_served(90, "iss_x")),
    ("another run", lambda: notes_served(5, "iss_x", run="run-other")),
    ("expired", lambda: notes_served(5, "iss_x", issued_expires_at="2026-11-01T04:30:30Z")),
    ("other token", lambda: dict(notes_served(5, "iss_x"),
                                 attributes={**notes_served(5, "iss_x")["attributes"], "honeytoken_ids": ["tok_backup_01"]})),
])
def test_ineligible_servings_do_not_link(client, why, serving):
    send(client, ev(at=0, session="sess01"), serving(), portal_login(60))
    assert token_links(client) == [], why
    assert r09(client)["token_relation"] == "orphan"


def test_replay_serving_never_explains_a_live_use(client):
    send(client, notes_served(5, "iss_r", run="replay-k", mode="replay", origin_record_id="orig-1"))
    send(client, portal_login(60))
    assert token_links(client) == [] and r09(client)["token_relation"] == "orphan"


# ---- request_only (needs M4's bait_assets registry) ----
@pytest.fixture
def registry_client(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    shutil.copytree(ROOT / "config", cfg)
    tokens = yaml.safe_load((cfg / "honeytokens.yaml").read_text(encoding="utf-8"))
    tokens["bait_assets"] = [{"asset_id": "ssh:/home/dg_demo/notes.txt", "sensor_id": "ssh-decoy-01",
                              "path": "/home/dg_demo/notes.txt", "honeytoken_ids": ["tok_portal_01"],
                              "fixture_version": "notes@1"}]
    (cfg / "honeytokens.yaml").write_text(yaml.safe_dump(tokens), encoding="utf-8")
    monkeypatch.setenv("DG_CONFIG_DIR", str(cfg))
    with TestClient(create_app(str(tmp_path / "t.db"))) as c:
        yield c


def test_bait_read_request_gives_weaker_request_only_link(registry_client):
    c = registry_client
    send(c, ev(at=0, session="sess01"),
         ev(etype="command_input", at=5, session="sess01", command="cat notes.txt",
            requested_asset_id="ssh:/home/dg_demo/notes.txt"),
         portal_login(60))
    [link] = token_links(c)
    assert link["kind"] == "candidate" and link["attribution"] == "request_only"
    assert link["basis"] == "honeytoken tok_portal_01; bait read requested by command, output not recorded"
    f = r09(c)
    assert f["token_relation"] == "request_only" and f["pending_confirmation"] is True and f["points"] == 0
    assert f["evidence_roles"][link["from_event_id"]] == "request"
    decide(c, link["link_id"])
    assert r09(c)["points"] == 15


def test_serving_outranks_request(registry_client):
    c = registry_client
    send(c, ev(at=0, session="sess01"),
         ev(etype="command_input", at=5, session="sess01", command="cat notes.txt",
            requested_asset_id="ssh:/home/dg_demo/notes.txt"),
         notes_served(5, "iss_1"), portal_login(60))
    assert [l["attribution"] for l in token_links(c)] == ["unique"]
    assert r09(c)["token_relation"] == "linked"


def test_request_for_an_unregistered_asset_is_orphan(registry_client):
    send(registry_client, ev(at=0, session="sess01"),
         ev(etype="command_input", at=5, session="sess01", command="cat other.txt", requested_asset_id="ssh:/tmp/other"),
         portal_login(60))
    assert r09(registry_client)["token_relation"] == "orphan"


# ---- corrected mappings (map@2) ----
def test_identical_retries_are_not_password_guessing(client):
    same = "ab" * 32
    send(client, *[ev(etype="auth_failure", at=i, session=f"h{i}", username="root", password_sha256=same, version="1.0")
                   for i in range(6)])
    assert [c for c in client.get("/api/incidents").json()["items"] if c["case_kind"] == "credential_attempts"] == []
    send(client, *[ev(etype="auth_failure", at=10 + i, session=f"g{i}", username="root",
                      password_sha256=f"{i:02d}" * 32, version="1.0") for i in range(5)])
    [cred] = [c for c in client.get("/api/incidents").json()["items"] if c["case_kind"] == "credential_attempts"]
    f = client.app.state.db.list_findings(cred["incident_id"])[0]
    # the six identical retries count as one password, plus five new ones
    assert "6 distinct passwords" in f["label"] and f["mapping"][0]["technique_id"] == "T1110.001"


@pytest.mark.parametrize("command", ['echo "try ls; find /tmp"', "printf 'find / -name x'", "echo 'ls'"])
def test_quoted_commands_are_not_discovery(client, command):
    send(client, ev(at=0, session="sess01", version="1.0"),
         ev(etype="command_input", at=1, session="sess01", command=command, version="1.0"))
    rules = [f["rule_id"] for f in client.app.state.db.list_findings("inc_01")]
    assert "R02" in rules and "R03" not in rules


def test_every_finding_carries_a_valid_mapping(client):
    fixture = json.loads((ROOT / "contracts/examples/events_v1_1.json").read_text(encoding="utf-8"))
    send(client, *fixture["events"])
    db = client.app.state.db
    findings = [f for c in db.list_incidents() for f in db.list_findings(c["incident_id"])]
    assert {f["rule_id"] for f in findings} >= {"R01", "R02", "R04", "R07", "R09"}
    for f in findings:
        assert not list(FINDING_V.iter_errors(f)), f
        assert f["mapping_version"] == "map@2"
        assert f["technique_ids"] == [m["technique_id"] for m in f["mapping"] if m["technique_id"]]
    r04 = next(f for f in findings if f["rule_id"] == "R04")
    assert r04["stage"] == "lure_access" and r04["technique_ids"] == [] and r04["mapping"][0]["technique_id"] is None
    assert all("T1059.007" not in f["technique_ids"] and "T1105" not in f["technique_ids"] for f in findings)
    relations = sorted(f["token_relation"] for f in findings if f["rule_id"] == "R09")
    assert relations == ["linked", "linked", "orphan"]  # portal (unique), backup (ambiguous), run 2 orphan
