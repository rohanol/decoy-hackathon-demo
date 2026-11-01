"""Acceptance runner against real local producers/backend; SSH subprocess is
explicitly synthetic here because the native Cowrie VM is not available.
"""
import json
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from werkzeug.serving import make_server, WSGIRequestHandler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scenarios import four_acceptance as f
from backend.main import create_app
from decoys.web.app import create_app as web_app
from decoys.database.test_server import running_decoy
from decoys.files.test_server import running_smb
from decoys.web.backup import DB_PASSWORD, SMB_PASSWORD
from response.router import configure
from sensors.adapter import CowrieMapper, WebMapper, NativeMapper, Sender, Checkpoint, load_honeytokens, process_rotating_source


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


@pytest.fixture
def exercised(tmp_path, monkeypatch):
    run = "acceptance-runner-test"
    env = tmp_path / "lab.env"
    env.write_text(f"LAB_RUN_ID={run}\nATTACKER_IPS=192.168.77.10\nCAPTURE_MODE=live\nBACKEND_URL=http://127.0.0.1:8000\n")
    configure(state_dir=str(tmp_path), env_file=str(env))
    policy = tmp_path / "blocklist.json"
    policy.write_text('{"version":0,"entries":[]}')
    web_log, cowrie_log = tmp_path / "web.json", tmp_path / "cowrie.json"
    web = web_app({"TESTING": True, "WEB_EVENT_SCHEMA_VERSION": "1.2", "LAB_RUN_ID": run,
                   "LOG_PATH": str(web_log), "BLOCKLIST_PATH": str(policy)})
    # Web's peer is synthetic in this test; database/SMB retain actual loopback peers.
    def as_participant(environ, start_response):
        environ["REMOTE_ADDR"] = f.ATTACKER
        return web(environ, start_response)
    server = make_server("127.0.0.1", 0, as_participant, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_web, original_native, original_which = f.Web, f.native_probes, f.shutil.which
    monkeypatch.setattr(f, "Web", lambda base, tag: original_web(f"http://127.0.0.1:{server.server_port}", tag))
    monkeypatch.setattr(f.shutil, "which", lambda name: "synthetic-sshpass" if name == "sshpass" else original_which(name))
    def synthetic_ssh(directory, user, password, command, denied=False, **kwargs):
        session = uuid.uuid4().hex
        records = [{"eventid": "cowrie.session.connect"},
                   {"eventid": "cowrie.login.failed" if denied else "cowrie.login.success", "username": user, "password": password}]
        if not denied:
            records.append({"eventid": "cowrie.command.input", "input": command})
            if command.startswith("curl"):
                records.append({"eventid": "dgsoc.network.denied", "command": "network tool", "attempt_sha256": "a" * 64})
        with cowrie_log.open("a") as stream:
            for row in records:
                stream.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "src_ip": f.ATTACKER, "session": session, **row}) + "\n")
        if command.startswith("cat"):
            return (ROOT / "deployment/cowrie/honeyfs/home/dg_demo/notes.txt").read_bytes()
        return b"Network access is unavailable on this host.\n" if command.startswith("curl") else b"synthetic SSH output"
    monkeypatch.setattr(f, "ssh_probe", synthetic_ssh)
    with running_decoy(tmp_path, run_id=run) as (db_port, db_log, _), running_smb(tmp_path, run_id=run) as (smb_port, smb_log, quarantine):
        monkeypatch.setattr(f, "native_probes", lambda report, dp, sp, **kwargs: original_native(report, dp, sp, host="127.0.0.1", mysql_port=db_port, smb_port=smb_port, **kwargs))
        report = f.Report("synthetic-test", tmp_path / "client-report")
        try:
            result = f.attack(report, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
    with TestClient(create_app(str(tmp_path / "backend.db"))) as client:
        configure(state_dir=str(tmp_path), env_file=str(env), eligibility_lookup=lambda incident:
                  client.get(f"/api/incidents/{incident}/response-eligibility").json())
        class Api:
            def call(self, route, body=None):
                response = client.get(route) if body is None else client.post(route, json=body)
                assert response.status_code == 200, response.text
                return response.json()
            def events(self, current_run, cursor):
                return self.call(f"/api/events?lab_run_id={current_run}&capture_mode=live&since_seq={cursor}&limit=1000")
        api = Api()
        sender = Sender("http://127.0.0.1:9")
        def post(events):
            response = client.post("/api/ingest/events", json={"events": events})
            assert response.status_code == 200
            body = response.json()
            assert body["accepted"] == len(events), body
            return body["rejected"]
        sender.post = post
        tokens = load_honeytokens(str(ROOT / "config/honeytokens.yaml"))
        checkpoint = Checkpoint(str(tmp_path / "checkpoint.json"))
        sources = [(cowrie_log, CowrieMapper(run, "live", tokens)), (web_log, WebMapper(run, "live", tokens)),
                   (db_log, NativeMapper("db-decoy-01")), (smb_log, NativeMapper("file-decoy-01"))]
        def collect():
            for path, mapper in sources:
                process_rotating_source(str(path), mapper, checkpoint, sender)
        collect()
        events = api.events(run, 0)["items"]
        yield {"api": api, "events": events, "report": report, "result": result,
               "quarantine": quarantine, "web": web, "collect": collect, "root": tmp_path}


def test_bounded_probe_and_backend_rules(exercised):
    x = exercised
    assert x["result"] == 0
    assert x["report"].data["passed"] >= 40
    raw = (x["report"].path / "report.json").read_text()
    assert all(secret not in raw for secret in (DB_PASSWORD, SMB_PASSWORD, "DGLAB-Portal-4471"))
    assert len(list(x["quarantine"].glob("*.inert"))) == 1
    state = f.evidence_state(x["events"], f.findings_for(x["api"], x["events"]), x["api"].call("/api/links")["items"])
    assert all(state.values()), [k for k, v in state.items() if not v]
    assert {e["src_ip"] for e in x["events"] if e["sensor_id"] == "db-decoy-01"} == {"127.0.0.1"}


def test_manual_response_and_cleanup_use_actual_backend(exercised, monkeypatch):
    x = exercised
    monkeypatch.setattr("builtins.input", lambda prompt: "APPLY")
    def next_request(_):
        x["web"].test_client().get("/login", environ_overrides={"REMOTE_ADDR": f.ATTACKER})
        x["collect"]()
    monkeypatch.setattr(f.time, "sleep", next_request)
    report = f.Report("response-test", x["root"] / "response-report")
    f.response_test(x["api"], report, x["events"], x["api"].call("/api/links")["items"])
    assert report.data["failed"] == 0
    assert all(a["status"] == "revoked" for a in x["api"].call("/api/response/actions")["items"])
    assert any(l["status"] == "rejected" for l in x["api"].call("/api/links")["items"])


def test_lost_apply_response_still_revokes_its_own_action(exercised, monkeypatch):
    x = exercised
    monkeypatch.setattr("builtins.input", lambda prompt: "APPLY")
    def next_request(_):
        x["web"].test_client().get("/login", environ_overrides={"REMOTE_ADDR": f.ATTACKER})
        x["collect"]()
    monkeypatch.setattr(f.time, "sleep", next_request)
    original = x["api"].call
    def lost(route, body=None):
        result = original(route, body)
        if route == "/api/response/apply":
            raise OSError("simulated lost response")
        return result
    x["api"].call = lost
    report = f.Report("lost-response-test", x["root"] / "lost-report")
    with pytest.raises(OSError):
        f.response_test(x["api"], report, x["events"], original("/api/links")["items"])
    assert all(a["status"] == "revoked" for a in original("/api/response/actions")["items"])


def test_declined_actions_do_not_apply(exercised, monkeypatch):
    x = exercised
    monkeypatch.setattr("builtins.input", lambda prompt: "NO")
    report = f.Report("declined-test", x["root"] / "declined-report")
    with pytest.raises(f.CheckFailure):
        f.response_test(x["api"], report, x["events"], x["api"].call("/api/links")["items"])
    assert x["api"].call("/api/response/actions")["items"] == []
    assert not any(l["status"] == "confirmed" for l in x["api"].call("/api/links")["items"])


def test_existing_feed_cannot_pass_a_new_watcher(exercised, monkeypatch):
    x = exercised
    monkeypatch.setattr(f, "Api", lambda: x["api"])
    clock = [0]
    def sleep(seconds):
        clock[0] += seconds
    monkeypatch.setattr(f, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    env = x["root"] / "watch.env"
    env.write_text("LAB_HOST_IP=192.168.77.20\nATTACKER_IPS=192.168.77.10\nLAB_RUN_ID=acceptance-runner-test\n")
    report = f.Report("stale-test", x["root"] / "stale-report")
    with pytest.raises(f.CheckFailure, match="No fresh"):
        f.watch(report, env, 4, False)
    assert report.data["baseline_seq"] == max(e["seq"] for e in x["events"])
    assert any(c["name"] == "SOC: all four actual sources" and c["status"] == "FAIL" for c in report.data["checks"])
    assert x["api"].call("/api/response/actions")["items"] == []


@pytest.mark.parametrize("target", ["127.0.0.1", "example.com", "192.168.77.0/24"])
def test_cli_rejects_nonlab_target_before_network(target):
    result = subprocess.run([sys.executable, str(ROOT / "scenarios/four_acceptance.py"), "attack", "--target", target], capture_output=True, text=True)
    assert result.returncode == 2 and "Only isolated lab target" in result.stderr


def test_report_never_echoes_exception_payload(tmp_path, capsys):
    report = f.Report("privacy", tmp_path / "report")
    def failure():
        raise OSError("private-password-value")
    assert not report.check("remote failure", failure)
    assert "private-password-value" not in (report.path / "report.json").read_text()
    assert "private-password-value" not in capsys.readouterr().out


def test_ssh_helper_has_no_password_and_ignores_user_forwarding(tmp_path, monkeypatch):
    observed = {}
    def run(args, **kwargs):
        observed.update(args=args, **kwargs)
        return subprocess.CompletedProcess(args, 0, b"synthetic output", b"")
    monkeypatch.setattr(f.subprocess, "run", run)
    assert f.ssh_probe(tmp_path, "dg_demo", "private-lab-value", "ls -la") == b"synthetic output"
    assert "private-lab-value" not in (tmp_path / "askpass.sh").read_text()
    assert "private-lab-value" not in str(observed["args"])
    assert observed["env"]["SSH_ASKPASS_REQUIRE"] == "force"
    assert observed["env"]["DG_LAB_SSH_PASSWORD"] == "private-lab-value"
    assert observed["args"][:3] == ["ssh", "-F", "none"]
    assert "ClearAllForwardings=yes" in observed["args"]
    assert observed["stdin"] == subprocess.DEVNULL and observed["start_new_session"] is True


def test_ssh_connection_failure_is_not_counted_as_password_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(f.subprocess, "run", lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 255, b"", b"Connection refused"))
    with pytest.raises(f.CheckFailure, match="not authentication denial"):
        f.ssh_probe(tmp_path, "test", "private", "pwd", denied=True)
