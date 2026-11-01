"""Actual Impacket SMB2 client, synthetic loopback only."""
import asyncio
import hashlib
import io
import json
import socket
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from impacket.smbconnection import SMBConnection, SessionError
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.database.server import EventWriter
from decoys.files.server import SMBDecoy, Quarantine, SYNTHETIC, USER
from decoys.web.backup import SMB_PASSWORD


@contextmanager
def running_smb(tmp_path, run_id="smb-client-test"):
    path = tmp_path / "smb.json"
    quarantine = Quarantine(tmp_path / "quarantine")
    decoy = SMBDecoy(EventWriter(path, run_id, sensor_id="file-decoy-01", protocol="smb"), quarantine, timeout=.6)
    loop, ready, state = asyncio.new_event_loop(), threading.Event(), {}
    def run():
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(asyncio.start_server(decoy.handle, "127.0.0.1", 0, limit=65540))
        state.update(server=server, port=server.sockets[0].getsockname()[1])
        ready.set()
        loop.run_forever()
        loop.close()
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(3)
    try:
        yield state["port"], path, quarantine.path
    finally:
        async def stop():
            state["server"].close()
            await state["server"].wait_closed()
            await decoy.close_connections()
        asyncio.run_coroutine_threadsafe(stop(), loop).result(3)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(3)
        assert not thread.is_alive()
        if path.is_file():
            text = path.read_text()
            assert SMB_PASSWORD not in text
            schema = json.loads((ROOT / "contracts/event.schema.json").read_text())
            for event in records(path):
                Draft202012Validator(schema, format_checker=FormatChecker()).validate(event)


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def client(port):
    return SMBConnection("FILES-SRV-02", "127.0.0.1", sess_port=port, preferredDialect=0x202, timeout=2)


def test_actual_smb2_login_read_and_inert_upload(tmp_path):
    with running_smb(tmp_path) as (port, path, quarantine):
        connection = client(port)
        connection.login(USER, SMB_PASSWORD, domain="WORKGROUP")
        output = io.BytesIO()
        connection.getFile("backups", "README.txt", output.write)
        assert output.getvalue() == SYNTHETIC["README.txt"]
        content = b"Harmless synthetic upload, never executed.\n"
        connection.putFile("backups", "report.txt", io.BytesIO(content).read)
        connection.logoff()
        connection.close()
    events = records(path)
    assert any(e["event_type"] == "auth_success" and e["attributes"].get("honeytoken_id") == "tok_smb_01" for e in events)
    upload, = [e for e in events if e["attributes"].get("file", {}).get("storage") == "quarantined_inert"]
    assert upload["attributes"]["file"]["content_sha256"] == hashlib.sha256(content).hexdigest()
    assert upload["attributes"]["file"]["bytes"] == len(content)
    stored, = list(quarantine.glob("*.inert"))
    assert stored.read_bytes() == content and "report.txt" not in str(stored)


def test_wrong_proof_rejected_without_secret_logging(tmp_path):
    with running_smb(tmp_path) as (port, path, _):
        connection = client(port)
        with pytest.raises(SessionError):
            connection.login(USER, "DGLAB-Wrong-Password", domain="WORKGROUP")
        connection.close()
    failure, = [e for e in records(path) if e["event_type"] == "auth_failure"]
    assert failure["attributes"]["credential"]["proof_check"] == "not_matched"
    assert "DGLAB-Wrong-Password" not in path.read_text()


def test_no_host_paths_or_ipc_shares(tmp_path):
    with running_smb(tmp_path) as (port, path, quarantine):
        connection = client(port)
        connection.login(USER, SMB_PASSWORD, domain="WORKGROUP")
        with pytest.raises(SessionError):
            connection.connectTree("IPC$")
        for name in ("../outside.txt", "folder/nested.txt", "README.txt"):
            with pytest.raises(SessionError):
                connection.putFile("backups", name, io.BytesIO(b"x").read)
        connection.close()
    assert list(quarantine.glob("*.inert")) == []


def test_oversize_upload_and_quota_are_refused(tmp_path):
    with running_smb(tmp_path) as (port, path, quarantine):
        connection = client(port)
        connection.login(USER, SMB_PASSWORD, domain="WORKGROUP")
        with pytest.raises(SessionError):
            connection.putFile("backups", "large.txt", io.BytesIO(b"x" * 20000).read)
        connection.close()
    assert all(p.stat().st_size <= 16384 for p in quarantine.glob("*.inert"))
    with pytest.raises(OSError):
        Quarantine(tmp_path / "tiny", quota=1).store(b"too much")


def test_quarantine_count_cap_preserves_existing_evidence(tmp_path):
    quarantine = Quarantine(tmp_path / "counted")
    for index in range(256):
        (quarantine.path / f"{index}.inert").write_bytes(b"retained")
    with pytest.raises(OSError):
        quarantine.store(b"one too many")
    assert len(list(quarantine.path.glob("*.inert"))) == 256
    assert all(path.read_bytes() == b"retained" for path in quarantine.path.glob("*.inert"))


@pytest.mark.parametrize("payload", [b"\x00\xff\xff\xff", b"\x00\x00\x00\x04xxxx", b"\x00\x00\x01\x00partial"])
def test_bad_frames_close_without_persisting_bytes(tmp_path, payload):
    with running_smb(tmp_path) as (port, path, _):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            assert sock.recv(1024) == b""
    assert "partial" not in path.read_text()
