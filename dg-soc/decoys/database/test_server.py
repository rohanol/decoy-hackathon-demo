"""Actual PyMySQL client and bounded malformed-wire checks on ephemeral loopback."""
import asyncio
import hashlib
import json
import socket
import struct
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pymysql
import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.database.server import (CAPABILITIES, MAX_PACKET, USERNAME,
                                   EventWriter, MySQLDecoy, greeting, verify_native, packet, parse_auth)
from decoys.web.backup import DB_PASSWORD as LAB_PASSWORD


@contextmanager
def running_decoy(tmp_path, run_id="mysql-client-test", **bounds):
    path = tmp_path / "mysql.jsonl"
    events = EventWriter(path, run_id)
    decoy = MySQLDecoy(events, timeout=.4, lifetime=3, **bounds)
    loop, ready = asyncio.new_event_loop(), threading.Event()
    state = {}

    def run():
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(asyncio.start_server(decoy.handle, "127.0.0.1", 0, limit=MAX_PACKET + 4))
        state.update(server=server, port=server.sockets[0].getsockname()[1])
        ready.set()
        loop.run_forever()
        loop.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(3)
    try:
        yield state["port"], path, decoy
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
            assert LAB_PASSWORD not in text
            schema = json.loads((ROOT / "tests/e2e/fixtures/event.schema.v1_2.eb2a94e.json").read_text())
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            for event in records(path):
                validator.validate(event)


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def receive(sock):
    def exact(size):
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data
    header = exact(4)
    return header[3], exact(int.from_bytes(header[:3], "little"))


def client(port, **kwargs):
    return pymysql.connect(host="127.0.0.1", port=port, user=USERNAME, password=LAB_PASSWORD,
                           connect_timeout=2, read_timeout=2, write_timeout=2, **kwargs)


def test_real_pymysql_auth_query_refusal_and_ping(tmp_path):
    with running_decoy(tmp_path) as (port, path, _):
        connection = client(port)
        connection.ping(reconnect=False)
        with connection.cursor() as cursor:
            with pytest.raises(pymysql.err.OperationalError) as denied:
                cursor.execute("SELECT 'private-query-secret' FROM customer_data")
            assert denied.value.args[0] == 1142
        connection.close()
    events = records(path)
    success, = [e for e in events if e["event_type"] == "auth_success"]
    assert success["attributes"]["honeytoken_id"] == "tok_db_01"
    assert success["attributes"]["credential"]["proof_check"] == "matched_honeytoken"
    assert "password_sha256" not in success["attributes"]
    assert any(e["attributes"].get("db", {}).get("statement_verb") == "select" for e in events)
    assert all(e["attributes"]["db"]["execution"] == "not_supported" for e in events if e["event_type"] == "db_request")
    assert "private-query-secret" not in path.read_text()


@pytest.mark.parametrize("user,password,check", [
    (USERNAME, "wrong-password-secret", "not_matched"), ("root", "wrong", "not_checked"),
    ("DGLAB-SecretInUsername", "wrong", "not_checked"),
])
def test_real_client_failure_never_logs_credentials(tmp_path, user, password, check):
    with running_decoy(tmp_path) as (port, path, _):
        with pytest.raises(pymysql.err.OperationalError) as denied:
            pymysql.connect(host="127.0.0.1", port=port, user=user, password=password,
                            connect_timeout=2, read_timeout=2)
        assert denied.value.args[0] == 1045
    failure, = [e for e in records(path) if e["event_type"] == "auth_failure"]
    assert failure["attributes"]["credential"]["proof_check"] == check
    assert password not in path.read_text()
    if user.startswith("DGLAB-"):
        assert user not in path.read_text()


def test_random_challenges_and_reference_scramble():
    from pymysql._auth import scramble_native_password
    first, second = b"a" * 20, b"b" * 20
    proof = scramble_native_password(LAB_PASSWORD.encode(), first)
    assert verify_native(first, proof)
    assert not verify_native(second, proof)
    assert greeting(first)[0] == 10


def test_unknown_account_references_do_not_merge_distinct_names(tmp_path):
    with running_decoy(tmp_path) as (port, path, _):
        for username in ("private-account-one", "private-account-two", "private-account-one"):
            with pytest.raises(pymysql.err.OperationalError):
                pymysql.connect(host="127.0.0.1", port=port, user=username, password="synthetic-wrong",
                                connect_timeout=2, read_timeout=2)
    names = [e["attributes"]["username"] for e in records(path) if e["event_type"] == "auth_failure"]
    assert names[0] == names[2] and names[0] != names[1]
    assert "private-account" not in path.read_text()


@pytest.mark.parametrize("wire", [
    b"\x01\x00\x00\x01x",  # short auth
    b"\xff\xff\x00\x01",  # packet length over cap
    b"\x01\x00\x00\x04x",  # wrong sequence
    b"\x10\x00\x00\x01partial",  # truncated auth
    b"",  # idle handshake timeout
])
def test_malformed_or_idle_wire_is_closed_without_input_logging(tmp_path, wire):
    with running_decoy(tmp_path) as (port, path, _):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.settimeout(2)
            receive(sock)
            if wire:
                sock.sendall(wire)
            if wire.endswith(b"partial"):
                sock.shutdown(socket.SHUT_WR)
            try:
                while sock.recv(1024):
                    pass
            except ConnectionResetError:
                pass
    assert "partial" not in path.read_text()


def test_tls_and_unsupported_plugins_do_not_become_success(tmp_path):
    for plugin in (b"caching_sha2_password", b"mysql_clear_password"):
        with running_decoy(tmp_path) as (port, path, _):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                receive(sock)
                auth = struct.pack("<I", CAPABILITIES) + b"\x00" * 28 + USERNAME.encode() + b"\x00\x14" + b"p" * 20 + plugin + b"\x00"
                sock.sendall(packet(auth, 1))
                assert receive(sock)[1][0] == 255
        assert records(path)[-2]["attributes"]["credential"]["proof_check"] == "unsupported_scheme"


def test_log_rotation_and_disk_failure_are_bounded(tmp_path):
    writer = EventWriter(tmp_path / "rotate.json", "run", max_bytes=500)
    for _ in range(20):
        writer.emit("connection_open", ("127.0.0.1", 12), "dbs_test")
    assert len(list(tmp_path.glob("rotate.json*"))) <= 4
    broken = EventWriter(tmp_path / "directory", "run")
    broken.path.mkdir()
    with pytest.raises(OSError):
        broken.emit("connection_open", ("127.0.0.1", 12), "dbs_test")


def test_connection_and_command_limits(tmp_path):
    with running_decoy(tmp_path, max_clients=1, max_commands=2) as (port, path, decoy):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as first:
            receive(first)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as second:
                assert second.recv(1) == b""
            assert decoy.active <= 1


def test_tls_request_is_refused_without_cleartext_switch(tmp_path):
    with running_decoy(tmp_path) as (port, path, _):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            receive(sock)
            auth = struct.pack("<I", CAPABILITIES | 0x800) + b"\x00" * 28
            sock.sendall(packet(auth, 1))
            assert receive(sock)[1][0] == 255
    failure = next(e for e in records(path) if e["event_type"] == "auth_failure")
    assert failure["attributes"]["credential"]["proof_check"] == "unsupported_scheme"


def test_logging_failure_closes_before_greeting(tmp_path):
    with running_decoy(tmp_path) as (port, path, _):
        path.mkdir()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            assert sock.recv(1) == b""


def test_command_budget_closes_an_authenticated_connection(tmp_path):
    with running_decoy(tmp_path, max_commands=2) as (port, path, _):
        connection = client(port)  # two canned client setup messages consume budget
        with pytest.raises((pymysql.err.OperationalError, pymysql.err.InterfaceError)):
            connection.ping(reconnect=False)
        connection.close()
    assert len([e for e in records(path) if e["event_type"] == "db_request"]) == 2


@pytest.mark.parametrize("data", [b"", b"x" * 31, struct.pack("<I", CAPABILITIES) + b"\x00" * 28 + b"u" * 150])
def test_parser_rejects_incomplete_fields(data):
    with pytest.raises(ValueError):
        parse_auth(data)
