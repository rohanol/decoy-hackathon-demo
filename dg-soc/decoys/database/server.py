"""Standard-library MySQL protocol-41 emulator for synthetic lab credentials.

No SQL engine, shell, filesystem command, external fetch, or raw packet logger.
Native password verification follows MySQL's documented 20-byte scramble:
SHA1(password) XOR SHA1(challenge + SHA1(SHA1(password))). SHA-1 here is part
of the legacy wire protocol, not a recommended password storage algorithm.
"""
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import struct
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROTOCOL_41, SECURE_CONNECTION, PLUGIN_AUTH = 0x200, 0x8000, 0x80000
CONNECT_DB, SSL, LENENC_AUTH = 8, 0x800, 0x200000
CAPABILITIES = 1 | 4 | PROTOCOL_41 | 0x2000 | SECURE_CONNECTION | PLUGIN_AUTH
USERNAME = "svc_reports"
TOKEN_ID = "tok_db_01"
# Only the protocol verifier is held by this service; the planted value lives
# in the web archive. No cleartext switch is requested from a client.
NATIVE_VERIFIER = bytes.fromhex("34d10da08cb0eec8b7aa921d106edcd5183479c3")
MAX_PACKET = 16384
COMMANDS = {1: "COM_QUIT", 2: "COM_INIT_DB", 3: "COM_QUERY", 4: "COM_FIELD_LIST",
            14: "COM_PING", 22: "COM_STMT_PREPARE", 23: "COM_STMT_EXECUTE"}
VERBS = {"select", "show", "insert", "update", "delete", "drop", "create", "use", "set", "load"}
# Protocol clients issue these setup messages after auth. ACK them as canned
# no-ops; arbitrary SETs and every data query remain refused, never evaluated.
BOOTSTRAP = {b"SET NAMES utf8mb4", b"SET NAMES utf8", b"SET NAMES latin1",
             b"SET AUTOCOMMIT = 0", b"SET AUTOCOMMIT = 1"}


def packet(payload, sequence):
    return len(payload).to_bytes(3, "little") + bytes([sequence % 256]) + payload


def error(code=1142):
    return b"\xff" + struct.pack("<H", code) + b"#42000Command unavailable on this service"


OK = b"\x00\x00\x00\x02\x00\x00\x00"


def greeting(challenge):
    return (b"\x0a8.0.36\x00" + secrets.token_bytes(4) + challenge[:8] + b"\x00"
            + struct.pack("<H", CAPABILITIES & 0xffff) + b"\x2d\x02\x00"
            + struct.pack("<H", CAPABILITIES >> 16) + b"\x15" + b"\x00" * 10
            + challenge[8:] + b"\x00mysql_native_password\x00")


def verify_native(challenge, proof):
    if len(proof) != 20:
        return False
    mask = hashlib.sha1(challenge + NATIVE_VERIFIER).digest()
    stage1 = bytes(a ^ b for a, b in zip(proof, mask))
    return hmac.compare_digest(hashlib.sha1(stage1).digest(), NATIVE_VERIFIER)


def _cstring(data, offset, limit):
    end = data.find(b"\x00", offset, offset + limit + 1)
    if end == -1:
        raise ValueError("unterminated field")
    return data[offset:end], end + 1


def parse_auth(data):
    if len(data) < 32:
        raise ValueError("short auth")
    caps = int.from_bytes(data[:4], "little")
    if caps & SSL or not caps & PROTOCOL_41:
        return b"", b"", "other"
    username, offset = _cstring(data, 32, 128)
    if caps & LENENC_AUTH:
        if offset >= len(data) or data[offset] >= 251:
            raise ValueError("unsupported proof length")
        size, offset = data[offset], offset + 1
    elif caps & SECURE_CONNECTION:
        if offset >= len(data):
            raise ValueError("missing proof")
        size, offset = data[offset], offset + 1
    else:
        return username, b"", "other"
    if size > 32 or len(data) < offset + size:
        raise ValueError("proof bounds")
    proof, offset = data[offset:offset + size], offset + size
    if caps & CONNECT_DB:
        _, offset = _cstring(data, offset, 128)  # discard, do not log
    plugin = b"mysql_native_password"
    if caps & PLUGIN_AUTH:
        plugin, offset = _cstring(data, offset, 128)
    scheme = plugin.decode("ascii", errors="replace")
    return username, proof, scheme if scheme in {"mysql_native_password", "caching_sha2_password"} else "other"


class EventWriter:
    """Bounded JSONL with four files total. Single process; producer metadata only."""
    def __init__(self, path, run_id, capture_mode="live", max_bytes=1048576,
                 sensor_id="db-decoy-01", protocol="mysql"):
        if not run_id or len(run_id) > 128 or capture_mode not in {"live", "replay"}:
            raise ValueError("Invalid run/mode")
        self.path, self.run_id, self.mode = Path(path), run_id, capture_mode
        self.max_bytes, self.lock = max_bytes, threading.Lock()
        if (sensor_id, protocol) not in {("db-decoy-01", "mysql"), ("file-decoy-01", "smb")}:
            raise ValueError("Invalid producer identity")
        self.sensor_id, self.protocol = sensor_id, protocol
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, kind, peer, session, **attrs):
        event = {"schema_version": "1.2", "source_record_id": "db_" + uuid.uuid4().hex,
                 "sensor_id": self.sensor_id, "event_type": kind,
                 "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "src_ip": peer[0], "src_port": peer[1], "session_id": session,
                 "lab_run_id": self.run_id, "capture_mode": self.mode,
                 "attributes": {"protocol": self.protocol, **attrs}}
        data = (json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
        with self.lock:
            if self.path.exists() and self.path.stat().st_size + len(data) > self.max_bytes:
                for index in (2, 1):
                    source = self.path.with_name(self.path.name + "." + str(index))
                    if source.exists():
                        source.replace(self.path.with_name(self.path.name + "." + str(index + 1)))
                self.path.replace(self.path.with_name(self.path.name + ".1"))
            with self.path.open("ab") as stream:
                stream.write(data)
        return event


class MySQLDecoy:
    def __init__(self, writer, *, max_clients=32, timeout=3.0, lifetime=30.0, max_commands=32):
        if not (1 <= max_clients <= 128 and 0 < timeout <= 30 and 0 < lifetime <= 120
                and 1 <= max_commands <= 128):
            raise ValueError("Invalid connection bounds")
        self.writer, self.max_clients = writer, max_clients
        self.timeout, self.lifetime, self.max_commands = timeout, lifetime, max_commands
        self.active, self.tasks = 0, set()
        self.username_key = secrets.token_bytes(32)

    async def _read(self, reader, expected_seq, deadline):
        async def read():
            header = await reader.readexactly(4)
            length = int.from_bytes(header[:3], "little")
            if not 1 <= length <= MAX_PACKET or header[3] != expected_seq:
                raise ValueError("packet bounds/sequence")
            return await reader.readexactly(length)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError
        return await asyncio.wait_for(read(), min(self.timeout, remaining))

    async def _send(self, writer, payload, seq):
        writer.write(packet(payload, seq))
        await asyncio.wait_for(writer.drain(), self.timeout)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        if self.active >= self.max_clients:
            writer.close()
            self.tasks.discard(task)
            return
        self.active += 1
        peer = writer.get_extra_info("peername")
        session = "dbs_" + uuid.uuid4().hex
        deadline, opened = time.monotonic() + self.lifetime, False
        try:
            ipaddress.IPv4Address(peer[0])
            self.writer.emit("connection_open", peer, session)
            opened = True
            challenge = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(20)).encode()
            await self._send(writer, greeting(challenge), 0)
            try:
                data = await self._read(reader, 1, deadline)
                username, proof, scheme = parse_auth(data)
                if scheme != "mysql_native_password":
                    check = "unsupported_scheme"
                elif len(proof) not in {0, 20}:
                    check = "malformed"
                elif username != USERNAME.encode():
                    check = "not_checked"
                else:
                    check = "matched_honeytoken" if verify_native(challenge, proof) else "not_matched"
            except ValueError:
                username, scheme, check = b"", "other", "malformed"
            matched = check == "matched_honeytoken"
            # Never persist arbitrary username text, proofs, salts, SQL, schemas,
            # client attributes or exception strings (they can contain secrets).
            safe_user = username.decode("ascii", errors="replace")
            if safe_user not in {USERNAME, "root", "admin", "guest", "test"}:
                # Distinct unknown accounts must not collapse into one account
                # and accidentally satisfy R11. Reference is process-local.
                safe_user = "redacted_" + hmac.new(self.username_key, username, hashlib.sha256).hexdigest()[:24]
            attrs = {"username": safe_user, "outcome": "emulated_success" if matched else "denied",
                     "credential": {"scheme": scheme, "proof_check": check, "verifier_version": "mysqlauth@1"}}
            if matched:
                attrs["honeytoken_id"] = TOKEN_ID
            self.writer.emit("auth_success" if matched else "auth_failure", peer, session, **attrs)
            await self._send(writer, OK if matched else error(1045), 2)
            if not matched:
                return
            for _ in range(self.max_commands):
                data = await self._read(reader, 0, deadline)
                command = COMMANDS.get(data[0], "other")
                rest = data[1:]
                no_op = data[0] in {1, 14} or (data[0] == 3 and rest in BOOTSTRAP)
                metadata = {"command": command, "execution": "not_supported", "length_bytes": len(rest)}
                if data[0] in {3, 22}:
                    match = re.match(rb"\s*([a-zA-Z]{1,16})\b", rest[:64])
                    verb = match[1].decode().lower() if match else "none"
                    metadata["statement_verb"] = verb if verb in VERBS | {"none"} else "other"
                if not no_op:
                    metadata["error_code"] = 1142
                self.writer.emit("db_request", peer, session, db=metadata,
                                 outcome="emulated_success" if no_op else "failed")
                if data[0] == 1:
                    break
                await self._send(writer, OK if no_op else error(), 1)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass  # close without printing input or retaining partial packets
        finally:
            if opened:
                try:
                    self.writer.emit("connection_close", peer, session)
                except OSError:
                    pass
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), self.timeout)
            except (OSError, asyncio.TimeoutError):
                pass
            self.active -= 1
            self.tasks.discard(task)

    async def close_connections(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def serve(host, port, log, run_id, mode):
    address = ipaddress.IPv4Address(host)
    if not (address.is_loopback or host == "192.168.77.20" or
            (host == "0.0.0.0" and os.environ.get("DB_CONTAINER_BIND") == "1")):
        raise ValueError("Bind only to the lab IP or loopback")
    decoy = MySQLDecoy(EventWriter(log, run_id, mode))
    server = await asyncio.start_server(decoy.handle, host, port, limit=MAX_PACKET + 4)
    print("MySQL decoy ready; schema=1.2; SQL execution unsupported", flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await decoy.close_connections()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("DB_BIND_IP", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DB_PORT", "3306")))
    parser.add_argument("--log", default=os.environ.get("DB_LOG_PATH", "deployment/state/db-log/db.json"))
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.host, args.port, args.log, os.environ.get("LAB_RUN_ID", "run-01"),
                          os.environ.get("CAPTURE_MODE", "live")))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
