"""Restricted SMB 2.0.2 / NTLMv2 emulator using Impacket packet codecs only.

Never starts Impacket's general-purpose SMB server, credential dumper or RPC
services. There are no host shares. Only fixed synthetic reads and bounded,
non-executable uploads to an opaque quarantine are supported.
"""
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import os
import secrets
import struct
import time
import uuid
from pathlib import Path

from impacket import ntlm, spnego
from impacket import smb3structs as s
from decoys.database.server import EventWriter, MySQLDecoy

MAX_MESSAGE, MAX_FILE = 65536, 16384
USER = "backup_ops"
NT_VERIFIER = bytes.fromhex("adb02b178c8ad0bf79b3b9f54a5d83d2")
SHARE = "backups"
SYNTHETIC = {"README.txt": b"Research operations backup share. All data is synthetic.\n",
             "customer_data.csv": b"id,name,email\n1,Demo Researcher,researcher@example.com\n"}
ACCESS_DENIED, NOT_SUPPORTED, INVALID = 0xc0000022, 0xc00000bb, 0xc000000d


def span(data, offset, length, minimum=64):
    if offset < minimum or length < 0 or offset + length > len(data):
        raise ValueError("field bounds")
    return data[offset:offset + length]


def ntlm_field(token, offset, maximum=1024):
    length, _, position = struct.unpack_from("<HHI", token, offset)
    if length > maximum:
        raise ValueError("NTLM field too large")
    return span(token, position, length, 64)


def verify_proof(token, challenge):
    if len(token) < 64:
        raise ValueError("short NTLM")
    user_raw, domain_raw = ntlm_field(token, 36, 128), ntlm_field(token, 28, 128)
    user, domain = user_raw.decode("utf-16le"), domain_raw.decode("utf-16le")
    response = ntlm_field(token, 20, 4096)
    if len(response) < 48 or response[16:20] != b"\x01\x01\x00\x00":
        return user_raw, "unsupported_scheme"
    if user.casefold() != USER:
        return user_raw, "not_checked"
    key = hmac.new(NT_VERIFIER, (user.upper() + domain).encode("utf-16le"), hashlib.md5).digest()
    expected = hmac.new(key, challenge + response[16:], hashlib.md5).digest()
    return user_raw, "matched_honeytoken" if hmac.compare_digest(response[:16], expected) else "not_matched"


def challenge_token(challenge):
    pairs = ntlm.AV_PAIRS()
    pairs[ntlm.NTLMSSP_AV_HOSTNAME] = "FILES-SRV-02".encode("utf-16le")
    pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = "WORKGROUP".encode("utf-16le")
    pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = "files-srv-02.example.com".encode("utf-16le")
    pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = "example.com".encode("utf-16le")
    target = "WORKGROUP".encode("utf-16le")
    message = ntlm.NTLMAuthChallenge()
    message["flags"] = (ntlm.NTLMSSP_NEGOTIATE_UNICODE | ntlm.NTLMSSP_NEGOTIATE_NTLM |
                        ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                        ntlm.NTLMSSP_NEGOTIATE_128 | ntlm.NTLMSSP_NEGOTIATE_56 | ntlm.NTLMSSP_REQUEST_TARGET)
    message["challenge"] = challenge
    message["domain_name"] = target
    message["domain_offset"] = 48
    message["TargetInfoFields"] = pairs.getData()
    message["TargetInfoFields_offset"] = 48 + len(target)
    message["Version"] = b""
    response = spnego.SPNEGO_NegTokenResp()
    response["NegState"] = b"\x01"
    response["SupportedMech"] = spnego.TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
    response["ResponseToken"] = message.getData()
    return response.getData()


class Quarantine:
    """Fixed quota, no attacker path names, no overwrite or execution bits."""
    def __init__(self, directory, quota=8 * 1024 * 1024):
        self.path, self.quota = Path(directory), quota
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)

    def store(self, data):
        if not data or len(data) > MAX_FILE:
            raise ValueError("file size")
        used, count = 0, 0
        for item in self.path.glob("*.inert"):
            if item.is_file():
                count += 1
                if count >= 256:
                    raise OSError("quarantine file count reached")
                used += item.stat().st_size
        if used + len(data) > self.quota:
            raise OSError("quarantine quota reached")
        destination = self.path / (uuid.uuid4().hex + ".inert")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return hashlib.sha256(data).hexdigest()


class SMBDecoy(MySQLDecoy):
    def __init__(self, writer, quarantine, **kwargs):
        super().__init__(writer, max_clients=8, lifetime=60, max_commands=64, **kwargs)
        self.quarantine = quarantine

    async def _receive(self, reader, deadline):
        async def read():
            header = await reader.readexactly(4)
            length = int.from_bytes(header[1:], "big")
            if header[0] != 0 or not 64 <= length <= MAX_MESSAGE:
                raise ValueError("SMB framing")
            raw = await reader.readexactly(length)
            if raw[:4] != b"\xfeSMB" or raw[4:6] != b"\x40\x00":
                raise ValueError("SMB2 only")
            return raw
        return await asyncio.wait_for(read(), min(self.timeout, max(.001, deadline - time.monotonic())))

    async def _reply(self, writer, request, body=None, status=0, session=0, tree=0):
        response = s.SMB2Packet()
        response["Command"], response["MessageID"] = request["Command"], request["MessageID"]
        response["Flags"], response["Status"] = 1, status
        response["CreditRequestResponse"], response["CreditCharge"] = 1, 1
        response["SessionID"], response["TreeID"] = session, tree
        response["Data"] = body if body is not None else b"\x09\x00\x00\x00\x00\x00\x00\x00\x00"
        raw = response.getData()
        writer.write(b"\x00" + len(raw).to_bytes(3, "big") + raw)
        await asyncio.wait_for(writer.drain(), self.timeout)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        if self.active >= self.max_clients:
            writer.close()
            self.tasks.discard(task)
            return
        self.active += 1
        peer, reference = writer.get_extra_info("peername"), "smbs_" + uuid.uuid4().hex
        session, challenge = secrets.randbits(63) + 1, secrets.token_bytes(8)
        deadline = time.monotonic() + self.lifetime
        authenticated, negotiated, challenged, connected = False, False, False, False
        handles = {}
        def emit(kind, **attrs):
            return self.writer.emit(kind, peer, reference, **attrs)
        try:
            ipaddress.IPv4Address(peer[0])
            emit("connection_open")
            for _ in range(self.max_commands):
                if time.monotonic() >= deadline:
                    break
                raw = await self._receive(reader, deadline)
                request, command = s.SMB2Packet(raw), struct.unpack_from("<H", raw, 12)[0]
                if request["NextCommand"] or request["Flags"] & 8:
                    await self._reply(writer, request, status=NOT_SUPPORTED, session=session)
                    continue
                body, status, tree = None, 0, 0
                if command == 0 and not negotiated:
                    if len(raw) < 100:
                        raise ValueError("short negotiate")
                    count = struct.unpack_from("<H", raw, 66)[0]
                    dialects = span(raw, 100, count * 2)
                    if count > 16 or b"\x02\x02" not in [dialects[i:i+2] for i in range(0, len(dialects), 2)]:
                        status = NOT_SUPPORTED
                    else:
                        response = s.SMB2Negotiate_Response()
                        response["DialectRevision"], response["SecurityMode"] = 0x202, 0
                        response["ServerGuid"] = b"DGLAB-SMB-SERVER"
                        response["MaxTransactSize"] = response["MaxReadSize"] = response["MaxWriteSize"] = MAX_FILE
                        response["SystemTime"] = int((time.time() + 11644473600) * 10000000)
                        response["SecurityBufferOffset"], response["SecurityBufferLength"] = 128, 0
                        response["Buffer"] = b""
                        body, negotiated = response.getData(), True
                elif command == 1 and negotiated and not authenticated:
                    offset, length = struct.unpack_from("<HH", raw, 76)
                    security = span(raw, offset, length)
                    position = security.find(b"NTLMSSP\x00")
                    token = security[position:] if position >= 0 else b""
                    if len(token) < 12 or len(token) > 8192:
                        status = ACCESS_DENIED
                    elif int.from_bytes(token[8:12], "little") == 1 and not challenged:
                        response_token = challenge_token(challenge)
                        body = struct.pack("<HHHH", 9, 0, 72, len(response_token)) + response_token
                        status, challenged = 0xc0000016, True
                    elif int.from_bytes(token[8:12], "little") == 3 and challenged:
                        try:
                            name, proof = verify_proof(token, challenge)
                        except (ValueError, UnicodeError, struct.error):
                            name, proof = b"", "malformed"
                        authenticated = proof == "matched_honeytoken"
                        attrs = {"username": USER if authenticated else "redacted_" + hmac.new(self.username_key, name, hashlib.sha256).hexdigest()[:24],
                                 "outcome": "emulated_success" if authenticated else "denied",
                                 "credential": {"scheme": "ntlmv2" if proof != "unsupported_scheme" else "other",
                                                "proof_check": proof, "verifier_version": "smbproof@1"}}
                        if authenticated:
                            attrs["honeytoken_id"] = "tok_smb_01"
                        emit("auth_success" if authenticated else "auth_failure", **attrs)
                        if authenticated:
                            final = spnego.SPNEGO_NegTokenResp()
                            final["NegState"] = b"\x00"
                            response_token = final.getData()
                            body = struct.pack("<HHHH", 9, 0, 72, len(response_token)) + response_token
                        else:
                            status = ACCESS_DENIED
                    else:
                        status = ACCESS_DENIED
                elif not authenticated or request["SessionID"] != session:
                    status = ACCESS_DENIED
                elif command == 3:
                    offset, length = struct.unpack_from("<HH", raw, 68)
                    name = span(raw, offset, length).decode("utf-16le").rsplit("\\", 1)[-1]
                    if name.casefold() != SHARE:
                        status = ACCESS_DENIED
                    else:
                        connected, tree = True, 1
                        body = struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x1f01ff)
                        emit("file_operation", file={"operation": "tree_connect", "share": SHARE, "storage": "not_applicable"})
                elif command == 2:
                    body, authenticated = struct.pack("<HH", 4, 0), False
                elif command == 13:
                    body = struct.pack("<HH", 4, 0)
                elif not connected or request["TreeID"] != 1:
                    status = ACCESS_DENIED
                elif command == 4:
                    connected, body, tree = False, struct.pack("<HH", 4, 0), 1
                elif command == 5:
                    offset, length = struct.unpack_from("<HH", raw, 108)
                    name = span(raw, offset, length).decode("utf-16le") if length else ""
                    if not name or len(name) > 128 or any(x in name for x in ("..", "/", "\\", ":", "\x00")) or len(handles) >= 8:
                        status = ACCESS_DENIED
                    else:
                        access = struct.unpack_from("<I", raw, 88)[0]
                        write = bool(access & 2)
                        if (write and name in SYNTHETIC) or (not write and name not in SYNTHETIC):
                            status = ACCESS_DENIED
                        else:
                            fid = secrets.token_bytes(16)
                            data = bytearray() if write else bytearray(SYNTHETIC[name])
                            label = name if name in SYNTHETIC else "object_" + hmac.new(self.username_key, name.encode(), hashlib.sha256).hexdigest()[:24]
                            handles[fid] = {"data": data, "write": write, "label": label}
                            response = s.SMB2Create_Response()
                            response["FileID"], response["CreateAction"] = fid, 2 if write else 1
                            response["FileAttributes"], response["EndOfFile"] = 0x80, len(data)
                            response["AllocationSize"] = len(data)
                            response["Buffer"] = b""
                            body, tree = response.getData(), 1
                            emit("file_operation", file={"operation": "create" if write else "open", "share": SHARE,
                                                        "path": label, "storage": "not_applicable"})
                elif command in (6, 8, 9, 16):
                    fid_offset = {6: 72, 8: 80, 9: 80, 16: 88}[command]
                    handle = handles.get(span(raw, fid_offset, 16))
                    if handle is None:
                        status = ACCESS_DENIED
                    else:
                        data, label, tree = handle["data"], handle["label"], 1
                        if command == 16:
                            standard = struct.pack("<QQIBBxx", len(data), len(data), 1, 0, 0)
                            body = struct.pack("<HHI", 9, 72, len(standard)) + standard
                        elif command == 8 and not handle["write"]:
                            length, offset = struct.unpack_from("<IQ", raw, 68)
                            chunk = bytes(data[offset:offset + min(length, MAX_FILE)])
                            if not chunk:
                                status = 0xc0000011
                            else:
                                body = struct.pack("<HBBIII", 17, 80, 0, len(chunk), 0, 0) + chunk
                                emit("synthetic_file_access", asset_id="smb:" + label, outcome="served",
                                     size_bytes=len(chunk), sha256=hashlib.sha256(chunk).hexdigest(), digest_scope="full_asset" if len(chunk) == len(data) else "partial")
                        elif command == 9 and handle["write"]:
                            location, length, offset = struct.unpack_from("<HIQ", raw, 66)
                            chunk = span(raw, location, length)
                            if not chunk or offset != len(data) or len(data) + length > MAX_FILE:
                                handle["failed"] = True
                                status = INVALID
                            else:
                                data.extend(chunk)
                                body = struct.pack("<HHIIHH", 17, 0, length, 0, 0, 0)
                        elif command == 6:
                            if handle["write"] and data and not handle.get("failed"):
                                digest = self.quarantine.store(data)
                                emit("file_operation", file={"operation": "write", "share": SHARE, "path": label,
                                    "bytes": len(data), "content_sha256": digest, "digest_scope": "full_content", "storage": "quarantined_inert"})
                            handles.pop(span(raw, fid_offset, 16))
                            body = struct.pack("<HHIQQQQQQI", 60, 0, 0, 0, 0, 0, 0, len(data), len(data), 0x80)
                        else:
                            status = ACCESS_DENIED
                else:
                    status = NOT_SUPPORTED
                await self._reply(writer, request, body, status, session if negotiated else 0, tree)
                if command == 1 and status == ACCESS_DENIED:
                    break
        except (OSError, ValueError, UnicodeError, struct.error, KeyError, IndexError,
                asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                emit("connection_close")
            except OSError:
                pass
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), self.timeout)
            except (OSError, asyncio.TimeoutError):
                pass
            self.active -= 1
            self.tasks.discard(task)


async def serve(host, port, log, quarantine, run, mode):
    address = ipaddress.IPv4Address(host)
    if not (address.is_loopback or host == "192.168.77.20" or
            (host == "0.0.0.0" and os.environ.get("FILE_CONTAINER_BIND") == "1")):
        raise ValueError("Bind only to lab IP or loopback")
    writer = EventWriter(log, run, mode, sensor_id="file-decoy-01", protocol="smb")
    decoy = SMBDecoy(writer, Quarantine(quarantine))
    server = await asyncio.start_server(decoy.handle, host, port, limit=MAX_MESSAGE + 4)
    print("SMB2 decoy ready; fixed share; inert uploads only", flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await decoy.close_connections()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=445)
    parser.add_argument("--log", default="deployment/state/file-log/file.json")
    parser.add_argument("--quarantine", default="deployment/state/file-quarantine")
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.host, args.port, args.log, args.quarantine,
                          os.environ.get("LAB_RUN_ID", "run-01"), os.environ.get("CAPTURE_MODE", "live")))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
