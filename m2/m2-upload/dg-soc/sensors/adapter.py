#!/usr/bin/env python3
"""Log adapter: Cowrie + web decoy JSON logs -> event.schema.json -> POST /api/ingest/events. Owner: M2.

    python sensors/adapter.py                 # run forever
    python sensors/adapter.py --once          # drain what is there, then exit

- Tails deployment/state/cowrie-log/cowrie.json and deployment/state/web-log/web.json.
- Byte-offset checkpoint (deployment/state/adapter-checkpoint.json), advanced only after the backend
  accepted the batch, so a restart never skips events and never resends delivered ones. A crash between
  POST and checkpoint can resend one batch; the backend dedups on (sensor_id, source_record_id).
- Raw passwords are hashed with sha256 and dropped. Honeytoken hashes come from config/honeytokens.yaml.
- Needs PyYAML only for the honeytoken file (pip install pyyaml). Everything else is standard library.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

log = logging.getLogger("adapter")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENSOR_IDS = {"ssh-decoy-01", "web-decoy-01"}
EVENT_TYPES = {
    "connection_open", "auth_failure", "auth_success", "command_input", "connection_close",
    "http_request", "synthetic_file_access", "blocked_request",
}
TOP_LEVEL_KEYS = {
    "schema_version", "source_record_id", "sensor_id", "event_type", "occurred_at", "src_ip",
    "src_port", "session_id", "lab_run_id", "capture_mode", "attributes",
}
COWRIE_TYPES = {
    "cowrie.session.connect": "connection_open",
    "cowrie.login.failed": "auth_failure",
    "cowrie.login.success": "auth_success",
    "cowrie.command.input": "command_input",
    "cowrie.session.closed": "connection_close",
}
MAX_BATCH_EVENTS = 100
MAX_BATCH_BYTES = 900_000  # contract limit is 1 MiB; stay under it
FORBIDDEN_ATTRS = {"password", "passwd", "pass", "token", "secret"}  # defence in depth: never forward


# ---------------------------------------------------------------- helpers
def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def norm_ts(value: Any) -> Optional[str]:
    """Cowrie writes 2026-11-01T04:30:00.123456Z. Return RFC 3339 UTC with a Z suffix, or None."""
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def valid_ipv4(value: Any) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return isinstance(value, str)
    except ValueError:
        return False


def load_honeytokens(path: str) -> Dict[str, str]:
    """{value_sha256: token_id}. Missing file or PyYAML -> empty map with a loud warning."""
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        return {t["value_sha256"].lower(): t["id"] for t in doc.get("tokens", [])}
    except Exception as exc:  # noqa: BLE001
        log.warning("honeytokens NOT loaded (%s): R09 matches will be missing", exc)
        return {}


# ---------------------------------------------------------------- mapping
class CowrieMapper:
    def __init__(self, lab_run_id: str, capture_mode: str, honeytokens: Dict[str, str]):
        self.lab_run_id, self.capture_mode, self.honeytokens = lab_run_id, capture_mode, honeytokens
        self.pending_version: Dict[str, str] = {}  # session -> client version waiting for its next event

    def map(self, raw_line: str) -> Optional[Dict[str, Any]]:
        try:
            rec = json.loads(raw_line)
        except ValueError:
            log.warning("skip: not JSON")
            return None
        if not isinstance(rec, dict):
            return None
        eid, session = rec.get("eventid"), rec.get("session")
        if eid == "cowrie.client.version":
            v = rec.get("version")
            v = ",".join(map(str, v)) if isinstance(v, list) else v
            if isinstance(session, str) and isinstance(v, str):
                self.pending_version[session] = v[:256]
            return None
        etype = COWRIE_TYPES.get(eid)
        ts, ip = norm_ts(rec.get("timestamp")), rec.get("src_ip")
        if etype is None or ts is None or not valid_ipv4(ip):
            return None
        attrs: Dict[str, Any] = {}
        if etype in ("auth_failure", "auth_success"):
            username, password = rec.get("username"), rec.get("password")
            if isinstance(username, str):
                attrs["username"] = username[:128]
            if isinstance(password, str):
                digest = sha256_hex(password)
                attrs["password_sha256"] = digest
                token = self.honeytokens.get(digest)
                if token:
                    attrs["honeytoken_id"] = token
        elif etype == "command_input":
            cmd = rec.get("input")
            if isinstance(cmd, str):
                attrs["command"] = cmd[:4096]
        if isinstance(session, str) and session in self.pending_version and etype != "connection_close":
            attrs["client_version"] = self.pending_version.pop(session)
        if etype == "connection_close" and isinstance(session, str):
            self.pending_version.pop(session, None)
        port = rec.get("src_port")
        return {
            "schema_version": "1.0",
            "source_record_id": sha256_hex(raw_line),
            "sensor_id": "ssh-decoy-01",
            "event_type": etype,
            "occurred_at": ts,
            "src_ip": ip,
            "src_port": port if isinstance(port, int) and not isinstance(port, bool) else None,
            "session_id": session if isinstance(session, str) else None,
            "lab_run_id": self.lab_run_id,
            "capture_mode": self.capture_mode,
            "attributes": attrs,
        }


class WebMapper:
    """The web decoy (M4) is expected to log one event-shaped JSON object per line.
    We fill the envelope defaults, hash anything password-like that slipped in, and validate."""

    def __init__(self, lab_run_id: str, capture_mode: str, honeytokens: Dict[str, str]):
        self.lab_run_id, self.capture_mode, self.honeytokens = lab_run_id, capture_mode, honeytokens

    def map(self, raw_line: str) -> Optional[Dict[str, Any]]:
        try:
            rec = json.loads(raw_line)
        except ValueError:
            log.warning("skip: not JSON")
            return None
        if not isinstance(rec, dict):
            return None
        ev = {k: v for k, v in rec.items() if k in TOP_LEVEL_KEYS}
        ev.setdefault("schema_version", "1.0")
        ev.setdefault("sensor_id", "web-decoy-01")
        ev.setdefault("source_record_id", sha256_hex(raw_line))
        ev.setdefault("lab_run_id", self.lab_run_id)
        ev.setdefault("capture_mode", self.capture_mode)
        ts = norm_ts(ev.get("occurred_at"))
        if ts:
            ev["occurred_at"] = ts
        attrs = dict(ev.get("attributes") or {}) if isinstance(ev.get("attributes"), dict) else {}
        for key in list(attrs):
            if key.lower() in FORBIDDEN_ATTRS:
                raw = attrs.pop(key)
                if isinstance(raw, str) and "password_sha256" not in attrs:
                    attrs["password_sha256"] = sha256_hex(raw)
        digest = attrs.get("password_sha256")
        if isinstance(digest, str) and digest.lower() in self.honeytokens:
            attrs.setdefault("honeytoken_id", self.honeytokens[digest.lower()])
        ev["attributes"] = attrs
        ev.setdefault("src_port", None)
        ev.setdefault("session_id", None)
        return ev


def validate(ev: Dict[str, Any]) -> Optional[str]:
    """Return a reason string if the event would be rejected by the backend, else None."""
    if ev.get("schema_version") != "1.0":
        return "schema_version"
    if ev.get("sensor_id") not in SENSOR_IDS:
        return "sensor_id"
    if ev.get("event_type") not in EVENT_TYPES:
        return "event_type"
    if not isinstance(ev.get("source_record_id"), str) or not 0 < len(ev["source_record_id"]) <= 128:
        return "source_record_id"
    if norm_ts(ev.get("occurred_at")) is None:
        return "occurred_at"
    if not valid_ipv4(ev.get("src_ip")):
        return "src_ip: not an ipv4"
    if ev.get("capture_mode") not in ("live", "replay"):
        return "capture_mode"
    if not isinstance(ev.get("lab_run_id"), str) or not ev["lab_run_id"]:
        return "lab_run_id"
    return None


# ---------------------------------------------------------------- checkpoint + tailing
class Checkpoint:
    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Dict[str, int]] = {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            pass

    def get(self, log_path: str, inode: int) -> int:
        entry = self.data.get(log_path)
        return int(entry["offset"]) if entry and entry.get("inode") == inode else 0

    def set(self, log_path: str, inode: int, offset: int) -> None:
        self.data[log_path] = {"inode": inode, "offset": offset}
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)


def read_new_lines(path: str, offset: int, limit: int = 2000) -> Tuple[List[str], int]:
    """Return (complete lines, new offset). A trailing partial line is left for the next pass.
    If the file shrank (truncated or rotated in place) start again from 0."""
    try:
        size = os.stat(path).st_size
    except OSError:
        return [], offset
    if size < offset:
        log.warning("%s shrank, restarting from offset 0", path)
        offset = 0
    lines: List[str] = []
    with open(path, "rb") as fh:
        fh.seek(offset)
        while len(lines) < limit:
            chunk_start = fh.tell()
            raw = fh.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                fh.seek(chunk_start)
                break
            offset = fh.tell()
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if text.strip():
                lines.append(text)
    return lines, offset


def batches(events: List[Dict[str, Any]]) -> Iterable[List[Dict[str, Any]]]:
    cur: List[Dict[str, Any]] = []
    size = 0
    for ev in events:
        n = len(json.dumps(ev))
        if cur and (len(cur) >= MAX_BATCH_EVENTS or size + n > MAX_BATCH_BYTES):
            yield cur
            cur, size = [], 0
        cur.append(ev)
        size += n
    if cur:
        yield cur


# ---------------------------------------------------------------- sender
class Sender:
    def __init__(self, backend_url: str, max_retries: int = 6, sleep=None):
        self.url = backend_url.rstrip("/") + "/api/ingest/events"
        self.max_retries = max_retries
        self.sleep = sleep or (lambda seconds: time.sleep(seconds))  # resolved at call time so tests can patch

    def post(self, events: List[Dict[str, Any]]) -> bool:
        """True when the backend handled the batch (or answered with a non-retryable 4xx we must skip).
        False when retries ran out: the caller must NOT advance the checkpoint."""
        body = json.dumps({"events": events}).encode()
        delay = 0.5
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.load(resp)
                if result.get("rejected"):
                    log.warning("backend rejected %d events: %s", len(result["rejected"]), result["rejected"][:3])
                log.info("sent %d events: accepted=%s duplicates=%s", len(events), result.get("accepted"), result.get("duplicates"))
                return True
            except urllib.error.HTTPError as exc:
                if exc.code in (400, 413, 422):  # our batch is bad; retrying will not help
                    log.error("backend returned %s for a batch of %d, skipping it: %s", exc.code, len(events), exc.read()[:300])
                    return True
                log.warning("backend HTTP %s (attempt %d)", exc.code, attempt)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                log.warning("backend unreachable: %s (attempt %d)", exc, attempt)
            self.sleep(delay)
            delay = min(delay * 2, 8)
        return False


# ---------------------------------------------------------------- main loop
def process_source(path: str, mapper, ckpt: Checkpoint, sender: Sender) -> int:
    """One pass over one log file. Returns the number of events delivered."""
    try:
        inode = os.stat(path).st_ino
    except OSError:
        return 0
    offset = ckpt.get(path, inode)
    delivered = 0
    while True:
        lines, new_offset = read_new_lines(path, offset)
        if new_offset == offset and not lines:
            break
        events = []
        for line in lines:
            ev = mapper.map(line)
            if ev is None:
                continue
            problem = validate(ev)
            if problem:
                log.warning("dropped event (%s)", problem)
                continue
            events.append(ev)
        for batch in batches(events):
            if not sender.post(batch):
                return delivered  # keep old checkpoint, retry next pass
            delivered += len(batch)
        offset = new_offset
        ckpt.set(path, inode, offset)
    return delivered


def parse_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def main(argv: Optional[List[str]] = None) -> int:
    env = parse_env_file(os.path.join(ROOT, "deployment", "lab.env"))
    state = os.path.join(ROOT, "deployment", "state")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default=os.environ.get("BACKEND_URL", env.get("BACKEND_URL", "http://127.0.0.1:8000")))
    ap.add_argument("--lab-run-id", default=os.environ.get("LAB_RUN_ID", env.get("LAB_RUN_ID", "run-01")))
    ap.add_argument("--capture-mode", choices=["live", "replay"], default="live")
    ap.add_argument("--cowrie-log", default=os.path.join(state, "cowrie-log", "cowrie.json"))
    ap.add_argument("--web-log", default=os.path.join(state, "web-log", "web.json"))
    ap.add_argument("--checkpoint", default=os.path.join(state, "adapter-checkpoint.json"))
    ap.add_argument("--honeytokens", default=os.path.join(ROOT, "config", "honeytokens.yaml"))
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    tokens = load_honeytokens(args.honeytokens)
    sources = [
        (args.cowrie_log, CowrieMapper(args.lab_run_id, args.capture_mode, tokens)),
        (args.web_log, WebMapper(args.lab_run_id, args.capture_mode, tokens)),
    ]
    ckpt, sender = Checkpoint(args.checkpoint), Sender(args.backend)
    log.info("adapter up: backend=%s run=%s mode=%s honeytokens=%d", args.backend, args.lab_run_id, args.capture_mode, len(tokens))
    while True:
        total = sum(process_source(path, mapper, ckpt, sender) for path, mapper in sources)
        if args.once:
            log.info("done, %d events delivered", total)
            return 0
        if total == 0:
            time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
