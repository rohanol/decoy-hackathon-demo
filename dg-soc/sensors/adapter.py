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
    "dgsoc.network.denied": "command_input",
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
    sensor_id = "ssh-decoy-01"
    def __init__(self, lab_run_id: str, capture_mode: str, honeytokens: Dict[str, str]):
        self.lab_run_id, self.capture_mode, self.honeytokens = lab_run_id, capture_mode, honeytokens
        self.pending_version: Dict[str, str] = {}  # session -> client version waiting for its next event
        self.last_record_ignored = False

    def export_state(self) -> Dict[str, str]:
        return dict(self.pending_version)

    def restore_state(self, state: Any) -> None:
        if isinstance(state, dict):
            self.pending_version = {str(k): str(v)[:256] for k, v in state.items()
                                    if isinstance(k, str) and isinstance(v, str)}

    def map(self, raw_line: str) -> Optional[Dict[str, Any]]:
        self.last_record_ignored = False
        try:
            rec = json.loads(raw_line)
        except ValueError:
            log.warning("skip: not JSON")
            return None
        if not isinstance(rec, dict):
            return None
        eid, session = rec.get("eventid"), rec.get("session")
        if eid == "cowrie.client.version":
            self.last_record_ignored = True
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
            cmd = rec.get("input") if isinstance(rec.get("input"), str) else rec.get("command")
            if isinstance(cmd, str):
                attrs["command"] = cmd[:4096]
            if eid == "dgsoc.network.denied":
                attrs["network_attempt_outcome"] = "denied"
                attrs["real_execution"] = False
                digest = rec.get("attempt_sha256")
                if isinstance(digest, str) and len(digest) == 64:
                    attrs["attempt_sha256"] = digest
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
    sensor_id = "web-decoy-01"

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

    def get_state(self, log_path: str, inode: int) -> Any:
        entry = self.data.get(log_path)
        return entry.get("mapper_state") if entry and entry.get("inode") == inode else None

    def set(self, log_path: str, inode: int, offset: int, mapper_state: Any = None) -> None:
        self.data[log_path] = {"inode": inode, "offset": offset}
        if mapper_state is not None:
            self.data[log_path]["mapper_state"] = mapper_state
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
        self.error_count = 0
        self.last_successful_ingest_at: Optional[str] = None
        self.accepted_count = self.duplicate_count = self.rejected_count = 0
        self.quarantine_count = self.retry_count = 0

    def post(self, events: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        """Return backend rejections; None means retries ran out and checkpoint must not advance."""
        body = json.dumps({"events": events}).encode()
        delay = 0.5
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.load(resp)
                self.last_successful_ingest_at = datetime.now(timezone.utc).isoformat()
                rejected = result.get("rejected", [])
                self.accepted_count += int(result.get("accepted", 0) or 0)
                self.duplicate_count += int(result.get("duplicates", 0) or 0)
                if rejected:
                    log.warning("backend rejected %d events", len(rejected))
                    self.rejected_count += len(rejected)
                log.info("sent %d events: accepted=%s duplicates=%s", len(events), result.get("accepted"), result.get("duplicates"))
                return rejected if isinstance(rejected, list) else []
            except urllib.error.HTTPError as exc:
                if exc.code in (400, 413, 422):  # our batch is bad; retrying will not help
                    log.error("backend returned %s for a batch of %d; quarantining", exc.code, len(events))
                    self.rejected_count += len(events)
                    return [{"index": i, "reason": f"backend_http_{exc.code}"} for i in range(len(events))]
                log.warning("backend HTTP %s (attempt %d)", exc.code, attempt)
                self.error_count += 1
                self.retry_count += 1
            except (urllib.error.URLError, OSError, ValueError) as exc:
                log.warning("backend unreachable: %s (attempt %d)", exc, attempt)
                self.error_count += 1
                self.retry_count += 1
            self.sleep(delay)
            delay = min(delay * 2, 8)
        return None


def quarantine(path: str, sensor: str, source_record_id: str, reason: str,
               event: Optional[Dict[str, Any]] = None) -> None:
    """Durably store sanitized rejection details before allowing the source checkpoint to move."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    record: Dict[str, Any] = {"sensor_id": sensor, "source_record_id": source_record_id,
                              "reason": str(reason)[:240], "quarantined_at": datetime.now(timezone.utc).isoformat()}
    if event is not None:
        # Mapper output is schema-bounded and contains password hashes only.
        record["event"] = event
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


# ---------------------------------------------------------------- main loop
def process_source(path: str, mapper, ckpt: Checkpoint, sender: Sender, quarantine_path: Optional[str] = None) -> int:
    """One pass over one log file. Returns the number of events delivered."""
    try:
        inode = os.stat(path).st_ino
    except OSError:
        return 0
    offset = ckpt.get(path, inode)
    if hasattr(mapper, "restore_state"):
        mapper.restore_state(ckpt.get_state(path, inode))
    delivered = 0
    while True:
        lines, new_offset = read_new_lines(path, offset)
        if new_offset == offset and not lines:
            break
        events = []
        for line in lines:
            ev = mapper.map(line)
            if ev is None:
                if getattr(mapper, "last_record_ignored", False):
                    continue
                if quarantine_path:
                    quarantine(quarantine_path, getattr(mapper, "sensor_id", "unknown"), sha256_hex(line), "unmapped_or_malformed_record")
                    sender.quarantine_count += 1
                    sender.rejected_count += 1
                continue
            problem = validate(ev)
            if problem:
                log.warning("quarantining invalid event (%s)", problem)
                if quarantine_path:
                    quarantine(quarantine_path, ev.get("sensor_id", "unknown"), ev.get("source_record_id", ""), problem, ev)
                    sender.quarantine_count += 1
                    sender.rejected_count += 1
                continue
            events.append(ev)
        for batch in batches(events):
            rejected = sender.post(batch)
            if rejected is None:
                return delivered  # keep old checkpoint, retry next pass
            if rejected and quarantine_path:
                for item in rejected:
                    index = item.get("index") if isinstance(item, dict) else None
                    if isinstance(index, int) and 0 <= index < len(batch):
                        event = batch[index]
                        quarantine(quarantine_path, event["sensor_id"], event["source_record_id"],
                                   item.get("reason", "backend_rejected"), event)
                        sender.quarantine_count += 1
            delivered += len(batch) - len(rejected)
        offset = new_offset
        state = mapper.export_state() if hasattr(mapper, "export_state") else None
        ckpt.set(path, inode, offset, state)
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
    ap.add_argument("--quarantine", default=os.path.join(state, "rejected-events.jsonl"))
    ap.add_argument("--health", default=os.path.join(state, "collector-health.json"))
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
        errors_before = sender.error_count
        counters_before = (sender.accepted_count, sender.duplicate_count, sender.rejected_count,
                           sender.quarantine_count, sender.retry_count)
        total = sum(process_source(path, mapper, ckpt, sender, args.quarantine) for path, mapper in sources)
        counters_after = (sender.accepted_count, sender.duplicate_count, sender.rejected_count,
                          sender.quarantine_count, sender.retry_count)
        accepted, duplicates, rejected, quarantined, retries = (a - b for a, b in zip(counters_after, counters_before))
        health = {"status": "degraded" if sender.error_count > errors_before else "healthy",
                  "last_poll_at": datetime.now(timezone.utc).isoformat(), "last_successful_ingest_at": sender.last_successful_ingest_at,
                  "last_poll_delivered": total, "accepted": accepted, "duplicates": duplicates,
                  "rejected": rejected, "quarantined": quarantined, "retries": retries,
                  "error_count": sender.error_count,
                  "sources": [{"name": os.path.basename(path), "present": os.path.isfile(path)} for path, _ in sources]}
        tmp_health = args.health + ".tmp"
        os.makedirs(os.path.dirname(args.health) or ".", exist_ok=True)
        with open(tmp_health, "w", encoding="utf-8") as fh:
            json.dump(health, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_health, args.health)
        if args.once:
            log.info("done, %d events delivered", total)
            return 0
        if total == 0:
            time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
