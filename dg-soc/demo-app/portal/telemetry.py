"""app_request telemetry (telemetry_version 1.0, contracts/telemetry.schema.json, v1.2).

Redaction happens HERE, before anything reaches disk. The record never holds a
password, a password hash, a cookie, a header or a request body. Query values under
secret-looking keys, and any DGLAB- value anywhere, become <redacted>.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Iterable, Optional, Tuple
from urllib.parse import quote, unquote

SECRET_KEYS = re.compile(r"pass|pwd|token|secret|key|session|cookie|auth|credential", re.I)
DGLAB_VALUE = re.compile(r"DGLAB-[A-Za-z0-9_-]+")
REDACTED = "<redacted>"


def redact_text(value: str, limit: int) -> str:
    return DGLAB_VALUE.sub(REDACTED, unquote(unquote(value)))[:limit]


def redact_query(pairs: Iterable[Tuple[str, str]]) -> str:
    out = []
    for key, value in pairs:
        safe_key = DGLAB_VALUE.sub(REDACTED, key)[:64]
        safe_value = REDACTED if SECRET_KEYS.search(key) else redact_text(value, 256)
        out.append(f"{quote(safe_key, safe='')}={quote(safe_value, safe='<>')}")
    return "&".join(out)[:2048]


class TelemetryWriter:
    """Appends one JSON line per record. One gunicorn worker keeps writes serialized."""

    def __init__(self, path: Optional[str], lab_run_id: str, capture_mode: str = "live"):
        self.path = path
        self.lab_run_id = lab_run_id
        self.capture_mode = capture_mode
        self._lock = threading.Lock()
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def app_request(self, attributes: dict) -> dict:
        record = {
            "telemetry_version": "1.0",
            "record_id": "app-" + secrets.token_hex(8),
            "source_id": "demo-app-01",
            "record_type": "app_request",
            "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "lab_run_id": self.lab_run_id,
            "capture_mode": self.capture_mode,
            "attributes": attributes,
        }
        if self.path:
            line = json.dumps(record, separators=(",", ":"), sort_keys=True)
            with self._lock, open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return record
