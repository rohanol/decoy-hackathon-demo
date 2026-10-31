"""Blocklist policy check. Owner: M2. Standard library only so the web decoy can import it.

    from policy import check
    action_id = check(request_ip)      # None -> allow, "act_xx" -> return 403 and log blocked_request

The blocklist file is written atomically by response/router.py (write tmp, rename), so a reader
never sees a half-written file. The file is re-read on every call on purpose: a block must take
effect on the very next request, and the file is tiny.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

DEFAULT_PATH = os.environ.get("BLOCKLIST_PATH", "/state/blocklist.json")


def _parse_ts(value: str) -> Optional[datetime]:
    """Parse an RFC 3339 UTC timestamp such as 2026-11-01T05:12:00Z. None if unparseable."""
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if ts.tzinfo is None:
        return None
    return ts.astimezone(timezone.utc)


def check(ip: str, path: Optional[str] = None, now: Optional[datetime] = None) -> Optional[str]:
    """Return the action_id blocking `ip`, or None if the IP is not blocked.

    Fails open (returns None) when the file is missing or unreadable: a broken blocklist must never
    take the decoy down. The preflight script checks the file is valid JSON before every run.
    Entries with a missing or unparseable expires_at are ignored (a block always needs an expiry).
    """
    now = now or datetime.now(timezone.utc)
    try:
        with open(path or DEFAULT_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        entries = data.get("entries", [])
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("ip") != ip:
            continue
        expires = _parse_ts(entry.get("expires_at", ""))
        if expires is not None and expires > now:
            action_id = entry.get("action_id")
            if isinstance(action_id, str) and action_id:
                return action_id
    return None
