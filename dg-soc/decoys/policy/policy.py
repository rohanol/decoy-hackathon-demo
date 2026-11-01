"""Blocklist policy check. Owner: M2. Standard library only so the web decoy can import it.

    from policy import check
    action_id = check(request_ip)      # None -> allow, "act_xx" -> return 403 and log blocked_request

The blocklist file is written atomically by response/router.py (write tmp, rename), so a reader
never sees a half-written file. The file is re-read on every call on purpose: a block must take
effect on the very next request, and the file is tiny.
"""
from __future__ import annotations

import json
import ipaddress
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

    Invalid or unreadable enforcement state raises, allowing the web decoy to return 503. A malformed
    policy must never turn a denied request into an allow response.
    """
    action_id, _revision = check_with_revision(ip, path, now)
    return action_id


def check_with_revision(ip: str, path: Optional[str] = None,
                        now: Optional[datetime] = None) -> tuple[Optional[str], Optional[int]]:
    """Return the action and its enforced policy revision from one atomic file snapshot."""
    now = now or datetime.now(timezone.utc)
    try:
        with open(path or DEFAULT_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError("Invalid or unavailable blocklist policy") from exc
    if (not isinstance(data, dict) or type(data.get("version")) is not int
            or data["version"] < 0 or not isinstance(data.get("entries"), list)):
        raise ValueError("Invalid blocklist policy")
    entries, version = data["entries"], data["version"]
    parsed = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid blocklist entry")
        try:
            address = str(ipaddress.IPv4Address(entry.get("ip")))
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("Invalid blocklist entry IP") from None
        expires = _parse_ts(entry.get("expires_at"))
        action_id = entry.get("action_id")
        revision = entry.get("policy_revision", version)
        if (expires is None or not isinstance(action_id, str) or not action_id
                or type(revision) is not int or revision < 0):
            raise ValueError("Invalid blocklist entry")
        parsed.append((address, action_id, revision, expires))
    for address, action_id, revision, expires in parsed:
        if address == ip and expires > now:
            return action_id, revision
    return None, version
