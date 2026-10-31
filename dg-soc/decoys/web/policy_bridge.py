"""Use M2's checker when installed, otherwise read its frozen file contract."""

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path


def file_checker(path, allowed_ips):
    """Read on every request; callers fail closed on missing/malformed state."""
    allowed = set(allowed_ips)
    for value in allowed:
        address = ipaddress.IPv4Address(value)
        if address not in ipaddress.IPv4Network("192.168.77.0/24") or value in {
            "192.168.77.0", "192.168.77.20", "192.168.77.255"
        }:
            raise ValueError("ATTACKER_IPS must contain exact allowed lab IPs")

    def check(ip):
        state = json.loads(Path(path).read_text())
        if (not isinstance(state, dict) or type(state.get("version")) is not int
                or state["version"] < 0 or not isinstance(state.get("entries"), list)):
            raise ValueError("Invalid blocklist format")
        now = datetime.now(timezone.utc)
        for entry in state["entries"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("expires_at"), str):
                raise ValueError("Invalid blocklist entry")
            expires = datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
            if expires.tzinfo is None or not isinstance(entry["action_id"], str) or not entry["action_id"]:
                raise ValueError("Invalid blocklist entry")
            if entry["ip"] == ip and ip in allowed and expires > now:
                return entry["action_id"]
        return None

    return check


def resolve_checker(path, allowed_ips):
    guarded = file_checker(path, allowed_ips)
    try:
        from decoys.policy.policy import check
    except ModuleNotFoundError as error:
        if error.name not in {"decoys.policy", "decoys.policy.policy"}:
            raise
        return guarded

    def m2_check(ip):
        # M2's check() fails open and defaults to /state/blocklist.json. Validate the configured
        # file first, so missing or malformed state still fails closed exactly as it does in the
        # container (whose build context has no decoys/policy), then ask M2 about that same file.
        guarded(ip)
        return check(ip, str(path))

    return m2_check


def resolve_enforcer(path, allowed_ips):
    """Fail closed and return action/revision from one atomic file snapshot.

    The web image does not package decoys.policy. Use the same strict reader
    whether or not that optional module happens to be importable on the host.
    Never validate one snapshot, then reread another to infer its revision.
    """
    allowed = set(allowed_ips)
    file_checker(path, allowed)  # Validate configured targets at construction.

    def enforce(ip):
        state = json.loads(Path(path).read_text())
        if (not isinstance(state, dict) or type(state.get("version")) is not int
                or state["version"] < 0 or not isinstance(state.get("entries"), list)):
            raise ValueError("Invalid blocklist format")
        now = datetime.now(timezone.utc)
        match = (None, state["version"])
        for entry in state["entries"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("expires_at"), str):
                raise ValueError("Invalid blocklist entry")
            expires = datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
            if (expires.tzinfo is None or not isinstance(entry.get("action_id"), str)
                    or not entry["action_id"] or not isinstance(entry.get("ip"), str)):
                raise ValueError("Invalid blocklist entry")
            ipaddress.IPv4Address(entry["ip"])
            revision = entry.get("policy_revision", state["version"])
            if type(revision) is not int or revision < 0:
                raise ValueError("Invalid policy revision")
            if entry["ip"] == ip and ip in allowed and expires > now:
                match = (entry["action_id"], revision)
        return match

    return enforce
