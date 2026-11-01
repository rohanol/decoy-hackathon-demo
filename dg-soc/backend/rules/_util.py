"""Helpers shared by the rules. Rules are pure: events in, finding dicts out."""
import re
from datetime import datetime
from typing import Optional
from urllib.parse import unquote_plus

MAX_EVIDENCE = 50
MAX_DECODE_ROUNDS = 3
_WHITESPACE = re.compile(r"\s+")
_SLASHES = re.compile(r"/{2,}")


def ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00"))


def in_order(events: list) -> list:
    """Time order, with seq as tiebreak, so arrival order never changes a result."""
    return sorted(events, key=lambda e: (ts(e), e["seq"]))


def first_window(events: list, count: int, seconds: int) -> Optional[list]:
    """First run of `count` or more time-ordered events spanning at most `seconds`
    (inclusive). Returns every event in that window, or None."""
    events = in_order(events)
    for i in range(len(events) - count + 1):
        start = ts(events[i])
        if (ts(events[i + count - 1]) - start).total_seconds() <= seconds:
            return [e for e in events[i:] if (ts(e) - start).total_seconds() <= seconds]
    return None


def evidence_ids(events: list) -> list:
    return [e["event_id"] for e in events[:MAX_EVIDENCE]]


def normalize_url(text: str) -> str:
    """What the web rules match against. Same steps a WAF takes before matching
    (OWASP CRS transforms urlDecodeUni, removeNulls, compressWhitespace, lowercase):
    URL-decode until nothing changes (max 3 rounds, catches %2527 and %252527),
    drop NUL bytes, turn any run of whitespace into one space, lowercase."""
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return _WHITESPACE.sub(" ", text.replace("\x00", "")).lower()


def normalize_path(path: str) -> str:
    """URL path for R08: normalized as above, query dropped, `//` and `/./` collapsed,
    no trailing slash. `/ADMIN//./` and `/admin` compare equal."""
    p = normalize_url(path.split("?", 1)[0])
    p = _SLASHES.sub("/", p)
    while "/./" in p:
        p = p.replace("/./", "/")
    if p.endswith("/."):
        p = p[:-2]
    return p.rstrip("/") or "/"


MAPPING_VERSION = "map@2"


def mapped(technique_id: Optional[str], status: str, rationale: str) -> dict:
    """One ATT&CK interpretation (finding.schema.json `mapping`). status: attempted | emulated | observed."""
    return {"technique_id": technique_id, "status": status, "rationale": rationale[:300]}


def roles(events: list, role: str) -> dict:
    return {e["event_id"]: role for e in events[:MAX_EVIDENCE]}


def finding(rule_id: str, key: str, *, mapping: list, stage: str, label: str,
            limitation: str, events: list, version: int = 1, **extra) -> dict:
    """Finding without finding_id/incident_id/src_ip/created_at: the engine adds those.
    `key` makes the finding_id stable so re-running the rules never duplicates it.
    Bump `version` whenever a rule's matching logic changes (shown as rule_version).
    technique_ids is derived from `mapping`, so the two can never disagree."""
    out = {
        "key": key,
        "rule_id": rule_id,
        "rule_version": f"{rule_id}@{version}",
        "technique_ids": [m["technique_id"] for m in mapping if m["technique_id"]],
        "mapping": mapping,
        "mapping_version": MAPPING_VERSION,
        "stage": stage,
        "label": label,
        "limitation": limitation,
        "evidence_event_ids": evidence_ids(events),
    }
    out.update(extra)
    return out
