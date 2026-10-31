"""Helpers shared by the rules. Rules are pure: events in, finding dicts out."""
from datetime import datetime
from typing import Optional
from urllib.parse import unquote_plus

MAX_EVIDENCE = 50


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


def decode_twice(text: str) -> str:
    """URL-decode twice (catches %2527-style encoding), lowercase for matching."""
    return unquote_plus(unquote_plus(text)).lower()


def finding(rule_id: str, key: str, *, techniques: list, stage: str, label: str,
            limitation: str, events: list, **extra) -> dict:
    """Finding without finding_id/incident_id/src_ip/created_at: the engine adds those.
    `key` makes the finding_id stable so re-running the rules never duplicates it."""
    out = {
        "key": key,
        "rule_id": rule_id,
        "rule_version": f"{rule_id}@1",
        "technique_ids": techniques,
        "stage": stage,
        "label": label,
        "limitation": limitation,
        "evidence_event_ids": evidence_ids(events),
    }
    out.update(extra)
    return out
