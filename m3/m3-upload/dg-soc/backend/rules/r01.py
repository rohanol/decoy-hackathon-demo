"""R01: 5+ SSH auth failures, same src_ip + username, within 60 s (inclusive)."""
from ._util import finding, first_window


def evaluate(events: list, cfg) -> list:
    n = cfg.windows["r01_threshold"]
    secs = cfg.windows["r01_seconds"]
    by_user: dict = {}
    for e in events:
        if e["sensor_id"] == "ssh-decoy-01" and e["event_type"] == "auth_failure":
            by_user.setdefault(e["attributes"].get("username", ""), []).append(e)
    out = []
    for user, fails in sorted(by_user.items()):
        window = first_window(fails, n, secs)
        if window:
            out.append(finding(
                "R01", f"user={user}",
                techniques=["T1110.001"], stage="credential_attack",
                label=f"Repeated SSH password guessing ({len(window)} failures in {secs} s) for user '{user[:64]}'",
                limitation="Does not show that the account was compromised.",
                events=window,
            ))
    return out
