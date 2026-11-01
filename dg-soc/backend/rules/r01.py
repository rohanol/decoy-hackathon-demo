"""R01: 5+ distinct passwords tried for one username from one src_ip within 60 s (inclusive).

Distinct, because five identical retries are a stuck client, not guessing. A failure without a
password hash cannot be shown to repeat another, so it counts as distinct. Runs across all SSH
sessions of the source (Hydra opens one per attempt), in the credential_attempts case.

If the decoy then accepts a login for that same username within another 60 s, the label
says so and that login is cited as evidence (the guessing-then-success pattern behind
rules such as Elastic's "Potential Successful SSH Brute Force"). Points do not change.
"""
from ._util import MAX_EVIDENCE, finding, in_order, mapped, roles, ts


def _password_key(e: dict) -> str:
    return e["attributes"].get("password_sha256") or f"unhashed:{e['event_id']}"


def distinct_window(fails: list, n: int, secs: int):
    """First window of at most `secs` holding `n` or more distinct passwords; all its events."""
    fails = in_order(fails)
    for i, start in enumerate(fails):
        window = [e for e in fails[i:] if (ts(e) - ts(start)).total_seconds() <= secs]
        if len({_password_key(e) for e in window}) >= n:
            return window
    return None


def _accepted_after(events: list, user: str, window: list, secs: int):
    last = ts(window[-1])
    for e in in_order(events):
        if (e["sensor_id"] == "ssh-decoy-01" and e["event_type"] == "auth_success"
                and e["attributes"].get("username", "") == user
                and 0 <= (ts(e) - last).total_seconds() <= secs):
            return e
    return None


def evaluate(events: list, cfg) -> list:
    n = cfg.windows["r01_threshold"]
    secs = cfg.windows["r01_seconds"]
    by_user: dict = {}
    for e in events:
        if e["sensor_id"] == "ssh-decoy-01" and e["event_type"] == "auth_failure":
            by_user.setdefault(e["attributes"].get("username", ""), []).append(e)
    out = []
    for user, fails in sorted(by_user.items()):
        window = distinct_window(fails, n, secs)
        if not window:
            continue
        distinct = len({_password_key(e) for e in window})
        sessions = len({e["session_id"] for e in window})
        label = (f"Repeated SSH password guessing ({distinct} distinct passwords in {secs} s, "
                 f"{sessions} session(s)) for user '{user[:64]}'")
        evidence = window
        accepted = _accepted_after(events, user, window, secs)
        if accepted:
            gap = int((ts(accepted) - ts(window[-1])).total_seconds())
            label += f"; the decoy accepted a login for this user {gap} s later"
            evidence = window[:MAX_EVIDENCE - 1] + [accepted]  # keep the login inside the cap
        out.append(finding(
            "R01", f"user={user}",
            mapping=[mapped("T1110.001", "attempted",
                            f"{distinct} distinct passwords for one account in {secs} s across {sessions} SSH session(s)")],
            stage="credential_attack",
            label=label,
            limitation="Does not show that the account was compromised.",
            events=evidence, version=3, evidence_roles=roles(evidence, "request"),
        ))
    return out
