"""R11: 5+ failed logins for one username from one src_ip on one challenge-response decoy
(db-decoy-01 MySQL or file-decoy-01 SMB) within 60 s (inclusive), across connections.

Attempts, not distinct passwords: MySQL and NTLM send a salted proof, so the decoy cannot tell
whether two attempts used the same password (contract v1.2). Runs in the credential_attempts case
of that sensor, source, user, run and mode.
"""
from ._util import finding, first_window, mapped, roles

SENSORS = {"db-decoy-01": "MySQL", "file-decoy-01": "SMB"}


def evaluate(events: list, cfg) -> list:
    n = cfg.windows["r01_threshold"]
    secs = cfg.windows["r01_seconds"]
    groups: dict = {}
    for e in events:
        if e["sensor_id"] in SENSORS and e["event_type"] == "auth_failure":
            groups.setdefault((e["sensor_id"], e["attributes"].get("username", "")), []).append(e)
    out = []
    for (sensor, user), fails in sorted(groups.items()):
        window = first_window(fails, n, secs)
        if not window:
            continue
        connections = len({e["session_id"] for e in window})
        proto = SENSORS[sensor]
        out.append(finding(
            "R11", f"sensor={sensor}|user={user}",
            mapping=[mapped("T1110", "attempted",
                            f"{len(window)} failed {proto} logins for one account in {secs} s across "
                            f"{connections} connection(s); passwords are not observable in a challenge-response login")],
            stage="credential_attack",
            label=(f"Repeated {proto} login attempts ({len(window)} in {secs} s, {connections} connection(s)) "
                   f"for user '{user[:64]}' on {sensor}"),
            limitation="Counts attempts only; the decoy cannot see whether passwords differed. Not a compromise.",
            events=window, evidence_roles=roles(window, "request"),
        ))
    return out
