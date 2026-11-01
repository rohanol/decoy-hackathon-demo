"""R08: 5+ hidden-path requests in 60 s, or 10+ HTTP 404s in 60 s, from one src_ip.

A request counts as hidden-path when its normalized path is a listed path or sits under
one (`/admin/login.php` is under `/admin`), the way scanners such as dirb and gobuster probe.
The hidden-path trigger also needs 3+ distinct paths in the window: five reloads of /admin are
not wordlist scanning (contract map@2).
"""
from ._util import finding, first_window, in_order, mapped, normalize_path, roles, ts

MIN_DISTINCT_PATHS = 3


def hidden_window(hidden: list, n: int, secs: int):
    """First window of at most `secs` with `n`+ hidden-path requests over 3+ distinct paths."""
    hidden = in_order(hidden)
    for i, start in enumerate(hidden):
        window = [e for e in hidden[i:] if (ts(e) - ts(start)).total_seconds() <= secs]
        paths = {normalize_path(e["attributes"].get("path", "")) for e in window}
        if len(window) >= n and len(paths) >= MIN_DISTINCT_PATHS:
            return window
    return None


def is_hidden(path: str, hidden_paths) -> bool:
    p = normalize_path(path)
    return any(p == h or p.startswith(h + "/") for h in hidden_paths)


def evaluate(events: list, cfg) -> list:
    web = [e for e in events if e["sensor_id"] == "web-decoy-01" and e["event_type"] == "http_request"]
    secs = cfg.windows["r08_seconds"]
    hidden = [e for e in web if is_hidden(e["attributes"].get("path", ""), cfg.hidden_paths)]
    not_found = [e for e in web if e["attributes"].get("status_code") == 404]
    out = []
    window = hidden_window(hidden, cfg.windows["r08_hidden_threshold"], secs)
    kind = "hidden-path requests"
    if not window:
        window = first_window(not_found, cfg.windows["r08_404_threshold"], secs)
        kind = "404 responses"
    if window:
        out.append(finding(
            "R08", "probing",
            mapping=[mapped("T1595.003", "attempted", f"{len(window)} {kind} in {secs} s from one address")],
            stage="recon",
            label=f"Web path probing ({len(window)} {kind} in {secs} s)",
            limitation="A request pattern only; does not show a network scan.",
            events=window, version=3, evidence_roles=roles(window, "request"),
        ))
    return out
