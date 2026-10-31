"""R08: 5+ hidden-path requests in 60 s, or 10+ HTTP 404s in 60 s, from one src_ip."""
from ._util import decode_twice, finding, first_window


def evaluate(events: list, cfg) -> list:
    web = [e for e in events if e["sensor_id"] == "web-decoy-01" and e["event_type"] == "http_request"]
    secs = cfg.windows["r08_seconds"]
    hidden = [e for e in web
              if decode_twice(e["attributes"].get("path", "")).rstrip("/") in cfg.hidden_paths]
    not_found = [e for e in web if e["attributes"].get("status_code") == 404]
    out = []
    window = first_window(hidden, cfg.windows["r08_hidden_threshold"], secs)
    kind = "hidden-path requests"
    if not window:
        window = first_window(not_found, cfg.windows["r08_404_threshold"], secs)
        kind = "404 responses"
    if window:
        out.append(finding(
            "R08", "probing",
            techniques=["T1595.003"], stage="recon",
            label=f"Web path probing ({len(window)} {kind} in {secs} s)",
            limitation="A request pattern only; does not show a network scan.",
            events=window,
        ))
    return out
