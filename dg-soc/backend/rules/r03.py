"""R03: a submitted command starts with `ls` or `find`."""
import re

from ._util import finding, in_order

DISCOVERY = re.compile(r"^\s*(ls|find)(\s|$)")


def evaluate(events: list, cfg) -> list:
    ssh = in_order([e for e in events if e["sensor_id"] == "ssh-decoy-01"
                    and e["event_type"] == "command_input"])
    out = []
    for sid in sorted({e["session_id"] or "" for e in ssh}):
        hits = [e for e in ssh if (e["session_id"] or "") == sid
                and DISCOVERY.match(e["attributes"].get("command", ""))]
        if hits:
            out.append(finding(
                "R03", f"session={sid}",
                techniques=["T1083"], stage="post_access",
                label="Discovery command (ls/find) submitted to an emulated shell",
                limitation="Shows a discovery attempt only.",
                events=hits,
            ))
    return out
