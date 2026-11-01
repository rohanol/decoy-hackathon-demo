"""R03: a submitted command starts with `ls` or `find`.

Each part of a chained line counts on its own (`cd /tmp; ls -la`, `id && find / -name x`),
and so do full paths and sudo (`/bin/ls`, `sudo find`), which is how shell-command
detections such as Sigma's Linux discovery rules read a command line.

Quoted text is data, not a command: `echo "try ls; find /tmp"` and `printf 'ls'` do not count
(contract map@2). Quotes are removed before splitting so a `;` inside them cannot start a part.
"""
import re

from ._util import finding, in_order, mapped, roles

SEGMENTS = re.compile(r"\s*(?:;|&&|\|\||\||&|\n)\s*")
# sudo flags may take a value (`sudo -u root find`); the regex backtracks if that "value" is the command.
DISCOVERY = re.compile(r"^(?:sudo(?:\s+-\S+(?:\s+[^-\s]\S*)?)*\s+)?(?:\S*/)?(ls|find)(\s|$)")
QUOTED = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*\"""")


def is_discovery(command: str) -> bool:
    unquoted = QUOTED.sub(" '' ", command.strip())
    return any(DISCOVERY.match(part) for part in SEGMENTS.split(unquoted))


def evaluate(events: list, cfg) -> list:
    ssh = in_order([e for e in events if e["sensor_id"] == "ssh-decoy-01"
                    and e["event_type"] == "command_input"])
    out = []
    for sid in sorted({e["session_id"] or "" for e in ssh}):
        hits = [e for e in ssh if (e["session_id"] or "") == sid
                and is_discovery(e["attributes"].get("command", ""))]
        if hits:
            out.append(finding(
                "R03", f"session={sid}",
                mapping=[mapped("T1083", "attempted", "ls or find typed into the emulated shell")],
                stage="post_access",
                label=f"Discovery command (ls/find) submitted to an emulated shell ({len(hits)} command(s))",
                limitation="Shows a discovery attempt only.",
                events=hits, version=3, evidence_roles=roles(hits, "request"),
            ))
    return out
