"""R12: content written to an emulated SMB share (file_operation write/create, bytes > 0,
stored quarantined_inert). The upload is stored inert for review and never executed or scanned,
so no ATT&CK technique and no malware verdict are claimed (contract v1.2).
"""
from ._util import finding, mapped, roles


def evaluate(events: list, cfg) -> list:
    out = []
    for e in events:
        f = e["attributes"].get("file") if e["event_type"] == "file_operation" else None
        if not isinstance(f, dict) or f.get("operation") not in ("write", "create"):
            continue
        if not f.get("bytes") or f.get("storage") != "quarantined_inert":
            continue
        where = f"{str(f.get('share', ''))[:80]}:{str(f.get('path', ''))[:128]}"
        out.append(finding(
            "R12", f"event={e['event_id']}",
            mapping=[mapped(None, "emulated", "content written to an emulated share; stored inert; not a malware verdict")],
            stage="post_access",
            label=f"File written to an emulated SMB share ({f['bytes']} bytes at {where}); stored inert for review",
            limitation="Shows an upload to a decoy share only. The content was never executed or classified.",
            events=[e], evidence_roles=roles([e], "result"),
        ))
    return out
