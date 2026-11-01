"""R04: synthetic_file_access with outcome == served.

A web download of a synthetic lure is lure access, not ATT&CK T1005 (data from a local system):
nothing on a host was collected. T1005 is kept for a read from the SSH decoy's fake filesystem,
where the decoy emulated a local file read (contract map@2). A synthetic file read over the SMB
decoy is lure access too (R04@3, v1.2); web and SSH findings keep R04@2.
"""
from ._util import finding, mapped, roles


def evaluate(events: list, cfg) -> list:
    out = []
    for e in events:
        if e["event_type"] == "synthetic_file_access" and e["attributes"].get("outcome") == "served":
            asset = str(e["attributes"].get("asset_id", "unknown"))[:128]
            version = 2
            if e["sensor_id"] == "ssh-decoy-01":
                mapping = [mapped("T1005", "emulated", "file read from the SSH decoy's emulated filesystem")]
                stage = "data_access"
            elif e["sensor_id"] == "file-decoy-01":
                mapping = [mapped(None, "emulated",
                                  "synthetic lure retrieved over SMB; not collection from a local system")]
                stage, version = "lure_access", 3
            else:
                mapping = [mapped(None, "emulated",
                                  "synthetic lure retrieved over HTTP; not collection from a local system")]
                stage = "lure_access"
            out.append(finding(
                "R04", f"event={e['event_id']}",
                mapping=mapping, stage=stage,
                label=f"Synthetic file served: {asset}",
                limitation="The file is synthetic; no real data was taken.",
                events=[e], version=version, evidence_roles=roles([e], "result"),
            ))
    return out
