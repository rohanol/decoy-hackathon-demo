"""R09: a honeytoken planted on one sensor is presented on the other sensor.

How the presentation relates to a serving comes from the token links (links.token_links):
- linked: a bait_served result record cites it (strong_candidate, unique or ambiguous);
- request_only: only a bait-read command was seen (candidate, request_only);
- orphan: nothing was found. Still shown, never scored, and no source event is invented.
Counts for score only after the analyst confirms the link (scoring.py).
"""
from ._util import finding, in_order

RANK = {"linked": 2, "request_only": 1, "orphan": 0}


def _relation(link: dict) -> str:
    return "linked" if link["kind"] == "strong_candidate" else "request_only"


def evaluate(events: list, cfg, links: list = ()) -> list:
    uses: dict = {}
    for e in in_order(events):
        tok_id = e["attributes"].get("honeytoken_id")
        tok = cfg.honeytokens.get(tok_id) if tok_id else None
        if tok and e["event_type"] != "blocked_request" and e["sensor_id"] != tok["planted_on"]:
            uses.setdefault(tok_id, []).append(e)
    token_links = [l for l in links if l.get("attribution")]
    out = []
    for tok_id, evs in sorted(uses.items()):
        tok = cfg.honeytokens[tok_id]
        ids = {e["event_id"] for e in evs}
        cited = [l for l in token_links if l["to_event_id"] in ids and f"honeytoken {tok_id}" in l["basis"]]
        best = max(cited, key=lambda l: (RANK[_relation(l)], l["kind"]), default=None)
        relation = _relation(best) if best else "orphan"
        here = evs[0]["sensor_id"]
        extra = {"token_relation": relation}
        roles = {e["event_id"]: "presentation" for e in evs}
        sources = []
        if relation == "linked":
            group = [l for l in cited if l["kind"] == "strong_candidate"]
            attribution = "ambiguous" if any(l["attribution"] == "ambiguous" for l in group) else "unique"
            extra["attribution"] = attribution
            sources = [{"event_id": l["from_event_id"]} for l in group]
            roles.update({l["from_event_id"]: "bait" for l in group})
            if attribution == "ambiguous":
                n = len(best.get("candidate_issuance_ids") or [])
                label = (f"Honeytoken {tok_id} presented on {here}; served {n} times by {tok['planted_on']}, "
                         "so which serving was reused is not known")
            else:
                label = f"Honeytoken {tok_id} presented on {here}; served earlier by {tok['planted_on']} ({best['basis']})"
        elif relation == "request_only":
            extra["attribution"] = "request_only"
            sources = [{"event_id": best["from_event_id"]}]
            roles[best["from_event_id"]] = "request"
            label = (f"Honeytoken {tok_id} presented on {here}; a read of the bait on {tok['planted_on']} "
                     "was requested but its output was not recorded")
        else:
            label = f"Honeytoken {tok_id} presented on {here}; no record of it being served in this run"
        out.append(finding(
            "R09", f"token={tok_id}",
            mapping=[], stage="none",
            label=label,
            limitation="Token reuse does not show that it is the same person.",
            events=sources + evs, version=2, evidence_roles=roles, **extra,
        ))
    return out
