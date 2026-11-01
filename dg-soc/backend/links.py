"""Cross-decoy links. Pure functions: events in, link dicts out. Status is never set here;
only the analyst moves a link to confirmed or rejected (db.decide_link)."""
import hashlib

from .rules._util import in_order, ts

SENSOR_PAIR = ("ssh-decoy-01", "web-decoy-01")


def link_id(key: str) -> str:
    return "lnk_" + hashlib.sha256(key.encode()).hexdigest()[:10]


BASIS_TEXT = {"sensor_response": "sensor response", "session_output_log": "session output log"}


def _link(key, frm, to, kind, basis, attribution=None, issuance_ids=()):
    return {
        "link_id": link_id(key), "from_event_id": frm["event_id"], "to_event_id": to["event_id"],
        "from_sensor": frm["sensor_id"], "to_sensor": to["sensor_id"], "kind": kind, "basis": basis,
        "from_incident_id": frm["incident_id"], "to_incident_id": to["incident_id"],
        "attribution": attribution, "candidate_issuance_ids": list(issuance_ids),
    }


def candidate_links(events: list, cfg, logged_in_cases: set) -> list:
    """`events`: everything one src_ip did in one run and mode, across cases. One candidate per
    (SSH case, web case) pair, from the earliest pair of their events within the window.
    SSH sessions that never logged in (one Hydra attempt each) are not linked: they hold no
    activity to compare."""
    secs = cfg.windows["link_candidate_seconds"]
    usable = [e for e in events if e["event_type"] != "blocked_request" and e["sensor_id"] in SENSOR_PAIR
              and (e["sensor_id"] != SENSOR_PAIR[0] or e["incident_id"] in logged_in_cases)]
    last: dict = {}  # case id -> its latest event so far
    out, seen = [], set()
    for e in in_order(usable):
        for case, prev in last.items():
            if prev["sensor_id"] == e["sensor_id"] or (ts(e) - ts(prev)).total_seconds() > secs:
                continue
            pair = tuple(sorted((case, e["incident_id"])))
            if pair not in seen:
                seen.add(pair)
                out.append(_link(f"candidate|{pair[0]}|{pair[1]}", prev, e, "candidate",
                                 f"same src_ip within {secs // 60} min"))
        last[e["incident_id"]] = e
    return out


def token_links(uses: list, cfg, servings_for, request_for) -> list:
    """Causal token matching (contracts/API.md). `uses`: events presenting a honeytoken on a sensor
    other than where it was planted. `servings_for(token, use)` returns the eligible bait_served
    records in time order; `request_for(token, use)` returns the newest bait-read command or None.

    - one eligible serving: strong_candidate, attribution unique;
    - several: one strong_candidate per source case (from its newest serving), attribution
      ambiguous, listing every issuance; the backend never picks one;
    - none, but a bait-read command: candidate, attribution request_only;
    - neither: no link at all (R09 shows the use as an orphan).
    The first presentation of a token in a case stands for that case."""
    out, seen = [], set()
    for e in in_order(uses):
        tok_id = e["attributes"]["honeytoken_id"]
        if (tok_id, e["incident_id"]) in seen:
            continue
        seen.add((tok_id, e["incident_id"]))
        tok = cfg.honeytokens[tok_id]
        servings = servings_for(tok, e)
        if servings:
            newest = {s["incident_id"]: s for s in servings}  # time order: the last one per case wins
            ambiguous = len(servings) > 1
            issuances = [s["attributes"]["issuance_id"] for s in servings] if ambiguous else []
            for s in newest.values():
                a = s["attributes"]
                basis = f"honeytoken {tok_id} served by {a['asset_id']} ({BASIS_TEXT[a['evidence_basis']]})"
                if ambiguous:
                    basis += f"; {len(servings)} servings eligible"
                out.append(_link(f"token|{tok_id}|{s['incident_id']}|{e['incident_id']}", s, e, "strong_candidate",
                                 basis, "ambiguous" if ambiguous else "unique", issuances))
            continue
        req = request_for(tok, e)
        if req:
            out.append(_link(f"request|{tok_id}|{req['incident_id']}|{e['incident_id']}", req, e, "candidate",
                             f"honeytoken {tok_id}; bait read requested by command, output not recorded",
                             "request_only"))
    return out


def token_uses(events: list, cfg) -> list:
    out = []
    for e in events:
        tok = cfg.honeytokens.get(e["attributes"].get("honeytoken_id", ""))
        if tok and e["event_type"] != "blocked_request" and e["sensor_id"] != tok["planted_on"]:
            out.append(e)
    return out
