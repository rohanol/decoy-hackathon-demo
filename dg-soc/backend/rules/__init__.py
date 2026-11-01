"""Rule engine. Event rules expose evaluate(events, cfg) -> list of finding dicts;
R05 reads links instead (evaluate_links(links)).

Which rules run where (contract v1.1, Session cases versus source profiles):
- session cases run every event rule except R01;
- a credential_attempts case runs R01 over all SSH sessions of one source, user, run and mode,
  or R11 over all connections to one MySQL/SMB decoy (v1.2);
- an investigation holds R05, one per confirmed link that joins its children.
"""
import hashlib

from . import r01, r02, r03, r04, r05, r07, r08, r09, r11, r12

RULES = [r01, r02, r03, r04, r07, r08, r09, r11, r12]
SESSION_RULES = ("R02", "R03", "R04", "R07", "R08", "R09", "R12")
CREDENTIAL_RULES = ("R01",)
CHALLENGE_CREDENTIAL_RULES = ("R11",)


def rule_id(module) -> str:
    return module.__name__.rsplit(".", 1)[-1].upper()


def finding_id(incident_id: str, rule_id: str, key: str) -> str:
    digest = hashlib.sha256(f"{incident_id}|{rule_id}|{key}".encode()).hexdigest()
    return "fnd_" + digest[:12]


def _stamp(incident: dict, raw: list) -> list:
    out = []
    for f in raw:
        f = dict(f)
        key = f.pop("key")
        f["finding_id"] = finding_id(incident["incident_id"], f["rule_id"], key)
        f["incident_id"] = incident["incident_id"]
        f["src_ip"] = incident["src_ip"]
        out.append(f)
    return out


def evaluate_incident(incident: dict, events: list, cfg, rule_ids=SESSION_RULES, links: list = ()) -> list:
    """Findings from the event rules in `rule_ids`, with stable ids. `incident` needs incident_id, src_ip.
    R09 also reads the case's token links to say how each presentation relates to a serving."""
    raw = []
    for rule in RULES:
        if rule_id(rule) in rule_ids:
            raw += rule.evaluate(events, cfg, list(links)) if rule is r09 else rule.evaluate(events, cfg)
    return _stamp(incident, raw)


def evaluate_investigation(incident: dict, links: list) -> list:
    """R05 for each confirmed link the investigation stands on."""
    return _stamp(incident, r05.evaluate_links(links))
