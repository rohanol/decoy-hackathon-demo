"""R07: URL-decoded path/query matches a web attack class from config/web_patterns.yaml,
or (schema 1.1) the producer's body indicators imply one (contracts/API.md, input_features)."""
from ._util import finding, normalize_url

CLASS_ORDER = ["sqli", "xss", "lfi", "rfi", "cmd_injection"]
EXTRA_TECHNIQUES = {"xss": "T1059.007", "rfi": "T1105"}


def classify(text: str, cfg) -> list:
    """Attack classes whose patterns match the normalized text."""
    decoded = normalize_url(text)
    return [c for c in CLASS_ORDER
            if any(p.search(decoded) for p in cfg.classes.get(c, []))]


def classify_indicators(indicators) -> list:
    """Classes implied by M4's fixed indicator vocabulary. null_byte and encoded_payload
    only support other evidence, so they never create a class on their own."""
    i = set(indicators)
    classes = {
        "sqli": "sql_quote" in i and bool(i & {"sql_keyword", "sql_comment"}),
        "xss": bool(i & {"script_tag", "event_handler", "js_scheme"}),
        "lfi": bool(i & {"path_traversal", "sensitive_file_path", "php_wrapper"}),
        "rfi": "remote_url_in_param" in i,
        "cmd_injection": bool(i & {"shell_metachar_command", "command_substitution"}),
    }
    return [c for c in CLASS_ORDER if classes[c]]


def _body_indicators(e: dict) -> list:
    # Only 1.1 events have validated input_features; a 1.0 event may carry anything there.
    if e.get("schema_version") != "1.1":
        return []
    features = e["attributes"].get("input_features")
    return features.get("indicators", []) if isinstance(features, dict) else []


def evaluate(events: list, cfg) -> list:
    out = []
    for e in events:
        # blocked_request and synthetic_file_access are not request evidence for R07.
        if e["sensor_id"] != "web-decoy-01" or e["event_type"] != "http_request":
            continue
        a = e["attributes"]
        text = a.get("path", "")
        if a.get("query_redacted"):
            text += "?" + a["query_redacted"]
        url_classes = classify(text, cfg)
        body_classes = classify_indicators(_body_indicators(e))
        classes = [c for c in CLASS_ORDER if c in url_classes or c in body_classes]
        if not classes:
            continue
        where = "request body" if body_classes and not url_classes else "request"
        techniques = ["T1190"] + [EXTRA_TECHNIQUES[c] for c in classes if c in EXTRA_TECHNIQUES]
        out.append(finding(
            "R07", f"event={e['event_id']}",
            techniques=techniques, stage="exploit_attempt",
            label=f"Web attack attempt ({', '.join(classes)}) in {where} to {a.get('path', '')[:128]}",
            limitation="Shows an attempt only; does not show successful exploitation.",
            events=[e], web_attack_class=classes, version=3,
        ))
    return out
