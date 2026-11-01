"""R07: URL-decoded path/query matches a web attack class from config/web_patterns.yaml,
or (schema 1.1) the producer's body indicators imply one (contracts/API.md, input_features)."""
from ._util import finding, mapped, normalize_url, roles

CLASS_ORDER = ["sqli", "xss", "lfi", "rfi", "cmd_injection"]


def classify(text: str, cfg) -> list:
    """Attack classes whose patterns match the normalized text."""
    decoded = normalize_url(text)
    return [c for c in CLASS_ORDER
            if any(p.search(decoded) for p in cfg.classes.get(c, []))]


# Structural indicators only (contracts/API.md, Indicator semantics). sql_quote, sql_keyword,
# sql_comment, null_byte and encoded_payload are lexical: no combination of them makes a class,
# so "John's quarterly report--" stays benign.
INDICATOR_CLASS = {
    "sql_quote_breakout": "sqli", "sql_union_select": "sqli", "sql_tautology": "sqli",
    "sql_stacked_query": "sqli", "sql_time_function": "sqli",
    "script_tag": "xss", "event_handler": "xss", "js_scheme": "xss",
    "path_traversal": "lfi", "sensitive_file_path": "lfi", "php_wrapper": "lfi",
    "remote_url_in_param": "rfi",
    "shell_metachar_command": "cmd_injection", "command_substitution": "cmd_injection",
}


def classify_indicators(indicators) -> list:
    """Classes implied by M4's fixed indicator vocabulary."""
    found = {INDICATOR_CLASS[i] for i in indicators if i in INDICATOR_CLASS}
    return [c for c in CLASS_ORDER if c in found]


def _body_indicators(e: dict) -> list:
    # Only 1.1+ events have validated input_features; a 1.0 event may carry anything there.
    if e.get("schema_version") not in ("1.1", "1.2"):
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
        # T1190 only: XSS-looking text is not JavaScript execution (T1059.007) and a URL in a
        # parameter is not a tool transfer (T1105); web_attack_class still names the class.
        out.append(finding(
            "R07", f"event={e['event_id']}",
            mapping=[mapped("T1190", "attempted",
                            f"{', '.join(classes)} pattern in the {where} to {a.get('path', '')[:64]}; "
                            "the decoy answered with a canned response")],
            stage="exploit_attempt",
            label=f"Web attack attempt ({', '.join(classes)}) in {where} to {a.get('path', '')[:128]}",
            limitation="Shows an attempt only; does not show successful exploitation.",
            events=[e], web_attack_class=classes, version=5, evidence_roles=roles([e], "request"),
        ))
    return out
