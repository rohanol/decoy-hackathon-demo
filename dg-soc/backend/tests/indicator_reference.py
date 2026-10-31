"""Reference reading of the input_features indicator semantics (contracts/API.md).

Test-only. The backend never sees field values; this exists so the written semantics and
contracts/examples/input_indicator_vectors.json can be checked against each other, and so
M4 has an executable reading to compare the producer with.
"""
import re
from urllib.parse import unquote

I = re.IGNORECASE
_LIT = r"(?:'([^']*)'?|\"([^\"]*)\"?|(\d+))"

PATTERNS = {
    "sql_quote": re.compile(r"['\"]"),
    "sql_keyword": re.compile(r"\b(?:select|union|insert|update|delete|drop|from|where|or|and)\b", I),
    "sql_comment": re.compile(r"--|#|/\*"),
    "sql_union_select": re.compile(r"\bunion(?:\s+|/\*\*/)+(?:(?:all|distinct)(?:\s+|/\*\*/)+)?select\b", I),
    "sql_stacked_query": re.compile(
        r";\s*(?:drop\s+(?:table|database)|delete\s+from|insert\s+into|update\s+\w+\s+set|"
        r"truncate\s+table|exec(?:ute)?\b|shutdown\b)", I),
    "sql_time_function": re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b", I),
    "script_tag": re.compile(r"<script", I),
    "event_handler": re.compile(r"<[a-z][a-z0-9]*\b[^>]*\bon[a-z]+\s*=", I),
    "js_scheme": re.compile(r"(?:^|[='\"])\s*javascript:", I),
    "path_traversal": re.compile(r"\.\./|\.\.\\"),
    "sensitive_file_path": re.compile(r"/etc/passwd|/etc/shadow|/proc/self/|win\.ini", I),
    "php_wrapper": re.compile(r"\b(?:php|phar|zip|data)://", I),
    "remote_url_in_param": re.compile(r"^\s*(?:https?|ftp)://", I),
    "shell_metachar_command": re.compile(
        r"(?:;|\||&&|\n)\s*(?:id|whoami|uname|cat|ls|wget|curl|nc|bash|sh)\b", I),
    "command_substitution": re.compile(r"\$\(|`[^`]*`"),
    "null_byte": re.compile(r"%00|\x00"),
}
_TAUTOLOGY = re.compile(r"\b(?:or|and)\s+" + _LIT + r"\s*=\s*" + _LIT, I)
_AFTER_QUOTE_KEYWORD = re.compile(r"[\s)]+(?:union|select|order\s+by|group\s+by)\b", I)
_AFTER_QUOTE_COMMENT = re.compile(r"[\s)]*(?:--|#|/\*)[\s\-]*$")


def _breakout(v: str) -> bool:
    for m in re.finditer(r"['\"]", v):
        i = m.start()
        before = v[i - 1] if i else ""
        after = v[i + 1] if i + 1 < len(v) else ""
        if before.isalnum() and after.isalnum():
            continue  # inside a word, such as John's
        rest = v[i + 1:]
        if _AFTER_QUOTE_KEYWORD.match(rest) or _AFTER_QUOTE_COMMENT.match(rest):
            return True
    return False


def _tautology(v: str) -> bool:
    for m in _TAUTOLOGY.finditer(v):
        left = next(g for g in m.groups()[:3] if g is not None)
        right = next(g for g in m.groups()[3:] if g is not None)
        if left == right:
            return True
    return False


def indicators(value: str) -> set:
    out = {name for name, p in PATTERNS.items() if p.search(value)}
    if _breakout(value):
        out.add("sql_quote_breakout")
    if _tautology(value):
        out.add("sql_tautology")
    if unquote(value) != value:
        out.add("encoded_payload")
    return out
