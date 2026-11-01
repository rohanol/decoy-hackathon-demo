"""Bounded request context, not an attack detector. Never retain body bytes.

Inspect before redaction so secrets copied into other fields can be removed.
Only fixed indicators, bounded field names and redacted URL/header text leave
this object. Body values stay private; classification belongs to M3.
"""
import base64
import json
import re
from urllib.parse import parse_qsl, unquote, urlencode

from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from .input_indicators import extract_indicators

SENSITIVE = re.compile(r"pass|token|secret|authorization|api.?key|cookie|credential", re.I)
PLANTED = re.compile(r"DGLAB-[A-Za-z0-9_-]+")


def decode(value):
    return unquote(unquote(str(value)))


def bound(value, size):
    # ASCII JSON size is the backend's actual attribute budget, not char count.
    text = str(value)
    while len(json.dumps(text)) > size and text:
        text = text[:max(0, len(text) // 2)]
    return text


class RequestObservation:
    def __init__(self, request, *, seeded_secrets=()):
        self.secrets = {v for v in seeded_secrets if v}
        self.scalars = []
        self.truncated = False
        self.body_status = "absent"
        self.json_data = None
        self.query = []
        self.captured = False
        self._remaining = 4096
        self.field_count = 0
        self.source = "none"
        self.body_bytes = None
        self.body_consumed = False
        self.encoded = False
        self.max_value_length = 0
        self._request = request
        for value in request.cookies.values():
            self._secret(value)
        authorization = request.headers.get("Authorization", "")
        self._secret(authorization)
        if authorization:
            self._secret(authorization.partition(" ")[2])
            if authorization.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(authorization.partition(" ")[2], validate=True).decode()
                    self._secret(decoded)
                    self._secret(decoded.partition(":")[2])
                except (ValueError, UnicodeDecodeError):
                    pass

    def _secret(self, value):
        if value:
            self.secrets.update((str(value), decode(value)))

    def _scalar(self, location, name, value, *, sensitive=False):
        self.field_count += 1
        if self.field_count > 256:
            self.truncated = True
        if sensitive or SENSITIVE.search(decode(name)):
            self._secret(value)
            return
        if value is None or isinstance(value, (str, int, float, bool)):
            text = decode(value)
            self.encoded |= text != str(value)
            self.max_value_length = max(self.max_value_length, len(text))
            if len(self.scalars) < 16 and self._remaining > 0:
                limit = min(512, self._remaining)
                clipped = bound(text, limit)
                self.truncated |= clipped != text
                self._remaining -= len(json.dumps(clipped))
                self.scalars.append((location, bound(decode(name), 128), clipped))
            else:
                self.truncated = True

    def _walk(self, node, path="", depth=0, sensitive=False):
        if depth > 4:
            self.truncated = True
            return
        if isinstance(node, dict):
            for name, value in node.items():
                child = f"{path}.{name}" if path else str(name)
                self._walk(value, child, depth + 1, sensitive or bool(SENSITIVE.search(decode(name))))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                self._walk(value, f"{path}[{index}]", depth + 1, sensitive)
        else:
            self._scalar("json", path, node, sensitive=sensitive)

    def capture(self):
        if self.captured:
            return self
        self.captured = True
        request = self._request
        raw_query = request.query_string
        self.encoded = bool(re.search(rb"%[0-9a-fA-F]{2}", raw_query))
        if len(raw_query) > 4096:
            self.truncated = True
        # Never persist a sliced, partially redacted query. Oversized queries
        # are represented by a marker rather than potentially partial secrets.
        query_text = raw_query.decode("utf-8", "replace")
        try:
            all_query = parse_qsl(unquote(query_text), keep_blank_values=True, max_num_fields=256)
        except ValueError:
            all_query = []
            self.truncated = True
        for name, value in all_query:
            if SENSITIVE.search(decode(name)):
                self._secret(value)
        if len(raw_query) <= 4096:
            self.query = all_query
            self.source = "query" if all_query else "none"
            for name, value in self.query:
                self._scalar("query", name, value)

        if (request.method in {"POST", "PUT", "PATCH", "DELETE"}
                or request.content_length or request.headers.get("Transfer-Encoding")):
            try:
                # Flask enforces MAX_CONTENT_LENGTH on declared and terminated
                # streams. Reading once also applies the cap to unsupported routes.
                raw = request.get_data(cache=True)
                self.body_bytes, self.body_consumed = len(raw), True
                self.body_status = "empty" if not raw else "unsupported"
                if request.mimetype == "application/x-www-form-urlencoded":
                    self.source = "form"
                    self.body_status = "form"
                    for name, values in request.form.lists():
                        for value in values:
                            self._scalar("form", name, value)
                elif request.is_json:
                    self.source = "json"
                    try:
                        self.json_data = json.loads(raw)
                        self._walk(self.json_data)
                        self.body_status = "json"
                    except (ValueError, RecursionError):
                        self.json_data = None
                        self.body_status = "invalid_json"
                elif request.mimetype == "multipart/form-data":
                    self.source = "multipart"
                    self.body_status = "multipart_metadata"
                    for name, values in request.form.lists():
                        for value in values:
                            self._scalar("form", name, value)
                    for name, file in request.files.items():
                        # No filenames or uploaded contents enter request features.
                        self._scalar("multipart", name, file.mimetype)
            except RequestEntityTooLarge:
                self.body_status = "oversized"
                self.truncated = True
            except BadRequest:
                self.body_status = "invalid_body"
        return self

    def clean(self, value, limit=512):
        value = decode(value)
        for secret in sorted(self.secrets, key=len, reverse=True):
            if secret:
                value = value.replace(secret, "<redacted>")
        return bound(PLANTED.sub("<redacted>", value), limit)

    def attributes(self):
        # For opaque/malformed/deep/truncated bodies, secret discovery is not
        # complete. Suppress free text across *all* locations in that request.
        suppressed = self.body_status in {"unsupported", "invalid_json", "invalid_body", "oversized"} or self.truncated
        inspected = [] if suppressed else [(self.clean(name, 64), self.clean(value, 512))
                                           for _, name, value in self.scalars]
        # Each structural hint is extracted within one field, so a quote in one
        # field and a keyword in another cannot manufacture a SQL structure.
        indicators = set().union(*(extract_indicators(value) for _, value in inspected))
        if not suppressed and self.encoded:
            indicators.add("encoded_payload")
        if len(indicators) > 16:
            # Preserve the frozen payload bound. An over-budget inspection is
            # incomplete, never evidence that no attack-shaped input existed.
            suppressed = self.truncated = True
            indicators, inspected = set(), []
        parse_status = {"absent": "no_body", "empty": "no_body", "oversized": "rejected_too_large",
                        "unsupported": "unsupported_type", "invalid_json": "malformed", "invalid_body": "malformed"}.get(self.body_status, "parsed")
        processing = {"parse_status": parse_status, "body_consumed": self.body_consumed,
                      "redaction_version": "2", "producer_version": "m4-web@4"}
        if self.body_bytes is not None:
            processing["body_bytes"] = self.body_bytes
        return {
            "query_redacted": "<not retained>" if suppressed else bound(urlencode([
                (self.clean(name, 128), "<redacted>" if SENSITIVE.search(decode(name)) else self.clean(value, 512))
                for name, value in self.query
            ], safe="<>/'():,; "), 2048),
            "path": "<not retained>" if suppressed else self.clean(self._request.path, 2048),
            "user_agent": "<not retained>" if suppressed else self.clean(self._request.headers.get("User-Agent", ""), 512),
            "input_features": {"source": self.source, "field_count": min(self.field_count, 256),
                               "field_names": list(dict.fromkeys(name for name, _ in inspected))[:32],
                               "max_value_length": 0 if suppressed else self.max_value_length,
                               "indicators": sorted(indicators), "truncated": self.truncated},
            "processing": processing,
            "input_truncated": self.truncated,
            "body_observation": self.body_status,
            "normalisation_version": 1,
            "redaction_version": 2,
        }
