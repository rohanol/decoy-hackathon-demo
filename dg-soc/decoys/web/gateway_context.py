"""v1.2 upstream verification; wire-compatible with M1's portal/context.py.

Only the authenticated envelope supplies attribution. Forwarded headers are
ignored. This checks a short-lived gateway assertion, not a person's identity.
"""
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import re
import time

HEADER = "X-DG-Gateway-Context"
KEY = re.compile(r"DGLAB-GWCTX-[0-9a-f]{64}")


def _decode(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        raise ValueError("base64url")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate key")
        result[name] = value
    return result


def verify(header, key, run_id, *, now=None):
    """Return (ingress, client_ip, client_port); absent/invalid has no ids."""
    def invalid(reason):
        return {"gateway_context": "invalid", "invalid_reason": reason}, None, None

    if not header:
        return {"gateway_context": "absent"}, None, None
    if not isinstance(key, str) or not KEY.fullmatch(key):
        return invalid("bad_signature")
    if len(header) > 4096:
        return invalid("malformed")
    parts = header.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        return invalid("malformed")
    _, body, mac = parts
    try:
        given = _decode(mac)
        expected = hmac.new(key.encode(), ("v1." + body).encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(given, expected):
            return invalid("bad_signature")
        data = json.loads(_decode(body), object_pairs_hook=_unique)
        if not isinstance(data, dict) or set(data) != {
            "gw_req", "gw_sess", "client_ip", "client_port", "run", "upstream", "iat"
        }:
            return invalid("malformed")
        if not isinstance(data["gw_req"], str) or not re.fullmatch(r"gw_[A-Za-z0-9_-]{8,64}", data["gw_req"]):
            return invalid("malformed")
        if data["gw_sess"] is not None and (
            not isinstance(data["gw_sess"], str) or not re.fullmatch(r"gws_[0-9a-f]{16,64}", data["gw_sess"])
        ):
            return invalid("malformed")
        ipaddress.IPv4Address(data["client_ip"])
        if not isinstance(data["client_ip"], str):
            return invalid("malformed")
        port = data["client_port"]
        if port is not None and (type(port) is not int or not 0 <= port <= 65535):
            return invalid("malformed")
        issued = data["iat"]
        if type(issued) not in (int, float) or not math.isfinite(issued):
            return invalid("malformed")
        if data["upstream"] != "web-decoy-01":
            return invalid("wrong_upstream")
        if data["run"] != run_id:
            return invalid("wrong_run")
        if abs((time.time() if now is None else now) - issued) > 30:
            return invalid("expired")
    except (ValueError, TypeError, UnicodeError, binascii.Error, OverflowError):
        return invalid("malformed")
    return {"gateway_context": "verified", "gateway_request_id": data["gw_req"],
            "gateway_session_ref": data["gw_sess"]}, data["client_ip"], port
