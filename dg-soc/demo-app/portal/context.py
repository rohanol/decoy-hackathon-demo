"""Verification of the gateway's signed context header (contract v1.2, Gateway trust boundary).

Header: X-DG-Gateway-Context: v1.<payload>.<mac>
  payload = base64url(JSON {gw_req, gw_sess, client_ip, client_port, run, upstream, iat})
  mac     = base64url(HMAC-SHA256(key, "v1.<payload>"))
The key is DG_GATEWAY_CONTEXT_KEY (format DGLAB-GWCTX-<64 hex>), used as its UTF-8 bytes.
base64url is accepted with or without '=' padding.

Nothing a client sends is trusted as a client address: X-Forwarded-For and similar
headers are never read. Only a verified context may name the client.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from typing import Optional

HEADER = "X-DG-Gateway-Context"
UPSTREAM_ID = "demo-app-01"
MAX_AGE_S = 30
GW_REQ = re.compile(r"^gw_[A-Za-z0-9_-]{8,64}$")
GW_SESS = re.compile(r"^gws_[0-9a-f]{16,64}$")
KEY_FORMAT = re.compile(r"^DGLAB-GWCTX-[0-9a-f]{64}$")


@dataclass(frozen=True)
class GatewayContext:
    status: str  # verified | absent | invalid
    invalid_reason: Optional[str] = None
    gateway_request_id: Optional[str] = None
    gateway_session_ref: Optional[str] = None
    client_ip: Optional[str] = None


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign(payload: dict, key: str) -> str:
    """Build a header value. Used by tests and as the reference for M2's gateway."""
    body = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    mac = hmac.new(key.encode(), f"v1.{body}".encode(), hashlib.sha256).digest()
    return f"v1.{body}.{_b64url_encode(mac)}"


def verify(header: Optional[str], key: Optional[str], run_id: str, now: Optional[float] = None) -> GatewayContext:
    if header is None or header == "":
        return GatewayContext("absent")
    if not key or not KEY_FORMAT.match(key):
        # No usable key configured: a header cannot be checked, so it is never trusted.
        return GatewayContext("invalid", "bad_signature")
    parts = header.split(".")
    if len(parts) != 3 or parts[0] != "v1" or len(header) > 4096:
        return GatewayContext("invalid", "malformed")
    _, body, mac = parts
    expected = hmac.new(key.encode(), f"v1.{body}".encode(), hashlib.sha256).digest()
    try:
        given = _b64url_decode(mac)
    except (binascii.Error, ValueError):
        return GatewayContext("invalid", "malformed")
    if not hmac.compare_digest(expected, given):
        return GatewayContext("invalid", "bad_signature")
    try:
        payload = json.loads(_b64url_decode(body))
    except (binascii.Error, ValueError):
        return GatewayContext("invalid", "malformed")
    if not isinstance(payload, dict):
        return GatewayContext("invalid", "malformed")
    gw_req, gw_sess = payload.get("gw_req"), payload.get("gw_sess")
    client_ip, iat = payload.get("client_ip"), payload.get("iat")
    if not isinstance(gw_req, str) or not GW_REQ.match(gw_req):
        return GatewayContext("invalid", "malformed")
    if gw_sess is not None and (not isinstance(gw_sess, str) or not GW_SESS.match(gw_sess)):
        return GatewayContext("invalid", "malformed")
    try:
        if not isinstance(client_ip, str) or ipaddress.ip_address(client_ip).version != 4:
            return GatewayContext("invalid", "malformed")
    except ValueError:
        return GatewayContext("invalid", "malformed")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        return GatewayContext("invalid", "malformed")
    if payload.get("upstream") != UPSTREAM_ID:
        return GatewayContext("invalid", "wrong_upstream")
    if payload.get("run") != run_id:
        return GatewayContext("invalid", "wrong_run")
    if abs((now if now is not None else time.time()) - float(iat)) > MAX_AGE_S:
        return GatewayContext("invalid", "expired")
    return GatewayContext("verified", None, gw_req, gw_sess, client_ip)
