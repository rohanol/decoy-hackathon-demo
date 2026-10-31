"""Manual block flow: preview -> apply -> (verify) -> revoke/expire. Owner: M2.

Mounted by M3 (Rohan) in the backend:

    from response.router import router, on_event, configure
    app.include_router(router, prefix="/api/response")
    # in the ingest path, after an event is stored and has its event_id:
    on_event(event)

Scope is one exact lab IP on web-decoy-01, nothing else. Targets must be listed in ATTACKER_IPS
(deployment/lab.env). 192.168.77.20, loopback and any range are refused even if lab.env is wrong.

Route handlers are plain `def` so FastAPI runs them in a thread pool. That matters: the default
incident lookup calls the backend's own GET /api/incidents/{id} over loopback, which would
deadlock inside an `async def` handler on a single worker. M3 may instead call
`configure(incident_lookup=fn)` where fn(incident_id) -> src_ip string or None.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

PREVIEW_TTL_SECONDS = 60
DEFAULT_BLOCK_TTL = 120
MIN_BLOCK_TTL, MAX_BLOCK_TTL = 10, 600
ACTIVE = ("applied", "verified")
SCOPE = "web-decoy-01 only"
NEVER_BLOCK = {"192.168.77.20", "127.0.0.1", "0.0.0.0"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _parse_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _valid_single_ipv4(value: Any) -> Optional[str]:
    """Return the canonical string for one IPv4 host address, else None. Rejects ranges and CIDR."""
    if not isinstance(value, str) or "/" in value or " " in value:
        return None
    try:
        addr = ipaddress.IPv4Address(value.strip())
    except ValueError:
        return None
    return str(addr)


class ResponseService:
    def __init__(
        self,
        state_dir: str,
        allowed_ips: List[str],
        incident_lookup: Callable[[str], Optional[str]],
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        live_context: Optional[Callable[[], Dict[str, Any]]] = None,
    ):
        self.state_dir = state_dir
        self.blocklist_path = os.path.join(state_dir, "blocklist.json")
        self.actions_path = os.path.join(state_dir, "response-actions.json")
        self.verification_audit_path = os.path.join(state_dir, "response-verification-audit.jsonl")
        safe = []
        for ip in allowed_ips:
            canon = _valid_single_ipv4(ip)
            if canon and canon not in NEVER_BLOCK and not ipaddress.IPv4Address(canon).is_loopback:
                safe.append(canon)
        self.allowed_ips = safe
        self.incident_lookup = incident_lookup
        self.now = now
        self.live_context = live_context or (lambda: {})
        self._lock = threading.RLock()
        self._previews: Dict[str, Dict[str, Any]] = {}
        self._actions: Dict[str, Dict[str, Any]] = {}
        self._version = 0
        self._load()

    # ---- persistence -------------------------------------------------
    def _atomic_write(self, path: str, data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o644)  # web decoy runs as another uid and mounts this read-only
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _load(self) -> None:
        changed = False
        try:
            with open(self.actions_path, "r", encoding="utf-8") as fh:
                saved = json.load(fh)
            actions = saved.get("actions", {})
            self._actions = actions if isinstance(actions, dict) else {}
            self._version = int(saved.get("version", 0))
        except (OSError, ValueError, AttributeError, TypeError):
            pass
        policy_entries = []
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as fh:
                policy = json.load(fh)
            self._version = max(self._version, int(policy.get("version", 0)))
            policy_entries = policy.get("entries", []) if isinstance(policy.get("entries", []), list) else []
        except (OSError, ValueError, AttributeError, TypeError):
            pass
        entries_by_id = {e.get("action_id"): e for e in policy_entries
                         if isinstance(e, dict) and isinstance(e.get("action_id"), str)}
        for action_id, action in self._actions.items():
            if not isinstance(action, dict) or action.get("status") not in ACTIVE:
                continue
            entry = entries_by_id.get(action_id)
            if not entry or entry.get("ip") != action.get("target_ip") or entry.get("expires_at") != action.get("until"):
                action["status"] = "reconciliation_required"
                action.setdefault("verification_mismatches", []).append({"event_id": None,
                    "received_at": _iso(self.now()), "reason": "active_action_missing_or_changed_in_policy_after_restart"})
                changed = True
        now = self.now()
        for action_id, entry in entries_by_id.items():
            if action_id in self._actions:
                continue
            try:
                expiry, created = _parse(entry["expires_at"]), _parse(entry["created_at"])
            except (KeyError, TypeError, ValueError):
                continue
            if expiry <= now:
                continue
            target = _valid_single_ipv4(entry.get("ip"))
            revision = entry.get("policy_revision")
            if target not in self.allowed_ips or entry.get("capture_mode") != "live":
                continue
            if not isinstance(revision, int) or isinstance(revision, bool):
                continue
            self._actions[action_id] = {"action_id": action_id, "target_ip": target, "status": "applied",
                "reason": "recovered from enforcement policy after restart", "created_at": _iso(created),
                "until": _iso(expiry), "verified_by_event_id": None, "incident_id": None,
                "lab_run_id": entry.get("lab_run_id"), "capture_mode": "live", "policy_revision": revision,
                "recovered_after_restart": True}
            changed = True
        if changed:
            self._write_state()

    def _write_state(self) -> None:
        """Blocklist first (enforcement), then the action record."""
        self._version += 1
        entries = [
            {"ip": a["target_ip"], "action_id": a["action_id"], "expires_at": a["until"],
             "policy_revision": a["policy_revision"], "created_at": a["created_at"],
             "lab_run_id": a["lab_run_id"], "capture_mode": a["capture_mode"]}
            for a in self._actions.values()
            if a["status"] in ACTIVE
        ]
        self._atomic_write(self.blocklist_path, {"version": self._version, "entries": entries})
        self._atomic_write(self.actions_path, {"version": self._version, "actions": self._actions})

    # ---- lifecycle ---------------------------------------------------
    def expire(self) -> None:
        with self._lock:
            now = self.now()
            changed = False
            for a in self._actions.values():
                if a["status"] in ACTIVE and _parse(a["until"]) <= now:
                    a["status"] = "expired"
                    changed = True
            for pid in [p for p, v in self._previews.items() if v["expires_at"] <= now]:
                del self._previews[pid]
            if changed:
                self._write_state()

    def preview(self, incident_id: Any, ttl: Any) -> Dict[str, Any]:
        if not isinstance(incident_id, str) or not incident_id.strip() or len(incident_id) > 64:
            raise ApiError(400, "invalid_request", "incident_id is required")
        if ttl is None:
            ttl = DEFAULT_BLOCK_TTL
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not MIN_BLOCK_TTL <= ttl <= MAX_BLOCK_TTL:
            raise ApiError(400, "invalid_request", f"ttl_seconds must be an integer {MIN_BLOCK_TTL} to {MAX_BLOCK_TTL}")
        context = self.live_context()
        if context.get("capture_mode", "live") != "live":
            raise ApiError(409, "not_live", "response previews are available only during a live run")
        run_id = context.get("lab_run_id")
        if not isinstance(run_id, str) or not run_id:
            raise ApiError(409, "run_unavailable", "live lab run context is unavailable")
        src = self.incident_lookup(incident_id)
        if src is None:
            raise ApiError(404, "not_found", "incident not found")
        target = _valid_single_ipv4(src)
        if target is None or target not in self.allowed_ips:
            raise ApiError(400, "target_not_allowed", "target is not an allowed lab attacker IP")
        with self._lock:
            self.expire()
            now = self.now()
            preview_id = "prv_" + secrets.token_hex(6)
            expires = now + timedelta(seconds=PREVIEW_TTL_SECONDS)
            self._previews[preview_id] = {"incident_id": incident_id, "target_ip": target, "ttl": ttl,
                "expires_at": expires, "lab_run_id": run_id,
                "policy_revision": self._current_policy_version()}
            return {"preview_id": preview_id, "target_ip": target, "scope": SCOPE, "ttl_seconds": ttl, "expires_at": _iso(expires)}

    def apply(self, preview_id: Any, reason: Any, confirm: Any) -> Dict[str, Any]:
        if confirm is not True:
            raise ApiError(400, "confirmation_required", "confirm must be true")
        if not isinstance(reason, str) or len(reason.strip()) < 5 or len(reason) > 500:
            raise ApiError(400, "invalid_request", "reason must be 5 to 500 characters")
        with self._lock:
            self.expire()
            pv = self._previews.get(preview_id) if isinstance(preview_id, str) else None
            if pv is None:
                raise ApiError(400, "preview_invalid", "preview not found or expired; request a new preview")
            target = pv["target_ip"]
            if target not in self.allowed_ips:  # re-check at apply time
                raise ApiError(400, "target_not_allowed", "target is not an allowed lab attacker IP")
            context = self.live_context()
            if context.get("capture_mode", "live") != "live":
                raise ApiError(409, "not_live", "response actions are available only during a live run")
            run_id = context.get("lab_run_id")
            if not isinstance(run_id, str) or not run_id:
                raise ApiError(409, "run_unavailable", "live lab run context is unavailable")
            if run_id != pv["lab_run_id"] or self._current_policy_version() != pv["policy_revision"]:
                raise ApiError(409, "preview_stale", "run or policy changed; request a new preview")
            policy_revision = max(self._version, self._current_policy_version()) + 1
            if any(a["target_ip"] == target and a["status"] in ACTIVE for a in self._actions.values()):
                raise ApiError(409, "already_blocked", "an active block already exists for this IP")
            del self._previews[preview_id]  # single use
            now = self.now()
            until = now + timedelta(seconds=pv["ttl"])
            action_id = "act_" + secrets.token_hex(4)
            self._actions[action_id] = {
                "action_id": action_id, "target_ip": target, "status": "applied", "reason": reason.strip(),
                "created_at": _iso(now), "until": _iso(until), "verified_by_event_id": None,
                "incident_id": pv["incident_id"], "lab_run_id": run_id,
                "capture_mode": "live", "policy_revision": policy_revision,
            }
            self._write_state()
            return {"action_id": action_id, "status": "applied", "until": _iso(until)}

    def revoke(self, action_id: str) -> Dict[str, Any]:
        with self._lock:
            self.expire()
            a = self._actions.get(action_id)
            if a is None:
                raise ApiError(404, "not_found", "action not found")
            if a["status"] not in ACTIVE:
                raise ApiError(409, "not_active", f"action is already {a['status']}")
            a["status"] = "revoked"
            self._write_state()
            return {"action_id": action_id, "status": "revoked"}

    def list_actions(self) -> Dict[str, Any]:
        with self._lock:
            self.expire()
            items = [
                {k: a[k] for k in ("action_id", "target_ip", "status", "reason", "created_at", "until", "verified_by_event_id")}
                | {"verification_mismatches": a.get("verification_mismatches", [])}
                for a in sorted(self._actions.values(), key=lambda x: x["created_at"], reverse=True)
            ]
            return {"items": items}

    def on_event(self, event: Any, trusted_context: Optional[Dict[str, Any]] = None) -> None:
        """Verify only a trusted, persisted blocked_request matching the full enforcement context.

        `trusted_context` is populated by the backend after commit. In particular, received_at must
        be the backend's own timestamp, never a field copied from the sensor payload.
        """
        get = event.get if isinstance(event, dict) else lambda k, d=None: getattr(event, k, d)
        if get("event_type") != "blocked_request":
            return
        attrs = get("attributes") or {}
        attrs = attrs if isinstance(attrs, dict) else getattr(attrs, "__dict__", {})
        action_id = attrs.get("block_action_id")
        context = trusted_context if isinstance(trusted_context, dict) else {}
        sensor_id = get("sensor_id")
        src_ip = get("src_ip")
        run_id = get("lab_run_id")
        capture_mode = get("capture_mode")
        event_time = get("occurred_at")
        revision = attrs.get("policy_revision")
        event_id = get("event_id")
        with self._lock:
            a = self._actions.get(action_id) if isinstance(action_id, str) else None
            if a is None:
                self._write_unmatched_verification(event_id, action_id, context)
                return
            if a is not None:
                now = self.now()
                try:
                    occurred = _parse(event_time) if isinstance(event_time, str) else None
                    received = _parse(context.get("received_at")) if isinstance(context.get("received_at"), str) else None
                    action_created = _parse(a["created_at"])
                    action_until = _parse(a["until"])
                except (TypeError, ValueError):
                    occurred = received = action_created = action_until = None
                live = self.live_context()
                valid = (
                    a["status"] == "applied"
                    and sensor_id == "web-decoy-01" and src_ip == a["target_ip"]
                    and run_id == a["lab_run_id"] and run_id == live.get("lab_run_id")
                    and capture_mode == "live" and a.get("capture_mode") == "live"
                    and live.get("capture_mode", "live") == "live"
                    and revision == a.get("policy_revision") == self._policy_revision(action_id)
                    and occurred is not None and received is not None
                    and context.get("source") == "backend_ingest"
                    and context.get("persisted_event_id") == event_id
                    and action_created is not None and action_until is not None
                    and action_created <= occurred <= action_until
                    and action_created <= received <= action_until
                    and now <= action_until
                    and isinstance(event_id, str) and bool(event_id)
                )
                if not valid:
                    # Keep a rejected verification attempt visible in the durable audit trail.
                    a.setdefault("verification_mismatches", []).append({
                        "event_id": event_id if isinstance(event_id, str) else None,
                        "received_at": context.get("received_at"),
                        "reason": "verification_context_mismatch",
                    })
                    self._atomic_write(self.actions_path, {"version": self._version, "actions": self._actions})
                    return
                a["status"] = "verified"
                a["verified_by_event_id"] = event_id
                self._atomic_write(self.actions_path, {"version": self._version, "actions": self._actions})

    def _write_unmatched_verification(self, event_id: Any, action_id: Any, context: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.verification_audit_path), exist_ok=True)
        record = {"event_id": event_id if isinstance(event_id, str) else None,
                  "block_action_id": action_id[:128] if isinstance(action_id, str) else None,
                  "received_at": context.get("received_at") if isinstance(context.get("received_at"), str) else None,
                  "reason": "unknown_action_id"}
        with open(self.verification_audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _policy_revision(self, action_id: str) -> Optional[int]:
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            entry = next((item for item in data.get("entries", [])
                          if isinstance(item, dict) and item.get("action_id") == action_id), None)
            value = entry.get("policy_revision") if entry else None
            return value if isinstance(value, int) and not isinstance(value, bool) else None
        except (OSError, ValueError, AttributeError):
            return None

    def _current_policy_version(self) -> int:
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as fh:
                value = json.load(fh).get("version", 0)
            return value if isinstance(value, int) and not isinstance(value, bool) else 0
        except (OSError, ValueError, AttributeError):
            return self._version


# ---- default wiring --------------------------------------------------
def _default_lookup_factory(backend_url: str) -> Callable[[str], Optional[str]]:
    def lookup(incident_id: str) -> Optional[str]:
        safe = urllib.parse.quote(incident_id, safe="")
        try:
            with urllib.request.urlopen(f"{backend_url}/api/incidents/{safe}", timeout=3) as resp:
                return json.load(resp).get("src_ip")
        except (urllib.error.URLError, OSError, ValueError):
            return None
    return lookup


_service: Optional[ResponseService] = None
_service_lock = threading.Lock()


def configure(state_dir: Optional[str] = None, env_file: Optional[str] = None,
              incident_lookup: Optional[Callable[[str], Optional[str]]] = None,
              now: Optional[Callable[[], datetime]] = None,
              live_context: Optional[Callable[[], Dict[str, Any]]] = None) -> ResponseService:
    """Build the service. Defaults read deployment/lab.env and use deployment/state."""
    global _service
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = _parse_env_file(env_file or os.path.join(root, "deployment", "lab.env"))
    allowed = [x.strip() for x in env.get("ATTACKER_IPS", "192.168.77.10").split(",") if x.strip()]
    backend = env.get("BACKEND_URL", "http://127.0.0.1:8000")
    run_id = env.get("LAB_RUN_ID", "run-01")
    with _service_lock:
        _service = ResponseService(
            state_dir or os.path.join(root, "deployment", "state"), allowed,
            incident_lookup or _default_lookup_factory(backend), now or (lambda: datetime.now(timezone.utc)),
            live_context or (lambda: {"lab_run_id": run_id, "capture_mode": env.get("CAPTURE_MODE", "live")}),
        )
    return _service


def _svc() -> ResponseService:
    return _service or configure()


def _run(fn: Callable[[], Dict[str, Any]], ok: int = 200) -> JSONResponse:
    try:
        return JSONResponse(fn(), status_code=ok)
    except ApiError as e:
        return JSONResponse({"error": {"code": e.code, "message": e.message}}, status_code=e.status)


router = APIRouter()


@router.post("/preview")
def preview(body: Any = Body(default=None)):
    b = body if isinstance(body, dict) else {}
    return _run(lambda: _svc().preview(b.get("incident_id"), b.get("ttl_seconds")))


@router.post("/apply")
def apply(body: Any = Body(default=None)):
    b = body if isinstance(body, dict) else {}
    return _run(lambda: _svc().apply(b.get("preview_id"), b.get("reason"), b.get("confirm")))


@router.post("/{action_id}/revoke")
def revoke(action_id: str, body: Any = Body(default=None)):
    return _run(lambda: _svc().revoke(action_id))


@router.get("/actions")
def actions():
    return _run(lambda: _svc().list_actions())


def on_event(event: Any, trusted_context: Optional[Dict[str, Any]] = None) -> None:
    _svc().on_event(event, trusted_context)
