"""Pydantic v2 models matching contracts/event.schema.json (schema 1.0, 1.1 and 1.2) and
contracts/telemetry.schema.json (gateway and demo-app telemetry 1.0).

schema_version picks the attribute rules: 1.0 events keep the 1.0 rules (unknown
attributes pass through untyped), 1.1 events get the 1.1 typed fields, and only 1.2 events
may name the MySQL and SMB honeypots or carry the v1.2 fields.
"""
import json
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, ValidationInfo, field_validator, model_validator

SensorId = Literal["ssh-decoy-01", "web-decoy-01", "db-decoy-01", "file-decoy-01"]
TelemetrySourceId = Literal["gateway-01", "demo-app-01"]
EventType = Literal[
    "connection_open", "auth_failure", "auth_success", "command_input",
    "connection_close", "http_request", "synthetic_file_access", "blocked_request",
    "bait_served", "db_request", "file_operation",
]
V11_SENSORS = ("ssh-decoy-01", "web-decoy-01")
V12_EVENT_TYPES = ("db_request", "file_operation")
# contracts/sources.json: what each v1.2 honeypot may send, and the protocol it speaks.
SENSOR_EVENT_TYPES = {
    "db-decoy-01": ("connection_open", "auth_failure", "auth_success", "db_request", "connection_close"),
    "file-decoy-01": ("connection_open", "auth_failure", "auth_success", "file_operation",
                      "synthetic_file_access", "bait_served", "connection_close"),
}
SENSOR_PROTOCOL = {"db-decoy-01": "mysql", "file-decoy-01": "smb"}
EVENT_OWNER = {"db_request": "db-decoy-01", "file_operation": "file-decoy-01"}
Indicator = Literal[
    "sql_quote", "sql_keyword", "sql_comment",
    "sql_quote_breakout", "sql_union_select", "sql_tautology", "sql_stacked_query", "sql_time_function",
    "script_tag", "event_handler", "js_scheme",
    "path_traversal", "sensitive_file_path", "php_wrapper", "remote_url_in_param",
    "shell_metachar_command", "command_substitution", "null_byte", "encoded_payload",
]

MAX_ATTR_KEYS = 32
MAX_ATTR_BYTES = 16 * 1024


class Attributes(BaseModel):
    """1.0 attribute rules. additionalProperties is true in the schema; extras are kept but bounded."""
    model_config = ConfigDict(extra="allow")

    username: Optional[str] = Field(None, max_length=128)
    password_sha256: Optional[str] = Field(None, max_length=128)
    client_version: Optional[str] = Field(None, max_length=256)
    command: Optional[str] = Field(None, max_length=4096)
    method: Optional[str] = Field(None, max_length=32)
    path: Optional[str] = Field(None, max_length=4096)
    query_redacted: Optional[str] = Field(None, max_length=4096)
    user_agent: Optional[str] = Field(None, max_length=512)
    status_code: Optional[int] = None
    response_class: Optional[Literal["normal", "fake_error", "fake_data", "blocked"]] = None
    honeytoken_id: Optional[str] = Field(None, max_length=128)
    asset_id: Optional[str] = Field(None, max_length=128)
    size_bytes: Optional[int] = None
    sha256: Optional[str] = Field(None, max_length=128)
    outcome: Optional[Literal["served", "denied", "not_found"]] = None
    block_action_id: Optional[str] = Field(None, max_length=128)

    @model_validator(mode="after")
    def _bounded_and_no_raw_secrets(self) -> "Attributes":
        data = self.model_dump(exclude_none=True)
        # Raw passwords must never reach storage: only password_sha256 is allowed.
        for key in data:
            k = key.lower()
            if k != "password_sha256" and ("pass" in k or "secret" in k):
                raise ValueError(f"attribute '{key}' looks like a raw secret; send a hash only")
        if len(data) > MAX_ATTR_KEYS:
            raise ValueError(f"more than {MAX_ATTR_KEYS} attributes")
        if len(json.dumps(data, default=str)) > MAX_ATTR_BYTES:
            raise ValueError("attributes too large")
        return self


class InputFeatures(BaseModel):
    """M4's sanitised description of client input. Never values."""
    model_config = ConfigDict(extra="forbid")

    source: Literal["query", "form", "json", "multipart", "none"]
    field_count: int = Field(ge=0, le=256)
    field_names: list[str] = Field(default_factory=list, max_length=32)
    max_value_length: Optional[int] = Field(None, ge=0)
    indicators: list[Indicator] = Field(max_length=16)
    truncated: bool = False

    @field_validator("field_names")
    @classmethod
    def _short_names(cls, v: list[str]) -> list[str]:
        if any(len(name) > 64 for name in v):
            raise ValueError("field names are at most 64 characters")
        return v

    @field_validator("indicators")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("indicators must be unique")
        return v


class Processing(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parse_status: Literal["parsed", "no_body", "rejected_too_large", "unsupported_type", "malformed"]
    body_bytes: Optional[int] = Field(None, ge=0)
    body_consumed: Optional[bool] = None
    redaction_version: Optional[str] = Field(None, max_length=32)
    producer_version: Optional[str] = Field(None, max_length=32)


class AttributesV11(Attributes):
    """1.1 attribute rules: the 1.0 fields, tighter, plus the new evidence fields."""

    method: Optional[str] = Field(None, max_length=16)
    sha256: Optional[str] = Field(None, max_length=64)
    size_bytes: Optional[int] = Field(None, ge=0)
    block_action_id: Optional[str] = Field(None, max_length=64)
    outcome: Optional[Literal["served", "denied", "not_found", "attempted",
                              "emulated_success", "failed", "unknown"]] = None
    policy_revision: Optional[int] = Field(None, ge=0)
    observation_kind: Optional[Literal["network_input", "command_input", "emulated_result", "policy_result"]] = None
    evidence_role: Optional[Literal["request", "result", "bait"]] = None
    request_id: Optional[str] = Field(None, max_length=64)
    honeytoken_ids: Optional[list[str]] = Field(None, min_length=1, max_length=16)
    issuance_id: Optional[str] = Field(None, max_length=64)
    issued_expires_at: Optional[datetime] = None
    evidence_basis: Optional[Literal["sensor_response", "session_output_log"]] = None
    requested_asset_id: Optional[str] = Field(None, max_length=128)
    fixture_version: Optional[str] = Field(None, max_length=32)
    digest_scope: Optional[Literal["full_response", "full_sanitised_response", "full_asset", "partial"]] = None
    input_features: Optional[InputFeatures] = None
    processing: Optional[Processing] = None

    @field_validator("honeytoken_ids")
    @classmethod
    def _ids(cls, v):
        if v is not None and (len(set(v)) != len(v) or any(len(t) > 128 for t in v)):
            raise ValueError("honeytoken_ids must be unique ids of at most 128 characters")
        return v


GATEWAY_REQUEST_ID = r"^gw_[A-Za-z0-9_-]{8,64}$"
GATEWAY_SESSION_REF = r"^gws_[0-9a-f]{16,64}$"
SHA256_HEX = r"^[0-9a-f]{64}$"
ContextState = Literal["verified", "absent", "invalid"]
InvalidReason = Literal["bad_signature", "expired", "wrong_run", "wrong_upstream", "malformed"]


def _context_rules(state, request_id, session_ref, invalid_reason):
    """Only an upstream's own verification of the signed header may name a gateway request."""
    if state == "verified" and request_id is None:
        raise ValueError("a verified gateway context names its gateway_request_id")
    if state != "verified" and (request_id is not None or session_ref is not None):
        raise ValueError("only a verified gateway context may name a gateway request or session")
    if invalid_reason is not None and state != "invalid":
        raise ValueError("invalid_reason only with gateway_context 'invalid'")


class Ingress(BaseModel):
    model_config = ConfigDict(extra="forbid")
    gateway_context: ContextState
    gateway_request_id: Optional[str] = Field(None, pattern=GATEWAY_REQUEST_ID)
    gateway_session_ref: Optional[str] = Field(None, pattern=GATEWAY_SESSION_REF)
    invalid_reason: Optional[InvalidReason] = None

    @model_validator(mode="after")
    def _trust(self) -> "Ingress":
        _context_rules(self.gateway_context, self.gateway_request_id, self.gateway_session_ref, self.invalid_reason)
        return self


class Credential(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: Literal["mysql_native_password", "caching_sha2_password", "ntlmv2", "ntlmv1",
                    "smb_anonymous", "smb_guest", "other"]
    proof_check: Literal["matched_honeytoken", "not_matched", "not_checked", "unsupported_scheme", "malformed"]
    verifier_version: Optional[str] = Field(None, max_length=32)


class DbRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: Literal["COM_QUERY", "COM_INIT_DB", "COM_PING", "COM_QUIT", "COM_FIELD_LIST",
                     "COM_STMT_PREPARE", "COM_STMT_EXECUTE", "other"]
    statement_verb: Optional[Literal["select", "show", "insert", "update", "delete", "drop", "create", "use",
                                     "set", "load", "other", "none"]] = None
    length_bytes: Optional[int] = Field(None, ge=0, le=16777215)
    schema_name: Optional[str] = Field(None, max_length=64)
    execution: Literal["not_supported"]
    error_code: Optional[int] = Field(None, ge=0, le=65535)


class FileOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["tree_connect", "list", "open", "read", "write", "create", "delete", "rename", "close"]
    share: str = Field(max_length=80)
    path: Optional[str] = Field(None, max_length=1024)
    bytes: Optional[int] = Field(None, ge=0)
    content_sha256: Optional[str] = Field(None, pattern=SHA256_HEX)
    digest_scope: Optional[Literal["full_content", "partial", "none"]] = None
    storage: Optional[Literal["quarantined_inert", "discarded", "not_applicable"]] = None
    magic_type_hint: Optional[Literal["text", "csv", "zip", "pe", "elf", "script", "office", "pdf", "unknown"]] = None


class ArchiveEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(txt|csv)$")
    size_bytes: int = Field(ge=0, le=1048576)
    sha256: str = Field(pattern=SHA256_HEX)
    honeytoken_ids: list[str] = Field(default_factory=list, max_length=16)


class Archive(BaseModel):
    """Inert archive lure: plain text and CSV only, never executable or auto-run."""
    model_config = ConfigDict(extra="forbid")
    format: Literal["zip"]
    compression: Optional[Literal["stored", "deflate"]] = None
    entries: list[ArchiveEntry] = Field(min_length=1, max_length=16)
    contains_executable: Literal[False]
    auto_run: Literal[False]


class Transfer(BaseModel):
    """The serving sensor's own side only. body_written is not client receipt or extraction."""
    model_config = ConfigDict(extra="forbid")
    response_status: Optional[int] = Field(None, ge=100, le=599)
    content_length: Optional[int] = Field(None, ge=0)
    bytes_written: Optional[int] = Field(None, ge=0)
    completion: Literal["body_written", "aborted", "headers_only", "unknown"]


VERDICT_WORDS = ("verdict", "malware", "malicious")


class AttributesV12(AttributesV11):
    """1.2 attribute rules: every 1.1 rule plus the four-honeypot fields."""

    protocol: Optional[Literal["ssh", "http", "mysql", "smb"]] = None
    ingress: Optional[Ingress] = None
    credential: Optional[Credential] = None
    db: Optional[DbRequest] = None
    file: Optional[FileOperation] = None
    archive: Optional[Archive] = None
    transfer: Optional[Transfer] = None

    @model_validator(mode="after")
    def _v12_attribute_rules(self) -> "AttributesV12":
        for key in self.model_dump(exclude_none=True):
            if any(w in key.lower() for w in VERDICT_WORDS):
                raise ValueError(f"attribute '{key}': a record never carries a malware verdict")
        if self.credential is not None:
            matched = self.credential.proof_check == "matched_honeytoken"
            if matched and self.honeytoken_id is None:
                raise ValueError("credential: a matched proof names its honeytoken_id")
            if not matched and self.honeytoken_id is not None:
                raise ValueError("honeytoken_id: only a proof verified against a planted credential names a token")
        return self


class IngestEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0", "1.1", "1.2"]
    source_record_id: str = Field(min_length=1, max_length=128)
    origin_record_id: Optional[str] = Field(None, max_length=128)
    sensor_id: SensorId
    event_type: EventType
    occurred_at: datetime
    src_ip: str
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    session_id: Optional[str] = Field(None, max_length=128)
    lab_run_id: str = Field(min_length=1, max_length=128)
    capture_mode: Literal["live", "replay"]
    attributes: Attributes = Field(default_factory=Attributes)

    @field_validator("src_ip")
    @classmethod
    def _ipv4(cls, v: str) -> str:
        try:
            return str(IPv4Address(v))
        except ValueError:
            raise ValueError("not an ipv4") from None

    @field_validator("occurred_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must include a timezone (use UTC)")
        return v.astimezone(timezone.utc)

    @field_validator("attributes", mode="before")
    @classmethod
    def _version_rules(cls, v: Any, info: ValidationInfo):
        if v is None:
            v = {}
        if isinstance(v, BaseModel):
            return v
        version = info.data.get("schema_version")
        if version == "1.2":
            return AttributesV12.model_validate(v)
        if version == "1.1":
            return AttributesV11.model_validate(v)
        return v

    @model_validator(mode="after")
    def _evidence_rules(self) -> "IngestEvent":
        a = self.attributes
        if self.schema_version != "1.2":
            if self.sensor_id not in V11_SENSORS:
                raise ValueError(f"sensor_id: {self.sensor_id} needs schema_version 1.2")
            if self.event_type in V12_EVENT_TYPES:
                raise ValueError(f"event_type: {self.event_type} needs schema_version 1.2")
        else:
            self._v12_rules(a)
        if self.schema_version == "1.0":
            if self.event_type == "bait_served":
                raise ValueError("event_type: bait_served needs schema_version 1.1")
            if "origin_record_id" in self.model_fields_set:
                raise ValueError("origin_record_id: needs schema_version 1.1")
            return self
        if self.capture_mode == "live" and self.origin_record_id is not None:
            raise ValueError("origin_record_id: only replay events copy an original record")
        if self.event_type == "bait_served":
            missing = [k for k in ("asset_id", "honeytoken_ids", "issuance_id", "evidence_basis")
                       if getattr(a, k, None) is None]
            if missing:
                raise ValueError(f"attributes: bait_served needs {', '.join(missing)}")
            if a.evidence_role not in (None, "bait"):
                raise ValueError("attributes.evidence_role: bait_served is bait evidence")
        return self

    def _v12_rules(self, a: "AttributesV12") -> None:
        allowed = SENSOR_EVENT_TYPES.get(self.sensor_id)
        if allowed is not None:
            if self.event_type not in allowed:
                raise ValueError(f"event_type: {self.sensor_id} does not send {self.event_type}")
            if a.protocol != SENSOR_PROTOCOL[self.sensor_id]:
                raise ValueError(f"attributes.protocol: {self.sensor_id} speaks {SENSOR_PROTOCOL[self.sensor_id]}")
            if a.password_sha256 is not None:
                raise ValueError("attributes.password_sha256: a challenge-response decoy never sees the password")
            if a.ingress is not None:
                raise ValueError("attributes.ingress: the HTTP gateway never proxies MySQL or SMB")
            if self.event_type in ("auth_failure", "auth_success") and a.credential is None:
                raise ValueError("attributes.credential: a challenge-response login carries a proof record")
        elif self.event_type in V12_EVENT_TYPES:
            raise ValueError(f"event_type: {self.event_type} belongs to {EVENT_OWNER[self.event_type]}")
        if self.event_type == "db_request" and a.db is None:
            raise ValueError("attributes.db: db_request needs its command metadata")
        if self.event_type == "file_operation" and a.file is None:
            raise ValueError("attributes.file: file_operation needs its operation metadata")


# Derived when a producer omits them (contracts/API.md, "Request, result and bait evidence").
OBSERVATION_KIND = {
    "connection_open": "network_input", "auth_failure": "network_input", "auth_success": "network_input",
    "http_request": "network_input", "connection_close": "network_input",
    "command_input": "command_input",
    "synthetic_file_access": "emulated_result", "bait_served": "emulated_result",
    "blocked_request": "policy_result",
    "db_request": "network_input", "file_operation": "emulated_result",
}
EVIDENCE_ROLE = {"network_input": "request", "command_input": "request",
                 "emulated_result": "result", "policy_result": "result"}


def observation_kind(event_type: str, attributes: dict) -> str:
    given = attributes.get("observation_kind")
    return given if isinstance(given, str) and given in EVIDENCE_ROLE else OBSERVATION_KIND[event_type]


def evidence_role(event_type: str, attributes: dict) -> str:
    if event_type == "bait_served":
        return "bait"
    given = attributes.get("evidence_role")
    if isinstance(given, str) and given in ("request", "result", "bait"):
        return given
    return EVIDENCE_ROLE[observation_kind(event_type, attributes)]


MAX_COUNT = 10 ** 9


class HeartbeatCounters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accepted: Optional[int] = Field(None, ge=0, le=MAX_COUNT, strict=True)
    duplicate: Optional[int] = Field(None, ge=0, le=MAX_COUNT, strict=True)
    rejected: int = Field(0, ge=0, le=MAX_COUNT, strict=True)
    quarantined: int = Field(0, ge=0, le=MAX_COUNT, strict=True)
    retry: Optional[int] = Field(None, ge=0, le=MAX_COUNT, strict=True)


class Heartbeat(BaseModel):
    """Canonical M2 heartbeat; the earlier flat-counter form remains readable."""
    model_config = ConfigDict(extra="forbid")

    collector_id: str = Field(min_length=1, max_length=64)
    sensor_id: Optional[SensorId] = None
    source_id: Optional[TelemetrySourceId] = None  # v1.2: gateway and demo app report here, never as sensors
    sent_at: datetime
    process_state: Literal["running", "stopped", "unknown"]
    last_read_at: Optional[datetime] = None
    last_ingest_at: Optional[datetime] = None
    backlog_records: Optional[int] = Field(None, ge=0, le=MAX_COUNT, strict=True)
    oldest_backlog_age_s: Optional[float] = Field(None, ge=0, le=MAX_COUNT)
    error_count: int = Field(0, ge=0, le=MAX_COUNT, strict=True)
    ingest: HeartbeatCounters

    @model_validator(mode="before")
    @classmethod
    def _wire_compatibility(cls, value):
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if (data.get("sensor_id") is None) == (data.get("source_id") is None):
            raise ValueError("heartbeat names exactly one of sensor_id and source_id")
        if "sensor_process" in data:
            if any(k in data for k in ("process_state", "last_ingest_at", "backlog_records", "error_count", "ingest")):
                raise ValueError("heartbeat must use one wire format")
            state = data.pop("sensor_process")
            if state not in ("up", "down", "unknown"):
                raise ValueError("invalid sensor_process")
            data["process_state"] = {"up": "running", "down": "stopped", "unknown": "unknown"}[state]
            data["last_ingest_at"] = data.pop("last_ingest_ok_at", None)
            data["backlog_records"] = data.pop("backlog_lines", None)
            data["error_count"] = data.pop("errors_total", 0)
            data["ingest"] = {"accepted": None, "duplicate": None, "retry": None,
                "rejected": data.pop("rejected_total", 0), "quarantined": data.pop("quarantined_total", 0)}
        else:
            counts = data.get("ingest")
            required = {"accepted", "duplicate", "rejected", "quarantined", "retry"}
            if not isinstance(counts, dict) or not required <= counts.keys() or any(counts[k] is None for k in required):
                raise ValueError("heartbeat ingest needs all five counters")
        return data

    @field_validator("sent_at", "last_read_at", "last_ingest_at")
    @classmethod
    def _aware(cls, v):
        if v is not None and v.tzinfo is None:
            raise ValueError("timestamp needs a UTC offset")
        return v


# ---- telemetry (contracts/telemetry.schema.json): gateway and demo app, never events ----
RouteReason = Literal["no_trigger", "session_pinned", "source_pinned", "web_attack_indicator", "hidden_path_probe",
                      "bait_path_requested", "honeytoken_presented", "manual_lab_rule"]
WebClass = Literal["sqli", "xss", "lfi", "rfi", "cmd_injection"]
HTTP_PATH = r"^/[^?#]*$"


def _ipv4(v: str) -> str:
    try:
        return str(IPv4Address(v))
    except ValueError:
        raise ValueError("not an ipv4") from None


class Pin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["none", "session", "source_ip"]
    pinned_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class RouteDecision(BaseModel):
    """The gateway's requested routing, decided before any upstream handles the request."""
    model_config = ConfigDict(extra="forbid")
    gateway_request_id: str = Field(pattern=GATEWAY_REQUEST_ID)
    client_ip: str
    client_port: Optional[int] = Field(None, ge=0, le=65535)
    gateway_session_ref: Optional[str] = Field(pattern=GATEWAY_SESSION_REF)
    method: str = Field(max_length=16)
    path: str = Field(max_length=2048, pattern=HTTP_PATH)
    query_redacted: Optional[str] = Field(None, max_length=2048)
    decision: Literal["normal_app", "decoy"]
    upstream_id: Literal["demo-app-01", "web-decoy-01"]
    reasons: list[RouteReason] = Field(min_length=1, max_length=8)
    indicator_classes: Optional[list[WebClass]] = Field(None, max_length=5)
    routing_policy_id: str = Field(min_length=1, max_length=64)
    routing_policy_revision: int = Field(ge=0)
    pin: Pin
    decided_before_upstream: Literal[True]

    _ip = field_validator("client_ip")(lambda cls, v: _ipv4(v))

    @model_validator(mode="after")
    def _consistent(self) -> "RouteDecision":
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("reasons must be unique")
        if self.decision == "normal_app":
            if self.upstream_id != "demo-app-01" or self.reasons != ["no_trigger"] or self.pin.scope != "none":
                raise ValueError("decision: normal_app goes to demo-app-01, with reason no_trigger and no pin")
        elif self.upstream_id != "web-decoy-01" or "no_trigger" in self.reasons:
            raise ValueError("decision: decoy goes to web-decoy-01 with a trigger reason")
        if "web_attack_indicator" in self.reasons and not self.indicator_classes:
            raise ValueError("indicator_classes: web_attack_indicator names its classes")
        return self


class UpstreamResult(BaseModel):
    """What the gateway saw come back; not the upstream's own record."""
    model_config = ConfigDict(extra="forbid")
    gateway_request_id: str = Field(pattern=GATEWAY_REQUEST_ID)
    upstream_id: Literal["demo-app-01", "web-decoy-01"]
    outcome: Literal["response_received", "connect_error", "timeout", "aborted"]
    status_code: Optional[int] = Field(None, ge=100, le=599)
    response_bytes: Optional[int] = Field(None, ge=0)
    elapsed_ms: Optional[int] = Field(None, ge=0)

    @model_validator(mode="after")
    def _status(self) -> "UpstreamResult":
        if self.outcome == "response_received" and self.status_code is None:
            raise ValueError("status_code: a received response has a status")
        return self


class AppLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Optional[str] = Field(None, max_length=64)
    outcome: Literal["failed", "emulated_success"]


class AppRequest(BaseModel):
    """The normal demo app's own handling record."""
    model_config = ConfigDict(extra="forbid")
    app_request_id: str = Field(min_length=1, max_length=64)
    gateway_context: ContextState
    gateway_request_id: Optional[str] = Field(None, pattern=GATEWAY_REQUEST_ID)
    gateway_session_ref: Optional[str] = Field(None, pattern=GATEWAY_SESSION_REF)
    invalid_reason: Optional[InvalidReason] = None
    src_ip: str
    method: str = Field(max_length=16)
    path: str = Field(max_length=2048, pattern=HTTP_PATH)
    query_redacted: Optional[str] = Field(None, max_length=2048)
    status_code: int = Field(ge=100, le=599)
    route_class: Literal["page", "static", "api", "login", "not_found", "error"]
    login: Optional[AppLogin] = None

    _ip = field_validator("src_ip")(lambda cls, v: _ipv4(v))

    @model_validator(mode="after")
    def _trust(self) -> "AppRequest":
        _context_rules(self.gateway_context, self.gateway_request_id, self.gateway_session_ref, self.invalid_reason)
        return self


TELEMETRY_TYPES = {"gateway-01": {"route_decision": RouteDecision, "upstream_result": UpstreamResult},
                   "demo-app-01": {"app_request": AppRequest}}


class TelemetryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    telemetry_version: Literal["1.0"]
    record_id: str = Field(min_length=1, max_length=128)
    origin_record_id: Optional[str] = Field(None, max_length=128)
    source_id: TelemetrySourceId
    record_type: Literal["route_decision", "upstream_result", "app_request"]
    occurred_at: datetime
    lab_run_id: str = Field(min_length=1, max_length=128)
    capture_mode: Literal["live", "replay"]
    attributes: dict

    @field_validator("occurred_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must include a timezone (use UTC)")
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _typed(self) -> "TelemetryRecord":
        if self.capture_mode == "live" and self.origin_record_id is not None:
            raise ValueError("origin_record_id: only replay records copy an original record")
        model = TELEMETRY_TYPES[self.source_id].get(self.record_type)
        if model is None:
            raise ValueError(f"record_type: {self.source_id} does not send {self.record_type}")
        try:
            self.attributes = model.model_validate(self.attributes).model_dump(mode="json", exclude_none=True)
        except ValidationError as e:
            loc, msg = reason_for(e, "").split(": ", 1)
            raise ValueError(f"attributes{'.' + loc if loc else ''}: {msg}") from None
        return self


def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reason_for(exc: Any, whole: str = "event") -> str:
    """Short 'field: message' string from a pydantic ValidationError; `whole` names a model-level error."""
    err = exc.errors()[0]
    loc = ".".join(str(p) for p in err["loc"]) or whole
    msg = err["msg"].removeprefix("Value error, ")
    return f"{loc}: {msg}"
