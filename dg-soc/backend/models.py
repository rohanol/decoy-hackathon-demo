"""Pydantic v2 models matching contracts/event.schema.json (schema 1.0 and 1.1).

schema_version picks the attribute rules: 1.0 events keep the 1.0 rules (unknown
attributes pass through untyped), and only 1.1 events get the new typed fields.
"""
import json
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

SensorId = Literal["ssh-decoy-01", "web-decoy-01"]
EventType = Literal[
    "connection_open", "auth_failure", "auth_success", "command_input",
    "connection_close", "http_request", "synthetic_file_access", "blocked_request",
    "bait_served",
]
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


class IngestEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0", "1.1"]
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
        if info.data.get("schema_version") == "1.1" and not isinstance(v, BaseModel):
            return AttributesV11.model_validate(v)
        return v

    @model_validator(mode="after")
    def _evidence_rules(self) -> "IngestEvent":
        a = self.attributes
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


# Derived when a producer omits them (contracts/API.md, "Request, result and bait evidence").
OBSERVATION_KIND = {
    "connection_open": "network_input", "auth_failure": "network_input", "auth_success": "network_input",
    "http_request": "network_input", "connection_close": "network_input",
    "command_input": "command_input",
    "synthetic_file_access": "emulated_result", "bait_served": "emulated_result",
    "blocked_request": "policy_result",
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


class Heartbeat(BaseModel):
    """POST /api/ingest/heartbeat: exactly the per-sensor payload M2's adapter sends
    (sensors/adapter.py `_heartbeat_payloads`, PR #8). Translated to M1's CollectorHealth on read."""
    model_config = ConfigDict(extra="forbid")

    collector_id: str = Field(min_length=1, max_length=64)
    sensor_id: SensorId
    sent_at: datetime
    sensor_process: Literal["up", "down", "unknown"]
    last_read_at: Optional[datetime] = None
    last_ingest_ok_at: Optional[datetime] = None
    backlog_lines: Optional[int] = Field(None, ge=0, le=MAX_COUNT)
    oldest_backlog_age_s: Optional[float] = Field(None, ge=0, le=MAX_COUNT)
    errors_total: int = Field(0, ge=0, le=MAX_COUNT)
    rejected_total: int = Field(0, ge=0, le=MAX_COUNT)
    quarantined_total: int = Field(0, ge=0, le=MAX_COUNT)

    @field_validator("sent_at", "last_read_at", "last_ingest_ok_at")
    @classmethod
    def _aware(cls, v):
        if v is not None and v.tzinfo is None:
            raise ValueError("timestamp needs a UTC offset")
        return v


def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reason_for(exc: Any) -> str:
    """Short 'field: message' string from a pydantic ValidationError."""
    err = exc.errors()[0]
    loc = ".".join(str(p) for p in err["loc"]) or "event"
    msg = err["msg"].removeprefix("Value error, ")
    return f"{loc}: {msg}"
