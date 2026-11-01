/**
 * Contract v1.2 consumer types (four honeypots, gateway and telemetry).
 *
 * Source: contracts/API.md, sources.json, event.schema.json and
 * telemetry.schema.json from m3/next-telemetry-contract @ eb2a94e (PR #19, NOT
 * merged when written). Response shapes follow that PR's
 * examples/telemetry_v1_2.json `expected_reads`. Anything the backend on main
 * does not serve yet (/api/sources, /routing, /api/gateway/requests,
 * telemetry_health) is shown as unavailable, never guessed.
 */

import type { SensorId } from '../types/api';

export type TelemetrySourceId = 'gateway-01' | 'demo-app-01';

export interface RegistryBinding {
  host: string;
  port: number | null;
  status: 'deployed' | 'proposed' | string;
  also_behind?: string;
  reachable_via?: string;
}

export interface RegistryHoneypot {
  source_id: SensorId | string;
  source_kind: 'honeypot';
  protocol: string;
  label: string;
  event_schema_versions: string[];
  event_types: string[];
  binding: RegistryBinding;
  credential_evidence?: string;
  response: { block: 'supported' | 'unsupported' | string; scope?: string };
}

export interface RegistryTelemetrySource {
  source_id: TelemetrySourceId | string;
  source_kind: 'gateway' | 'application' | string;
  protocol: string;
  label: string;
  telemetry_versions: string[];
  record_types: string[];
  upstreams?: string[];
  binding: RegistryBinding;
  response: { block: 'not_applicable' | string };
}

export interface SourcesRegistry {
  registry_version: string;
  honeypots: RegistryHoneypot[];
  telemetry_sources: RegistryTelemetrySource[];
  honeypot_count?: number;
}

export type CorrelationStatus = 'observed' | 'gateway_only' | 'upstream_only' | 'conflict';

export interface GatewayDecision {
  record_id: string;
  decision: 'normal_app' | 'decoy';
  upstream_id: string;
  reasons: string[];
  indicator_classes?: string[];
  client_ip: string;
  gateway_session_ref: string | null;
  routing_policy_id: string;
  routing_policy_revision: number;
  pin_scope: 'none' | 'session' | 'source_ip' | string;
  occurred_at: string;
}

export interface GatewayRequestDetail {
  gateway_request_id: string;
  lab_run_id: string;
  capture_mode: 'live' | 'replay';
  decision: GatewayDecision | null;
  gateway_observed_upstream: {
    record_id: string;
    upstream_id: string;
    outcome: 'response_received' | 'connect_error' | 'timeout' | 'aborted' | string;
    status_code?: number | null;
  } | null;
  upstream_handling: Array<{
    kind: 'event' | 'telemetry' | string;
    event_id?: string;
    record_id?: string;
    sensor_id?: string;
    source_id?: string;
    event_type?: string;
    incident_id?: string;
    occurred_at: string;
  }>;
  correlation: { status: CorrelationStatus | string; reasons: string[] };
  note?: string;
}

export interface IncidentRouting {
  incident_id: string;
  gateway_requests: Array<{
    gateway_request_id: string;
    decision: 'normal_app' | 'decoy';
    reasons: string[];
    correlation_status: CorrelationStatus | string;
  }>;
  gateway_session_refs: string[];
  ingress: { verified: number; absent: number; invalid: number };
  normal_app_contact: {
    records: Array<{ record_id: string; gateway_request_id?: string; method: string; path: string; status_code: number; occurred_at: string }>;
    coverage: {
      source_id: string;
      lab_run_id: string;
      first_record_at: string | null;
      last_record_at: string | null;
      records_in_run: number;
      collection: 'ok' | 'stale' | 'never' | string;
    };
    statement: string;
  };
}

/** attributes.credential on db-decoy-01 / file-decoy-01 auth events. */
export interface CredentialEvidence {
  scheme: string;
  proof_check: 'matched_honeytoken' | 'not_matched' | 'not_checked' | 'unsupported_scheme' | 'malformed' | string;
  verifier_version?: string;
}

export interface DbAttributes {
  command: string;
  statement_verb?: string | null;
  length_bytes?: number;
  schema_name?: string | null;
  execution: 'not_supported' | string;
  error_code?: number | null;
}

export interface FileAttributes {
  operation: string;
  share?: string;
  path?: string;
  bytes?: number;
  content_sha256?: string | null;
  digest_scope?: string | null;
  storage?: 'quarantined_inert' | 'discarded' | string;
  magic_type_hint?: string | null;
}

export interface IngressAttributes {
  gateway_context: 'verified' | 'absent' | 'invalid';
  gateway_request_id?: string;
  gateway_session_ref?: string | null;
  invalid_reason?: string;
}

export interface ArchiveAttributes {
  format: string;
  compression?: string;
  entries: Array<{ name: string; size_bytes?: number; sha256?: string; honeytoken_ids?: string[] }>;
  contains_executable: boolean;
  auto_run: boolean;
}

export interface TransferAttributes {
  response_status?: number;
  content_length?: number | null;
  bytes_written?: number | null;
  completion?: string;
}
