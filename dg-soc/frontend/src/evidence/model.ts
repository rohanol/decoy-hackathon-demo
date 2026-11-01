/**
 * Evidence display model. PROPOSED — this is not a contract.
 *
 * Rohan (M3) owns contracts/. This file is the frontend's side of the
 * conversation for the corrected model in the review (sections 4, 11-15):
 * sessions kept distinct, sources grouped as observed endpoints, and only an
 * analyst-approved parent combining work across decoys. Field names follow
 * review section 12 so the agreed contract can map onto it with little churn.
 *
 * Every view carries `basis`, so a screen can always say where a value came
 * from:
 *   contract_v1       reshaped from today's API (contracts/API.md v1.0).
 *                     Nothing is scored, detected or guessed; a value the
 *                     contract does not carry is null and the UI says so.
 *   proposed_fixture  a development fixture in the PROPOSED shape. Never on
 *                     the demo path: fixtures load only in a fixture build.
 *
 * Only type imports here: the module is pure and runs under `node --test`.
 */

import type { CaptureMode, RuleId, SensorId, Severity, SocEvent } from '../types/api';

export type Basis = 'contract_v1' | 'contract_v11' | 'proposed_fixture';

/* ---------- observations (review section 5, "better evidence fields") ---------- */

/** What kind of thing an event records. */
export type ObservationKind = 'network_input' | 'command_input' | 'emulated_result' | 'policy_result';

/** What the decoy says happened. Input alone never proves a result. */
export type Outcome = 'attempted' | 'emulated_success' | 'denied' | 'failed' | 'unknown';

export const OUTCOMES: readonly Outcome[] = ['attempted', 'emulated_success', 'denied', 'failed', 'unknown'];

export interface ObservationFacet {
  observation_kind: ObservationKind | null;
  outcome: Outcome | null;
  request_id: string | null;
  channel_id: string | null;
  /** v1.0 fields that already say something about a result, shown as-is. */
  v1_outcome: string | null;
  v1_response_class: string | null;
}

const KINDS = new Set<string>(['network_input', 'command_input', 'emulated_result', 'policy_result']);
const OUTCOME_SET = new Set<string>(OUTCOMES);

function readString(event: SocEvent, key: string): string | null {
  // Proposed fields may land on the envelope or in attributes; read both.
  const top = (event as unknown as Record<string, unknown>)[key];
  if (typeof top === 'string' && top) return top;
  const nested = event.attributes?.[key];
  return typeof nested === 'string' && nested ? nested : null;
}

/** The observation facet of one event. Reads fields; never infers them. */
export function facetOf(event: SocEvent): ObservationFacet {
  const kind = readString(event, 'observation_kind');
  const outcome = readString(event, 'outcome');
  const v1Outcome = event.attributes?.outcome;
  return {
    observation_kind: kind && KINDS.has(kind) ? (kind as ObservationKind) : null,
    // v1.0 also uses attributes.outcome (served/denied/not_found) for file
    // access; only the proposed vocabulary counts as a proposed outcome.
    outcome: outcome && OUTCOME_SET.has(outcome) ? (outcome as Outcome) : null,
    request_id: readString(event, 'request_id'),
    channel_id: readString(event, 'channel_id'),
    v1_outcome: typeof v1Outcome === 'string' && !OUTCOME_SET.has(v1Outcome) ? v1Outcome : null,
    v1_response_class:
      typeof event.attributes?.response_class === 'string' ? event.attributes.response_class : null,
  };
}

/* ---------- cases, sources, relations, parents (review section 4) ---------- */

/**
 * Who owns a grouping. backend_case: a case or investigation the backend
 * created (M3's case model). display_grouping: built in the browser from
 * v1.0 events for display only. Never present one as the other.
 */
export type Authority = 'backend_case' | 'display_grouping';

export interface SessionCase {
  case_id: string;
  basis: Basis;
  authority: Authority;
  sensor_id: SensorId;
  session_id: string | null;
  /**
   * sensor_session: one decoy session (sensor_id + session_id + run + mode).
   * bounded_fallback: the sensor reports no session, so the case is that
   * source's requests on that sensor in that run. Always labelled as such.
   */
  boundary: 'sensor_session' | 'bounded_fallback';
  lab_run_id: string;
  capture_mode: CaptureMode | 'mixed';
  src_ip: string;
  first_at: string;
  last_at: string;
  event_ids: string[];
  event_count?: number;
  grouping_basis?: string | null;
  /** Proposed outcome counts; empty when the contract carries none. */
  outcomes: Partial<Record<Outcome, number>>;
  request_ids: string[];
  /** Account names tried. Attacker-supplied text. */
  accounts: string[];
  commands: number;
  /** Rules whose findings cite an event in this case. */
  rule_ids: RuleId[];
  /** A per-case score. null in v1.0, which scores the source, not the case. */
  score: number | null;
  severity: Severity | null;
}

export interface ClientClaim {
  kind: 'ssh_client_version' | 'http_user_agent';
  /** Attacker-supplied; a claim the client made, not a fingerprint. */
  value: string;
  event_id: string;
}

export interface SourceProfile {
  profile_id: string;
  basis: Basis;
  /** An observed network endpoint. Never a person. */
  src_ip: string;
  lab_run_id: string;
  capture_modes: CaptureMode[];
  first_at: string;
  last_at: string;
  sensors: Array<{ sensor_id: SensorId; cases: number; events: number }>;
  attempted_accounts: string[];
  client_claims: ClientClaim[];
  case_ids: string[];
  /**
   * v1.0's score is per source and run (the backend's incident), so it pools
   * every case behind this address. Shown as exactly that, never as a case or
   * parent score.
   */
  source_score: { incident_id: string; score: number; severity: Severity } | null;
}

export type RelationStatus = 'open' | 'confirmed' | 'rejected';

export interface RelationEnd {
  case_id: string | null;
  event_id: string;
  sensor_id: SensorId;
  at: string | null;
}

export interface BaitChain {
  token_id: string;
  asset_id: string | null;
  issuance_id: string | null;
  fixture_version: string | null;
  /** Which session or run the bait was issued to. */
  issued: { session_id: string | null; sensor_id: SensorId; at: string } | null;
  /** bait_served: the decoy recorded actually serving it. */
  served: { event_id: string; at: string; digest_scope: string | null } | null;
  presented: { event_id: string; sensor_id: SensorId; at: string | null };
  /**
   * served_then_presented: the causal chain the review asks for.
   * presented_without_served_evidence: the token appeared, but nothing records
   *   it being served. In v1.0 this is every chain: the backend links the
   *   nearest earlier event on the planted sensor, which is not proof of a read.
   * orphan_use: presented with no relation at all. Visible, not fabricated.
   */
  status: 'served_then_presented' | 'presented_without_served_evidence' | 'orphan_use';
  /** v1.0 only: the event the backend chose on the planted side, and why it is not proof. */
  v1_planted_side_event_id: string | null;
}

export interface CandidateRelation {
  relation_id: string;
  basis: Basis;
  kind: 'candidate' | 'strong_candidate';
  status: RelationStatus;
  /** The backend's stated reason, verbatim. */
  reason: string;
  from: RelationEnd;
  to: RelationEnd;
  gap_seconds: number | null;
  bait: BaitChain | null;
  decided_at: string | null;
  rationale: string | null;
  actor_id: string | null;
  attribution?: 'unique' | 'ambiguous' | 'request_only' | null;
  candidate_issuance_ids?: string[];
}

export interface ParentInvestigation {
  parent_id: string;
  basis: Basis;
  authority: Authority;
  relation_ids: string[];
  case_ids: string[];
  approved_at: string | null;
  approved_by: string | null;
  rationale: string | null;
  /** A parent score. null in v1.0, which has no parent: see SourceProfile.source_score. */
  score: number | null;
  severity: Severity | null;
  incident_revision: number | null;
  /** A reversal or new evidence made the summary out of date. */
  summary_stale: boolean;
}

/* ---------- mappings (review section 5) ---------- */

export interface MappingView {
  finding_id: string;
  rule_id: RuleId;
  rule_version: string;
  mapping_version: string | null;
  /** null is a valid answer: not every analytic maps to a technique. */
  technique_ids: string[];
  technique_status: 'mapped' | 'no_technique';
  /** Why the technique applies, from the backend. null when not supplied. */
  rationale: string | null;
  limitation: string;
  observation: 'observed' | 'inferred' | null;
  evidence_event_ids: string[];
}

/* ---------- health (review section 13) ---------- */

export type Liveness = 'up' | 'down' | 'unknown';

export interface CollectorHealth {
  sensor_id: SensorId;
  process_state: 'running' | 'stopped' | 'unknown';
  heartbeat_at: string | null;
  last_read_at: string | null;
  last_ingest_at: string | null;
  backlog_records: number | null;
  oldest_backlog_age_s: number | null;
  error_count: number | null;
  /** Sensor clock minus backend clock. A future event cannot make a collector healthy. */
  clock_skew_s: number | null;
  /** accepted / duplicate / rejected / quarantined / retry counts. */
  ingest: { accepted: number; duplicate: number; rejected: number; quarantined: number; retry: number | null } | null;
}

export interface HealthView {
  basis: Basis;
  /** Is the backend answering? */
  service: { backend: Liveness; checked_at: string | null };
  /** Is each collector alive and keeping up? null = the backend does not report it. */
  collectors: CollectorHealth[] | null;
  /** When attacker traffic last arrived. Activity, never health. */
  activity: Array<{ sensor_id: SensorId; last_event_at: string | null }>;
}

/* ---------- response (review section 14) ---------- */

/**
 * Refusal reasons. Free strings in both M2's runtime and M3's contract; these
 * are the ones seen so far, plus the proposed vocabulary the dev fixtures use.
 */
export type MismatchReason =
  | 'verification_context_mismatch'
  | 'active_action_missing_or_changed_in_policy_after_restart'
  | 'wrong_sensor'
  | 'wrong_source'
  | 'replay_mode'
  | 'wrong_run'
  | 'outside_window'
  | 'stale_policy_revision'
  | 'duplicate'
  | 'unknown_action'
  | (string & {});

export interface VerificationAttempt {
  event_id: string | null;
  /** When the backend received it, if reported. */
  at: string | null;
  /** The tuple, when the source supplies it. M2 and M3 report event id and reason only. */
  sensor_id: SensorId | null;
  src_ip: string | null;
  capture_mode: CaptureMode | null;
  /** The backend refused this as verification, and why (verbatim). */
  reason: MismatchReason;
  /** Which field carried it, while the name is not agreed. */
  field: 'verification_mismatches' | 'verification_rejects' | 'proposed';
}

export interface ResponseVerification {
  action_id: string;
  basis: Basis;
  target_ip: string;
  reason: string;
  until: string;
  /** Policy committed: the blocklist entry was written. Not proof it works. */
  committed: { at: string; policy_revision: number | null; by: string | null };
  /** A matching denied request, by the full tuple. The only proof. */
  verified: { event_id: string; at: string | null } | null;
  ended: { kind: 'expired' | 'revoked'; at: string | null; by: string | null } | null;
  /** Observations the backend rejected as verification. */
  rejected_attempts: VerificationAttempt[];
  /** The backend sends a refusal list for this action (possibly empty). False on v1.0. */
  refusals_reported: boolean;
  /** M2: after a restart the action no longer matches the enforced policy. */
  needs_reconciliation: boolean;
}

export interface EligibilityReason {
  code: 'replay_data' | 'mixed_modes' | 'no_live_run' | 'sensor_not_registered' | 'stale_observation' | string;
  message: string;
}

export interface ResponseEligibility {
  eligible: boolean;
  /**
   * backend: the backend's own eligibility answer.
   * ui_guard: the UI's conservative check from fields the backend reported.
   * The backend decides either way; the guard only avoids offering an action
   * that cannot be honest.
   */
  source: 'backend' | 'ui_guard';
  reasons: EligibilityReason[];
}
