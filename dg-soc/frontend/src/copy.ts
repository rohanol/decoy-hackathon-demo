/**
 * The wording dictionary. AGENTS.md section 7 is a hard constraint, not a style
 * preference: labels must match evidence.
 *
 * Every user-facing string about what the system observed lives here, so the
 * language cannot drift as screens get built. If a phrase is not in this file,
 * check AGENTS.md section 7 before inventing one.
 *
 * Never: "compromised", "exploited", "breached", "attacker isolated",
 * "identified", "data stolen", "attack stopped", "safe", "clear".
 */

import type { EventType, LinkKind, LinkStatus, ActionStatus, Stage } from './types/api';
import type { MismatchReason, ObservationKind, Outcome } from './evidence/model';

export const EVENT_TYPE_LABEL: Record<EventType, string> = {
  connection_open: 'connection open',
  auth_failure: 'auth failure',
  auth_success: 'auth accepted',
  command_input: 'command submitted',
  connection_close: 'connection close',
  http_request: 'http request',
  synthetic_file_access: 'synthetic file access',
  blocked_request: 'blocked request',
};

/** Longer form, used in the raw event drawer and tooltips. */
export const EVENT_TYPE_DESCRIPTION: Record<EventType, string> = {
  connection_open: 'A connection was opened to the decoy.',
  auth_failure: 'A login attempt was rejected by the decoy.',
  auth_success: 'Credentials were accepted by the emulated shell. No real account exists.',
  command_input: 'A command was submitted to the emulated shell. Nothing executed on a real host.',
  connection_close: 'The connection was closed.',
  http_request: 'An HTTP request reached the web decoy.',
  synthetic_file_access: 'A synthetic file was served. No real data exists in this lab.',
  blocked_request: 'A request was rejected by an analyst-applied block.',
};

export const SENSOR_LABEL: Record<string, string> = {
  'ssh-decoy-01': 'SSH decoy',
  'web-decoy-01': 'Web decoy',
};

export const STAGE_LABEL: Record<Stage, string> = {
  recon: 'recon',
  credential_attack: 'credential attack',
  exploit_attempt: 'exploit attempt',
  post_access: 'post-access',
  data_access: 'data access',
  none: 'no stage',
};

/** Shown in a kill-chain segment the incident never reached. Never "safe". */
export const STAGE_NOT_OBSERVED = 'not observed';

export function linkPhrase(kind: LinkKind, status: LinkStatus): string {
  if (status === 'confirmed') return 'analyst-confirmed link';
  if (status === 'rejected') return 'link rejected by analyst';
  return kind === 'strong_candidate'
    ? 'strong candidate link — honeytoken reuse'
    : 'candidate link';
}

export const ACTION_STATUS_LABEL: Record<ActionStatus, string> = {
  applied: 'APPLIED',
  verified: 'VERIFIED',
  expired: 'EXPIRED',
  revoked: 'REVOKED',
  reconciliation_required: 'RECONCILE',
};

export const ACTION_STATUS_MEANING: Record<ActionStatus, string> = {
  applied: 'Block written. Not yet proven to reject a request.',
  verified: 'A blocked request arrived carrying this action id.',
  expired: 'The time limit ran out and the block lifted itself.',
  revoked: 'An analyst undid this block.',
  reconciliation_required:
    'After a restart this action was missing from, or changed in, the enforced policy. Its state is not trusted until reconciled.',
};

export const COPY = {
  /** Non-dismissible banner above every transcript replay. */
  transcriptBanner:
    'Commands submitted to an emulated shell. Nothing executed on a real host.',

  /** Closing caveat in the link decision modal. From scenarios/demo_p3.md. */
  linkCaveat:
    'A confirmed link means the same source followed our planted trail. It does not identify a person.',

  /** Scope warning in the block preview. */
  blockScopeWarning:
    'This blocks the web decoy only. The SSH decoy stays reachable. This does not isolate the host.',

  blockScopeAck: 'I understand this blocks the web decoy only',

  blockAwaitingVerification: 'Applied. Waiting for a blocked request to verify.',

  noiseCounterNote:
    'Deduplicated sensor records grouped by source IP and lab run. This is grouping compression, not a measured false-positive reduction: separate clients behind one address are pooled into one incident.',

  lowPriorityTooltip: 'Scored below the noise threshold set in scoring.yaml.',

  exportTooltip: 'JSON export, password hashes excluded.',

  emptyFeedTitle: 'No events yet.',
  emptyFeedHint: 'Events appear here as soon as a decoy is touched.',

  emptyIncidentsTitle: 'No incidents yet.',
  emptyIncidentsHint: 'An incident opens the first time a source IP touches a decoy.',

  emptyTranscriptTitle: 'No commands recorded for this session.',
  emptyTranscriptHint: 'Brute-force sessions never reached a shell, so there is nothing to replay.',

  fixturesWarning:
    'Fixture data from contracts/examples/events_p3.json. Not a live capture.',
} as const;

/** Short rule names for analytics. Mirrors the docstrings in backend/rules/. */
export const RULE_NAME: Record<string, string> = {
  R01: 'SSH password guessing',
  R02: 'Commands after login',
  R03: 'Discovery commands',
  R04: 'Synthetic file served',
  R05: 'Confirmed cross-decoy link',
  R07: 'Web attack attempt',
  R08: 'Hidden-path scanning',
  R09: 'Honeytoken reuse',
};

/**
 * Landing punchline options. The part in `highlight` is drawn in neon green.
 * Pick with LANDING_PUNCHLINE, or preview any of them with /welcome?p=2.
 */
export const PUNCHLINES = [
  { lead: 'Nothing here is real.', highlight: 'Except the evidence.' },
  { lead: 'The attacker sees a network.', highlight: 'You see the attacker.' },
  { lead: 'Let them in.', highlight: 'Watch every move.' },
  { lead: 'Bait the breach.', highlight: 'Read the intent.' },
  { lead: 'Every touch is', highlight: 'a signal.' },
] as const;

export const LANDING_PUNCHLINE = 0;

/* ---------------------------------------------------------------------------
 * Evidence model wording (review sections 4, 5, 11-15). Same law as above:
 * labels match evidence. A relation is never an identity; a committed policy
 * is never a verified denial; activity is never health.
 * ------------------------------------------------------------------------- */


export const BASIS_LABEL = {
  contract_v1: 'contract v1.0',
  proposed_fixture: 'PROPOSED · dev fixture',
} as const;

export const BASIS_MEANING = {
  contract_v1: 'Reshaped from the live v1.0 API. Nothing here is scored or inferred by the browser.',
  proposed_fixture:
    'A development fixture in the proposed shape, pending the agreed contract. Not captured data.',
} as const;

export const OUTCOME_LABEL: Record<Outcome, string> = {
  attempted: 'attempted',
  emulated_success: 'emulated success',
  denied: 'denied',
  failed: 'failed',
  unknown: 'result unknown',
};

export const OUTCOME_MEANING: Record<Outcome, string> = {
  attempted: 'Input was received. Input alone never proves a result.',
  emulated_success: 'The decoy returned a fake success. Nothing real was accessed.',
  denied: 'The decoy or a policy refused it.',
  failed: 'The emulated command or request failed.',
  unknown: 'The decoy recorded no result for this input.',
};

export const OBSERVATION_KIND_LABEL: Record<ObservationKind, string> = {
  network_input: 'network input',
  command_input: 'command input',
  emulated_result: 'emulated result',
  policy_result: 'policy result',
};

export const CASE_COPY = {
  sensorSession: 'One decoy session: sensor, session id, run and capture mode.',
  boundedFallback:
    'This sensor reports no session id, so this case is every request from this source on it in this run.',
  unscoredV1: 'Not scored per case: contract v1.0 scores the source, not the session.',
  sourceIsEndpoint: 'An observed network endpoint in one run. Never a person.',
  sourceScoreV1:
    'v1.0 source score: pools every case behind this address, so it is not a case or parent score.',
  claims: 'Client strings are claims the client sent, not fingerprints.',
} as const;

export const RELATION_COPY = {
  identity: 'Relations connect observed sessions. They never identify a person.',
  candidate:
    'A reason to look, not a conclusion. Several clients behind one address (NAT, a shared laptop) produce the same pattern.',
  strong:
    'Stronger than address and time, still not identity: it shows a planted credential travelled between two sessions.',
  rejected: 'Rejected by an analyst. Both cases and all their evidence are kept.',
  parent:
    'An analyst approved this relation, so its cases are investigated together. Rejecting it later splits them again.',
  parentScoreV1: 'No parent score in contract v1.0. The source score is shown on the source profile.',
} as const;

export const BAIT_STATUS_LABEL = {
  served_then_presented: 'issued, served, then presented',
  presented_without_served_evidence: 'presented · serving not recorded',
  orphan_use: 'orphan use · no issuance or read on record',
} as const;

export const BAIT_STATUS_MEANING = {
  served_then_presented: 'The decoy recorded serving this bait to that session before the token appeared elsewhere.',
  presented_without_served_evidence:
    'The token appeared, but nothing records the bait being served. In contract v1.0 the planted-side event is the nearest earlier event the backend found, which is not proof of a read.',
  orphan_use:
    'The token appeared with no issuance or read on record. Kept visible; no read event is invented.',
} as const;

export const MAPPING_COPY = {
  noTechnique: 'No ATT&CK technique: this analytic does not warrant one.',
  noRationaleV1: 'Contract v1.0 does not carry a mapping rationale. The limitation below is the backend’s.',
  observed: 'observed',
  inferred: 'inferred',
} as const;

export const HEALTH_COPY = {
  service: 'Service',
  serviceHint: 'Is the backend answering, and is the event stream connected?',
  collection: 'Collection',
  collectionHint: 'Is each collector running and keeping up? Reported by the collector, not guessed from traffic.',
  collectionNotReported:
    'Not reported. Contract v1.0 has no collector heartbeat, so collection health is unknown. Quiet and broken look the same until it does.',
  activity: 'Attacker activity',
  activityHint: 'When decoy traffic last arrived. Activity, never health: a quiet decoy can be perfectly healthy.',
  skew: 'Sensor clock differs from the backend. Event times from it are suspect; a future timestamp never makes a collector healthy.',
} as const;

export const VERIFICATION_COPY = {
  committed: 'Policy committed',
  committedHint: 'The blocklist entry was written. That alone does not prove a request was refused.',
  pending: 'Pending verification',
  pendingHint: 'Waiting for a denied request matching the action, sensor, source, run and window.',
  verified: 'Verified denial',
  verifiedHint: 'A matching request was refused under this action.',
  expired: 'Expired',
  revoked: 'Revoked',
  rejectedTitle: 'Rejected as verification',
  rejectedHint: 'Observations the backend refused to count. They change nothing.',
  noneReported: 'The backend reports refusals for this action; none so far.',
  reconcile: 'Reconciliation required',
  reconcileHint: 'After a restart this action no longer matches the enforced policy. Treat its state as unknown.',
  v1Tuple:
    'Backend v1.0 matches the action id only (review F5); the full tuple check arrives with the contract.',
} as const;

/**
 * Labels for refusal reasons the backend sends. Reasons are free strings in
 * both M2's runtime and M3's contract, so an unknown one is shown verbatim
 * (mismatchReasonLabel). The browser never works out which check failed.
 */
export const MISMATCH_REASON_LABEL: Partial<Record<MismatchReason, string>> = {
  verification_context_mismatch:
    'Failed the verification tuple. The backend does not say which check (sensor, source, run, mode, time or revision)',
  active_action_missing_or_changed_in_policy_after_restart:
    'After a restart the action was missing from, or changed in, the enforced policy',
  wrong_sensor: 'Came from a sensor this action does not cover',
  wrong_source: 'Source address differs from the block target',
  replay_mode: 'A replayed record, not a live request',
  wrong_run: 'Belongs to a different lab run',
  outside_window: 'Outside the block window',
  stale_policy_revision: 'Matched an older policy revision',
  duplicate: 'Duplicate of an observation already counted',
  unknown_action: 'Carries an action id the backend does not know',
};

export const ELIGIBILITY_COPY = {
  backendDecides: 'The backend still checks every preview and apply; this only avoids offering an action that cannot be honest.',
  uiGuard: 'UI guard from reported capture modes.',
  backend: 'Backend eligibility.',
} as const;

export function mismatchReasonLabel(reason: string): string {
  return MISMATCH_REASON_LABEL[reason] ?? reason;
}

export const AUTHORITY_LABEL = {
  backend_case: 'backend case',
  display_grouping: 'display grouping',
} as const;

export const AUTHORITY_MEANING = {
  backend_case: 'A case or investigation the backend created and owns.',
  display_grouping:
    'Grouped in the browser from v1.0 events for display. Not a backend case: authoritative cases and investigations arrive with M3\u2019s case model.',
} as const;

/** Fallbacks so an event type or stage this build does not know never breaks a screen. */
export function eventTypeLabel(type: string): string {
  return (EVENT_TYPE_LABEL as Record<string, string>)[type] ?? type.replace(/_/g, ' ');
}

export function stageLabel(stage: string): string {
  return (STAGE_LABEL as Record<string, string>)[stage] ?? stage.replace(/_/g, ' ');
}

export function eventTypeDescription(type: string): string {
  return (
    (EVENT_TYPE_DESCRIPTION as Record<string, string>)[type] ??
    'An event type this dashboard build does not describe yet. Shown as received.'
  );
}
