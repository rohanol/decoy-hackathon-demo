/**
 * The v1.0 reshaper regroups; it never scores, detects or invents.
 * Review acceptance IDs in brackets.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  eligibilityFromV1,
  healthFromV1,
  parentsFromV1,
  relationsFromV1,
  sessionCasesFromV1,
  sourceProfileFromV1,
  verificationFromV1,
} from '../src/evidence/fromV1.ts';
import { facetOf } from '../src/evidence/model.ts';
import type { Incident, Link, ResponseAction, SocEvent } from '../src/types/api.ts';

let n = 0;
function ev(partial: Partial<SocEvent> & Pick<SocEvent, 'sensor_id' | 'event_type'>): SocEvent {
  n += 1;
  return {
    schema_version: '1.0',
    source_record_id: `r${n}`,
    occurred_at: new Date(Date.UTC(2026, 10, 1, 4, 30, n)).toISOString(),
    src_ip: '192.168.77.10',
    lab_run_id: 'run-01',
    capture_mode: 'live',
    session_id: null,
    event_id: `evt_${n}`,
    seq: n,
    ingested_at: new Date(Date.UTC(2026, 10, 1, 4, 30, n)).toISOString(),
    incident_id: 'inc_01',
    attributes: {},
    ...partial,
  };
}

const incident = (over: Partial<Incident> = {}): Incident => ({
  incident_id: 'inc_01', src_ip: '192.168.77.10', lab_run_id: 'run-01', score: 80, severity: 'critical',
  stages_observed: [], first_seen: '2026-11-01T04:30:00Z', last_seen: '2026-11-01T04:35:00Z', event_count: 0,
  findings: [], score_breakdown: [], links: [], sessions: [],
  summary: { source: 'rules', text: '', cited_event_ids: [] }, active_block: null, ...over,
});

test('[T01] two SSH sessions from one address stay two cases, and nothing is scored per case', () => {
  const a = ev({ sensor_id: 'ssh-decoy-01', event_type: 'auth_success', session_id: 'sA', attributes: { username: 'alice' } });
  const b = ev({ sensor_id: 'ssh-decoy-01', event_type: 'auth_success', session_id: 'sB', attributes: { username: 'bob' } });
  const c = ev({ sensor_id: 'ssh-decoy-01', event_type: 'command_input', session_id: 'sA', attributes: { command: 'ls' } });
  const cases = sessionCasesFromV1([a, b, c], [
    { finding_id: 'f1', rule_id: 'R03', rule_version: '2', incident_id: 'inc_01', src_ip: a.src_ip,
      technique_ids: ['T1083'], stage: 'post_access', label: 'x', limitation: 'y',
      evidence_event_ids: [c.event_id], created_at: c.occurred_at },
  ]);
  assert.equal(cases.length, 2);
  const caseA = cases.find((x) => x.session_id === 'sA');
  assert.deepEqual(caseA?.event_ids, [a.event_id, c.event_id]);
  assert.deepEqual(caseA?.rule_ids, ['R03']);
  assert.equal(caseA?.commands, 1);
  assert.deepEqual(cases.find((x) => x.session_id === 'sB')?.rule_ids, []);
  for (const item of cases) {
    assert.equal(item.score, null);
    assert.equal(item.severity, null);
    assert.equal(item.boundary, 'sensor_session');
  }
});

test('web events without a session form one labelled bounded-fallback case', () => {
  const w1 = ev({ sensor_id: 'web-decoy-01', event_type: 'http_request', attributes: { path: '/login' } });
  const w2 = ev({ sensor_id: 'web-decoy-01', event_type: 'http_request', attributes: { path: '/search' } });
  const cases = sessionCasesFromV1([w1, w2], []);
  assert.equal(cases.length, 1);
  assert.equal(cases[0]?.boundary, 'bounded_fallback');
  assert.equal(cases[0]?.session_id, null);
});

test('replay and live in one session are reported as mixed, not merged silently', () => {
  const x = ev({ sensor_id: 'ssh-decoy-01', event_type: 'auth_failure', session_id: 's', capture_mode: 'live' });
  const y = ev({ sensor_id: 'ssh-decoy-01', event_type: 'auth_failure', session_id: 's', capture_mode: 'replay' });
  assert.equal(sessionCasesFromV1([x, y], [])[0]?.capture_mode, 'mixed');
});

test('source profile keeps the v1.0 score as a source score and client strings as claims', () => {
  const a = ev({ sensor_id: 'ssh-decoy-01', event_type: 'connection_open', session_id: 's1', attributes: { client_version: 'SSH-2.0-x' } });
  const w = ev({ sensor_id: 'web-decoy-01', event_type: 'http_request', attributes: { user_agent: 'curl/8' } });
  const cases = sessionCasesFromV1([a, w], []);
  const profile = sourceProfileFromV1(incident(), [a, w], cases);
  assert.deepEqual(profile.source_score, { incident_id: 'inc_01', score: 80, severity: 'critical' });
  assert.deepEqual(profile.client_claims.map((c) => c.kind), ['ssh_client_version', 'http_user_agent']);
  assert.equal(profile.case_ids.length, 2);
});

const link = (over: Partial<Link> = {}): Link => ({
  link_id: 'lnk_1', from_event_id: 'evt_a', to_event_id: 'evt_b', from_sensor: 'ssh-decoy-01',
  to_sensor: 'web-decoy-01', kind: 'strong_candidate', basis: 'honeytoken tok_portal_01',
  status: 'open', decided_at: null, rationale: null, ...over,
});

test('[T05] a v1.0 token link never claims the bait was served', () => {
  const [relation] = relationsFromV1([link()], []);
  assert.equal(relation?.bait?.token_id, 'tok_portal_01');
  assert.equal(relation?.bait?.served, null);
  assert.equal(relation?.bait?.status, 'presented_without_served_evidence');
  assert.equal(relation?.bait?.v1_planted_side_event_id, 'evt_a');
});

test('only an analyst-confirmed relation becomes a parent, and it carries no invented score', () => {
  const relations = relationsFromV1(
    [link(), link({ link_id: 'lnk_2', status: 'confirmed', rationale: 'r' }), link({ link_id: 'lnk_3', status: 'rejected' })],
    [],
  );
  const parents = parentsFromV1(relations);
  assert.deepEqual(parents.map((p) => p.relation_ids[0]), ['lnk_2']);
  assert.equal(parents[0]?.score, null);
  // rejected relations are kept, with their evidence
  assert.equal(relations.find((r) => r.relation_id === 'lnk_3')?.from.event_id, 'evt_a');
});

test('[T03] the response guard withholds replay and mixed-mode sources', () => {
  const live = ev({ sensor_id: 'web-decoy-01', event_type: 'http_request' });
  const replay = ev({ sensor_id: 'web-decoy-01', event_type: 'http_request', capture_mode: 'replay' });
  assert.equal(eligibilityFromV1([live]).eligible, true);
  assert.deepEqual(eligibilityFromV1([replay]).reasons.map((r) => r.code), ['replay_data']);
  assert.deepEqual(eligibilityFromV1([live, replay]).reasons.map((r) => r.code), ['mixed_modes']);
  assert.equal(eligibilityFromV1([live]).source, 'ui_guard');
});

test('verification stages come from the action status, never from a 200', () => {
  const base: ResponseAction = { action_id: 'act_1', target_ip: '192.168.77.10', status: 'applied', reason: 'demo',
    created_at: '2026-11-01T05:00:00Z', until: '2026-11-01T05:02:00Z', verified_by_event_id: null };
  assert.equal(verificationFromV1(base).verified, null);
  assert.equal(verificationFromV1(base).ended, null);
  assert.equal(verificationFromV1({ ...base, status: 'verified', verified_by_event_id: 'evt_9' }).verified?.event_id, 'evt_9');
  assert.equal(verificationFromV1({ ...base, status: 'expired' }).ended?.kind, 'expired');
  assert.equal(verificationFromV1({ ...base, status: 'revoked' }).ended?.kind, 'revoked');
});

test('[T13] v1.0 health reports activity, and leaves collector health unknown', () => {
  const view = healthFromV1({ ok: true, sensors: { 'ssh-decoy-01': '2026-11-01T05:00:00Z', 'web-decoy-01': null } },
    '2026-11-01T05:00:05Z', ['ssh-decoy-01', 'web-decoy-01']);
  assert.equal(view.collectors, null);
  assert.equal(view.service.backend, 'up');
  assert.equal(view.activity[0]?.last_event_at, '2026-11-01T05:00:00Z');
  assert.equal(healthFromV1(null, null, ['ssh-decoy-01']).service.backend, 'down');
});

test('facets read proposed fields and never infer an outcome from the event type', () => {
  const success = ev({ sensor_id: 'ssh-decoy-01', event_type: 'auth_success' });
  assert.equal(facetOf(success).outcome, null);
  const proposed = ev({ sensor_id: 'web-decoy-01', event_type: 'http_request',
    attributes: { outcome: 'denied', observation_kind: 'policy_result', request_id: 'req_1' } });
  assert.deepEqual([facetOf(proposed).outcome, facetOf(proposed).observation_kind, facetOf(proposed).request_id],
    ['denied', 'policy_result', 'req_1']);
  const served = ev({ sensor_id: 'web-decoy-01', event_type: 'synthetic_file_access', attributes: { outcome: 'served' } });
  assert.equal(facetOf(served).outcome, null);
  assert.equal(facetOf(served).v1_outcome, 'served');
});
