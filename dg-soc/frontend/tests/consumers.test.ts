/**
 * Consumer checks against teammates' actual records (PR #10 follow-up):
 *  - feed filters against M3's v1.1 example web records and M2's adapter fixture
 *  - verification refusals from M2's real router output and M3's contract shape
 *  - display groupings never presented as backend cases
 *  - unknown v1.1 event types and stages do not break labels
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parentsFromV1, refusalsOf, relationsFromV1, sessionCasesFromV1, verificationFromV1 } from '../src/evidence/fromV1.ts';
import { matchesFeedFilters, NO_FILTERS, requestIdsAvailable } from '../src/state/feedFilters.ts';
import type { ResponseAction, SocEvent } from '../src/types/api.ts';

const here = new URL('./fixtures/', import.meta.url);
const read = (name: string) => readFileSync(new URL(name, here), 'utf8');

/** Give raw records the backend-issued fields, as GET /api/events would. */
function asSoc(records: Array<Record<string, unknown>>): SocEvent[] {
  return records.map((record, index) => ({
    ...(record as unknown as SocEvent),
    event_id: `evt_${index}`,
    seq: index + 1,
    ingested_at: String(record['occurred_at']),
    incident_id: 'inc_x',
  }));
}

const m3 = asSoc(JSON.parse(read('m3_events_v1_1.json')).events);
const m2Web = asSoc(read('m2_web_sample.jsonl').trim().split('\n').map((line) => JSON.parse(line)));

test('request filter: M3 v1.1 web records carry attributes.request_id and are found by it', () => {
  assert.equal(requestIdsAvailable(m3), true);
  const hits = m3.filter((e) => matchesFeedFilters(e, { ...NO_FILTERS, request: 'req_a_env' }));
  // the /.env request and the bait_served record share the request id
  assert.deepEqual(hits.map((e) => e.event_type).sort(), ['bait_served', 'http_request']);
  assert.ok(hits.every((e) => e.sensor_id === 'web-decoy-01'));
  const prefix = m3.filter((e) => matchesFeedFilters(e, { ...NO_FILTERS, request: 'req_a_' }));
  assert.equal(prefix.length, m3.filter((e) => String(e.attributes?.['request_id'] ?? '').startsWith('req_a_')).length);
});

test('request filter stays off for M2 adapter web records, which carry no request_id', () => {
  assert.equal(requestIdsAvailable(m2Web), false);
});

test('session filter: SSH sessions in M3 records, and web records once they carry a session', () => {
  const sess01 = m3.filter((e) => matchesFeedFilters(e, { ...NO_FILTERS, session: 'sess01' }));
  assert.ok(sess01.length > 0 && sess01.every((e) => e.session_id === 'sess01'));
  // M3's v1.1 example web records still have session_id null: none match a session filter.
  const web = m3.filter((e) => e.sensor_id === 'web-decoy-01');
  assert.ok(web.every((e) => e.session_id === null));
  // Shape M4 is to emit (contract v1.1 migration: a session cookie id in session_id).
  const withCookie = web.map((e) => ({ ...e, session_id: 'wsess_7f2a' }));
  const hits = withCookie.filter((e) => matchesFeedFilters(e, { ...NO_FILTERS, session: 'wsess_7f2a', request: 'req_a_csv' }));
  assert.equal(hits.length, 1);
});

test('run and mode filters separate the replay record in M3 examples', () => {
  const replay = m3.filter((e) => matchesFeedFilters(e, { ...NO_FILTERS, mode: 'replay' }));
  assert.ok(replay.length >= 1 && replay.every((e) => e.capture_mode === 'replay'));
  const run = replay[0]?.lab_run_id ?? '';
  assert.ok(m3.filter((e) => matchesFeedFilters(e, { ...NO_FILTERS, run })).every((e) => e.lab_run_id === run));
});

test('web session ids from M4 make web cases sensor sessions, still display groupings', () => {
  const web = m3.filter((e) => e.sensor_id === 'web-decoy-01' && e.event_type === 'http_request')
    .map((e, i) => ({ ...e, session_id: i < 2 ? 'wsess_a' : 'wsess_b' }));
  const cases = sessionCasesFromV1(web, []);
  assert.deepEqual(cases.map((c) => c.session_id).sort(), ['wsess_a', 'wsess_b']);
  assert.ok(cases.every((c) => c.boundary === 'sensor_session' && c.authority === 'display_grouping'));
  assert.ok(cases.every((c) => c.score === null));
});

test('parents built from confirmed v1.0 links are display groupings, not investigations', () => {
  const relations = relationsFromV1([{ link_id: 'l', from_event_id: 'a', to_event_id: 'b', from_sensor: 'ssh-decoy-01',
    to_sensor: 'web-decoy-01', kind: 'strong_candidate', basis: 'honeytoken tok_portal_01', status: 'confirmed',
    decided_at: null, rationale: 'r' }], []);
  assert.equal(parentsFromV1(relations)[0]?.authority, 'display_grouping');
});

const m2Actions: ResponseAction[] = JSON.parse(read('m2_actions_real.json')).items;

test("M2's real verification_mismatches are read, verbatim reason, no invented tuple", () => {
  const [action] = m2Actions;
  assert.ok(action);
  const v = verificationFromV1(action);
  assert.equal(v.refusals_reported, true);
  assert.deepEqual(v.rejected_attempts.map((a) => a.event_id), ['evt_wrong_sensor', 'evt_wrong_src', 'evt_replay']);
  assert.ok(v.rejected_attempts.every((a) => a.reason === 'verification_context_mismatch'));
  assert.ok(v.rejected_attempts.every((a) => a.field === 'verification_mismatches'));
  // M2 does not say which check failed; the browser must not guess it.
  assert.ok(v.rejected_attempts.every((a) => a.sensor_id === null && a.src_ip === null && a.capture_mode === null));
  assert.equal(v.rejected_attempts[0]?.at, '2026-11-01T05:00:05Z');
  assert.equal(v.verified?.event_id, 'evt_good');
});

test("M3's contract field verification_rejects is read the same way", () => {
  const base = { ...m2Actions[0]!, verification_mismatches: undefined };
  const v = verificationFromV1({ ...base, verification_rejects: [{ event_id: 'evt_x', reason: 'wrong run' }] });
  assert.deepEqual(v.rejected_attempts.map((a) => [a.event_id, a.reason, a.field]), [['evt_x', 'wrong run', 'verification_rejects']]);
});

test('both fields during the transition: the same refusal shows once', () => {
  const refusal = { event_id: 'evt_dup', reason: 'verification_context_mismatch' };
  const { attempts } = refusalsOf({ ...m2Actions[0]!, verification_mismatches: [refusal], verification_rejects: [refusal] });
  assert.equal(attempts.length, 1);
});

test('v1.0 router (no field) reports nothing; an empty list is reported-but-none', () => {
  const v1: ResponseAction = { action_id: 'a', target_ip: '192.168.77.10', status: 'applied', reason: 'r',
    created_at: '2026-11-01T05:00:00Z', until: '2026-11-01T05:02:00Z', verified_by_event_id: null };
  assert.equal(verificationFromV1(v1).refusals_reported, false);
  assert.equal(verificationFromV1({ ...v1, verification_mismatches: [] }).refusals_reported, true);
  assert.equal(verificationFromV1({ ...v1, verification_mismatches: [] }).rejected_attempts.length, 0);
});

test("M2's reconciliation_required status is surfaced, never treated as verified", () => {
  const v = verificationFromV1({ ...m2Actions[0]!, status: 'reconciliation_required', verified_by_event_id: null,
    verification_mismatches: [{ event_id: null, received_at: '2026-11-01T05:01:00Z', reason: 'active_action_missing_or_changed_in_policy_after_restart' }] });
  assert.equal(v.needs_reconciliation, true);
  assert.equal(v.verified, null);
  assert.equal(v.rejected_attempts[0]?.event_id, null);
});
