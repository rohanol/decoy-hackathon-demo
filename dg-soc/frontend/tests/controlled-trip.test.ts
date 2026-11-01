import assert from 'node:assert/strict';
import { test } from 'node:test';
import { matchesTrip, tripCommand, tripVerdict, TRIP_VALID_MS, type Trip } from '../src/lib/controlledTrip.ts';
import type { Finding, Health, SocEvent } from '../src/types/api.ts';

const started = Date.parse('2026-11-01T06:30:00Z');
const iso = (offset: number) => new Date(started + offset).toISOString();
const trip: Trip = { nonce: 'trip_' + 'a'.repeat(32), runId: 'live-trip', minSeq: 5, startedAt: started };
const event: SocEvent = { schema_version: '1.2', event_id: 'evt_trip', seq: 6, source_record_id: 'native-trip',
  sensor_id: 'web-decoy-01', event_type: 'http_request', occurred_at: iso(1000), ingested_at: iso(1500),
  src_ip: '192.168.77.10', lab_run_id: 'live-trip', capture_mode: 'live', incident_id: 'inc_trip',
  attributes: { method: 'GET', path: '/search', status_code: 500, query_redacted: `q=1&dg_trip=${trip.nonce}` } };
const finding: Finding = { finding_id: 'f_trip', rule_id: 'R07', rule_version: 'R07@5', incident_id: 'inc_trip',
  src_ip: event.src_ip, technique_ids: ['T1190'], stage: 'exploit_attempt', label: 'Attempt', limitation: 'Not execution',
  evidence_event_ids: ['evt_trip'], created_at: iso(1500), web_attack_class: ['sqli'] };
const health: Health = { ok: true, sensors: {}, sensor_health: { 'web-decoy-01': {
  service: 'up', collection: 'ok', activity: 'recent', process_state: 'running', collector_id: 'adapter',
  heartbeat_at: iso(2000), last_read_at: iso(2000), last_ingest_at: iso(1500), backlog_records: 0,
  oldest_backlog_age_s: 0, error_count: 0, clock_skew_s: 0, last_event_at: iso(1000), ingest: null,
} } };
const verdict = (e: SocEvent | null = event, fs: Finding[] = [finding], h: Health | null = health, at = started + 3000) =>
  tripVerdict(trip, e, fs, h, started + 3000, at);

test('trip passes only with an observed request, its backend alert and current collection', () => {
  assert.equal(verdict().status, 'passed');
  assert.equal(verdict().finding?.finding_id, 'f_trip');
});
test('replay, wrong run/source/sensor/type and old sequence cannot pass', () => {
  for (const patch of [{ capture_mode: 'replay' }, { lab_run_id: 'other' }, { src_ip: '127.0.0.1' },
    { sensor_id: 'ssh-decoy-01' }, { event_type: 'blocked_request' }, { seq: 5 }]) {
    assert.equal(matchesTrip({ ...event, ...patch } as SocEvent, trip), false);
  }
});
test('nonce matching is exact and duplicate query references are refused', () => {
  for (const query of [`dg_trip=${trip.nonce}x`, `other=${trip.nonce}`, `dg_trip=${trip.nonce}&dg_trip=${trip.nonce}`]) {
    assert.equal(matchesTrip({ ...event, attributes: { ...event.attributes, query_redacted: query } }, trip), false);
  }
});
test('wrong method, route and blocked response are not the intended trip', () => {
  for (const patch of [{ method: 'POST' }, { path: '/login' }, { status_code: 403 }]) {
    assert.equal(matchesTrip({ ...event, attributes: { ...event.attributes, ...patch } }, trip), false);
  }
});
test('old, future and invalid timestamps cannot become fresh proof', () => {
  for (const patch of [{ occurred_at: iso(-11000) }, { ingested_at: iso(-3000) },
    { occurred_at: iso(91000) }, { ingested_at: 'invalid' }]) assert.equal(matchesTrip({ ...event, ...patch }, trip), false);
});
test('a request alone and an unrelated finding never prove the alert chain', () => {
  assert.equal(verdict(event, []).status, 'waiting');
  assert.equal(verdict(event, [{ ...finding, evidence_event_ids: ['evt_other'] }]).status, 'waiting');
  assert.equal(verdict(event, [{ ...finding, web_attack_class: ['xss'] }]).status, 'waiting');
  assert.equal(verdict(event, [{ ...finding, incident_id: 'inc_other' }]).status, 'waiting');
});
test('missing or stale collection is distinct from activity', () => {
  assert.equal(verdict(event, [finding], { ok: true, sensors: { 'web-decoy-01': iso(2000) } }).collector, false);
  for (const patch of [{ collection: 'stale' }, { heartbeat_at: iso(-31000) }, { last_read_at: null },
    { last_ingest_at: iso(-5000) }, { backlog_records: 1 }, { process_state: 'stopped' }]) {
    const h = { ...health, sensor_health: { 'web-decoy-01': { ...health.sensor_health!['web-decoy-01']!, ...patch } } } as Health;
    assert.equal(verdict(event, [finding], h).collector, false);
  }
  assert.equal(tripVerdict(trip, event, [finding], health, started - 30000, started + 3000).collector, false);
});
test('missing proof times out and a past pass expires', () => {
  assert.equal(verdict(null, [], health, started + 91000).status, 'incomplete');
  assert.equal(tripVerdict(trip, event, [finding], health, started + 3000,
    started + 3000 + TRIP_VALID_MS + 1, started + 3000).status, 'expired');
});
test('generated command has one fixed lab destination and cannot accept shell syntax as a nonce', () => {
  const command = tripCommand(trip.nonce);
  assert.ok(command.includes('http://192.168.77.20:8080/search'));
  assert.ok(command.includes(`dg_trip=${trip.nonce}`));
  assert.throws(() => tripCommand("'; id"));
});
