/**
 * Contract v1.2 consumer checks against M3's PROVISIONAL fixtures
 * (src/v12/provisional/m3_telemetry_v1_2.json, from PR #19 @ eb2a94e).
 * Provisional until the gateway, demo-app, MySQL and SMB producers exist.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  archiveEvidence, credentialOf, dbOf, fileOf, hasTranscript, ingressOf, responseScope, sourceRows,
} from '../src/v12/views.ts';
import type { BackendEligibility, Health, SocEvent } from '../src/types/api.ts';

const fx = JSON.parse(readFileSync(new URL('../src/v12/provisional/m3_telemetry_v1_2.json', import.meta.url), 'utf8'));
const events: SocEvent[] = fx.events_valid.map((e: Record<string, unknown>, i: number) => ({
  ...e, event_id: `evt_${i}`, seq: i + 1, ingested_at: e['occurred_at'], incident_id: 'inc_x',
}));
const byType = (sensor: string, type: string) => events.filter((e) => e.sensor_id === sensor && e.event_type === type);

test('fixture is labelled provisional', () => {
  assert.equal(fx.provisional, true);
  assert.match(fx._m1_provenance, /PROVISIONAL/);
});

test('sources: served registry lists four honeypots and two separate telemetry sources', () => {
  const registry = {
    registry_version: '1.2',
    honeypots: fx.expected_reads.sources_excerpt.honeypots.map((id: string) => ({ source_id: id, source_kind: 'honeypot',
      protocol: 'x', label: id, event_schema_versions: ['1.2'], event_types: [], binding: { host: 'h', port: 1, status: 'proposed' }, response: { block: 'unsupported' } })),
    telemetry_sources: fx.expected_reads.sources_excerpt.telemetry_sources.map((id: string) => ({ source_id: id, source_kind: 'gateway',
      protocol: 'http', label: id, telemetry_versions: ['1.0'], record_types: [], binding: { host: 'h', port: null, status: 'proposed' }, response: { block: 'not_applicable' } })),
    honeypot_count: 4,
  };
  const health: Health = { ok: true, sensors: {}, sensor_health: {},
    telemetry_health: { 'gateway-01': fx.expected_reads.health_excerpt.telemetry_health_row } };
  const rows = sourceRows(registry, health);
  assert.deepEqual(rows.honeypots.map((r) => r.source_id), ['ssh-decoy-01', 'web-decoy-01', 'db-decoy-01', 'file-decoy-01']);
  assert.deepEqual(rows.telemetry.map((r) => r.source_id), ['gateway-01', 'demo-app-01']);
  assert.equal(rows.honeypot_count, 4);
  // gateway health comes from telemetry_health; demo-app sent none, and none is invented
  assert.equal(rows.telemetry[0]?.health?.counted_as_honeypot, false);
  assert.equal(rows.telemetry[1]?.health, null);
  assert.ok(rows.honeypots.every((r) => r.health === null));
});

test('sources: without /api/sources, rows are marked fallback and carry no binding claims', () => {
  const rows = sourceRows(null, { ok: true, sensors: { 'ssh-decoy-01': '2026-11-02T05:00:00Z' } });
  assert.ok(rows.honeypots.every((r) => r.registry === 'fallback' && r.entry === null));
  assert.equal(rows.honeypots[0]?.last_event_at, '2026-11-02T05:00:00Z');
  assert.equal(rows.honeypot_count, null);
});

test('db: credential evidence is a proof check, never a password hash; db_request never executed', () => {
  const fail = byType('db-decoy-01', 'auth_failure')[0]!;
  assert.equal(credentialOf(fail)?.proof_check, 'not_matched');
  assert.equal(fail.attributes?.password_sha256, undefined);
  const ok = byType('db-decoy-01', 'auth_success')[0]!;
  assert.equal(credentialOf(ok)?.proof_check, 'matched_honeytoken');
  const request = byType('db-decoy-01', 'db_request')[0]!;
  assert.equal(dbOf(request)?.execution, 'not_supported');
  assert.equal(dbOf(request)?.statement_verb, 'select');
  assert.equal(hasTranscript('db-decoy-01'), false);
  assert.equal(hasTranscript('file-decoy-01'), false);
  assert.equal(hasTranscript('ssh-decoy-01'), true);
});

test('file: uploads are inert with a type hint, never a verdict', () => {
  const write = byType('file-decoy-01', 'file_operation').find((e) => fileOf(e)?.operation === 'write')!;
  assert.equal(fileOf(write)?.storage, 'quarantined_inert');
  assert.equal(fileOf(write)?.magic_type_hint, 'pe');
  assert.ok(!JSON.stringify(write.attributes).match(/verdict|malware|malicious/));
});

test('ingress: verified and absent contexts are read as reported', () => {
  const via = byType('web-decoy-01', 'http_request').find((e) => ingressOf(e)?.gateway_context === 'verified')!;
  assert.equal(ingressOf(via)?.gateway_request_id, 'gw_00000000000002');
  const direct = byType('web-decoy-01', 'http_request').find((e) => ingressOf(e)?.gateway_context === 'absent')!;
  assert.equal(ingressOf(direct)?.gateway_request_id, undefined);
});

test('archive: served and requested observed; download and extraction never claimed; token use cites links', () => {
  const served = byType('web-decoy-01', 'bait_served')[0]!;
  const dbUse = byType('db-decoy-01', 'auth_success')[0]!;
  const link = { link_id: 'l1', from_event_id: served.event_id, to_event_id: dbUse.event_id, to_sensor: 'db-decoy-01',
    kind: fx.expected_reads.token_link_db.kind, basis: fx.expected_reads.token_link_db.basis, status: 'open',
    attribution: fx.expected_reads.token_link_db.attribution };
  const [archive] = archiveEvidence(events, [link]);
  assert.ok(archive);
  assert.deepEqual(archive.honeytoken_ids, ['tok_db_01', 'tok_smb_01']);
  const state = Object.fromEntries(archive.claims.map((c) => [c.claim, c.state]));
  assert.equal(state['served'], 'observed');
  assert.equal(state['client_completed_download'], 'never_observable');
  assert.equal(state['extracted_or_opened'], 'never_observable');
  assert.equal(state['planted_credential_used'], 'observed');
  assert.match(archive.claims.at(-1)!.detail!, /unique/);
  // ambiguous attribution stays visible, it is not resolved by the UI
  const [ambiguous] = archiveEvidence(events, [{ ...link, attribution: 'ambiguous' }]);
  assert.match(ambiguous!.claims.at(-1)!.detail!, /ambiguous/);
  // no link: credential use not observed, nothing invented
  const [none] = archiveEvidence(events, []);
  assert.equal(none!.claims.at(-1)!.state, 'not_observed');
});

test('response scope: db case is unsupported; the block is web-only; v1.1 still never claims universal', () => {
  const db = fx.expected_reads.eligibility_db_case;
  const eligibility: BackendEligibility = { eligible: db.eligible, reasons: db.reasons_include, capture_mode: 'live',
    lab_run_id: db.lab_run_id, target_ip: db.target_ip, checked_at: 'x', last_web_observation_at: null, response_scope: db.response_scope };
  const view = responseScope(eligibility);
  assert.deepEqual(view.enforced_on, ['web-decoy-01']);
  assert.ok(view.not_enforced_on.includes('db-decoy-01') && view.not_enforced_on.includes('file-decoy-01'));
  assert.equal(view.unsupported_sensor, true);
  assert.equal(view.stated_by_backend, true);
  const v11 = responseScope({ ...eligibility, response_scope: undefined, reasons: [] });
  assert.deepEqual(v11.enforced_on, ['web-decoy-01']);
  assert.equal(v11.stated_by_backend, false);
});

test('health: a v1.1 backend reporting two sensors never gets fabricated rows for the v1.2 decoys', async () => {
  const { healthFromV1 } = await import('../src/evidence/fromV1.ts');
  const { SENSOR_IDS } = await import('../src/types/api.ts');
  const row = { service: 'up', collection: 'ok', activity: 'recent', collector_id: 'c', process_state: 'running',
    heartbeat_at: null, last_read_at: null, last_ingest_at: null, backlog_records: 0, oldest_backlog_age_s: 0,
    error_count: 0, clock_skew_s: 0, last_event_at: null, ingest: null } as const;
  const view = healthFromV1({ ok: true, sensors: { 'ssh-decoy-01': null, 'web-decoy-01': null },
    sensor_health: { 'ssh-decoy-01': row, 'web-decoy-01': row } }, null, SENSOR_IDS);
  assert.deepEqual(view.collectors?.map((c) => c.sensor_id), ['ssh-decoy-01', 'web-decoy-01']);
  assert.deepEqual(view.activity.map((a) => a.sensor_id), ['ssh-decoy-01', 'web-decoy-01']);
});

test('archive: another client requesting the same path never counts as this serving\'s request', () => {
  const served = byType('web-decoy-01', 'bait_served')[0]!;
  const otherClient: SocEvent = { ...byType('web-decoy-01', 'synthetic_file_access')[0]!, event_id: 'evt_other', event_type: 'http_request',
    src_ip: '192.168.77.11', attributes: { path: '/backup/backup.zip', request_id: 'req-other' } };
  const [archive] = archiveEvidence([served, otherClient], []);
  const requested = archive!.claims.find((c) => c.claim === 'requested')!;
  assert.equal(requested.state, 'not_observed');
  assert.deepEqual(requested.event_ids, []);
});

test('ui guard: a db/file-only source is never offered the web block; ChakraView never maps db/file events', async () => {
  const { eligibilityFromV1 } = await import('../src/evidence/fromV1.ts');
  const { classify } = await import('../src/chakra/manifest.ts');
  const dbOnly = events.filter((e) => e.sensor_id === 'db-decoy-01');
  const guard = eligibilityFromV1(dbOnly);
  assert.equal(guard.eligible, false);
  assert.ok(guard.reasons.some((r) => r.code === 'response_unsupported_sensor'));
  assert.equal(eligibilityFromV1(events.filter((e) => e.sensor_id === 'web-decoy-01')).eligible, true);
  for (const e of events.filter((x) => x.sensor_id === 'db-decoy-01' || x.sensor_id === 'file-decoy-01')) {
    assert.equal(classify(e), null);
  }
});
