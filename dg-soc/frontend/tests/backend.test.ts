/** Captured local integrated API shapes, not invented frontend groupings. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import type { Incident } from '../src/types/api';
import { evidenceFromBackend, type BackendContext } from '../src/evidence/fromBackend.ts';
import { healthFromV1 } from '../src/evidence/fromV1.ts';
import { SENSOR_IDS } from '../src/types/api.ts';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/prototype_v11.json', import.meta.url), 'utf8'));
const context: BackendContext = fixture;
const incident: Incident = fixture.incident;

test('authoritative cases keep backend identities and scores without a source score', () => {
  const view = evidenceFromBackend(incident, context);
  assert.ok(view.cases.length >= 3);
  assert.ok(view.cases.every(item => item.authority === 'backend_case' && context.cases.some(row => row.incident_id === item.case_id && row.score === item.score)));
  assert.equal(view.profile.source_score, null);
  assert.equal(new Set(view.cases.filter(item => item.sensor_id === 'web-decoy-01' && item.session_id).map(item => item.session_id)).size, 3);
});

test('token provenance uses an actual bait_served endpoint', () => {
  const relation = evidenceFromBackend(incident, context).relations.find(item => item.kind === 'strong_candidate');
  assert.ok(relation?.bait?.served);
  assert.equal(relation.bait.status, 'served_then_presented');
  assert.equal(relation.bait.asset_id, 'web:/.env');
  assert.equal(relation.bait.v1_planted_side_event_id, null);
  assert.equal(context.events.find(event => event.event_id === relation.bait?.served?.event_id)?.event_type, 'bait_served');
});

test('confirmation never invents a parent; a real backend investigation supplies its score', () => {
  const confirmedIncident = fixture.confirmed.incident as Incident;
  assert.equal(evidenceFromBackend(confirmedIncident, context).parents.length, 0);
  const view = evidenceFromBackend(confirmedIncident, { ...context, cases: fixture.confirmed.cases });
  assert.equal(view.parents.length, 1);
  const parent = fixture.confirmed.cases.find((item: { case_kind: string }) => item.case_kind === 'investigation');
  assert.equal(view.parents[0]?.parent_id, parent.incident_id);
  assert.equal(view.parents[0]?.score, parent.score);
});

test('health and response eligibility are read from the actual backend', () => {
  const health = healthFromV1(fixture.health, null, SENSOR_IDS);
  assert.equal(health.basis, 'contract_v11');
  assert.equal(health.collectors?.length, 2);
  assert.ok(health.collectors?.every(item => item.process_state === 'running' && item.ingest));
  const view = evidenceFromBackend(incident, { ...context, eligibility: { ...context.eligibility,
    eligible: false, reasons: [{ code: 'replay_data', message: 'replay' }] } });
  assert.deepEqual(view.eligibility, { source: 'backend', eligible: false, reasons: [{ code: 'replay_data', message: 'replay' }] });
});
