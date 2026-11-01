/**
 * Review T14: "WebSocket drop during new events — snapshot/live reconciliation
 * has no unexplained missing or duplicate IDs."
 *
 * Run: npm test   (node --test with type stripping; Node 22.6 or newer)
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { FeedReconciler, mergeById } from '../src/state/reconcile.ts';
import type { SocEvent } from '../src/types/api.ts';

function ev(seq: number): SocEvent {
  return {
    schema_version: '1.0',
    source_record_id: `rec-${seq}`,
    sensor_id: 'ssh-decoy-01',
    event_type: 'auth_failure',
    occurred_at: new Date(Date.UTC(2026, 10, 1, 4, 30, seq)).toISOString(),
    src_ip: '192.168.77.10',
    lab_run_id: 'run-test',
    capture_mode: 'live',
    event_id: `evt_${String(seq).padStart(4, '0')}`,
    seq,
    ingested_at: new Date(Date.UTC(2026, 10, 1, 4, 30, seq)).toISOString(),
    incident_id: 'inc_01',
  };
}
const range = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => ev(from + i));
const ids = (events: SocEvent[]) => events.map((e) => e.event_id);

function assertExactly(events: SocEvent[], expectedSeqs: number[]) {
  const got = ids(events);
  assert.equal(new Set(got).size, got.length, `duplicate ids: ${got.join(',')}`);
  assert.deepEqual([...got].sort(), expectedSeqs.map((s) => ev(s).event_id).sort());
}

test('the old race: live events committed after the snapshot query are kept', () => {
  const r = new FeedReconciler(500);
  r.beginSnapshot();
  // Query ran when 1..10 were committed; 11..13 arrive over the socket before it returns.
  for (const e of range(11, 13)) assert.equal(r.acceptLive(e), 'buffered');
  const out = r.completeSnapshot(range(1, 10));
  assertExactly(out.events, range(1, 13).map((e) => e.seq));
  assert.equal(out.lastSeq, 13);
  assert.equal(out.rescued, 3);
  // and the socket carries on from 14 without a gap
  assert.equal(r.acceptLive(ev(14)), 'applied');
});

test('overlap: socket events that the snapshot already holds are not doubled', () => {
  const r = new FeedReconciler(500);
  r.beginSnapshot();
  for (const e of range(8, 12)) r.acceptLive(e);
  const out = r.completeSnapshot(range(1, 10));
  assertExactly(out.events, range(1, 12).map((e) => e.seq));
  assert.equal(out.rescued, 2);
});

test('steady state rejects replays of the same id and anything at or under the gate', () => {
  const r = new FeedReconciler(500);
  r.beginSnapshot();
  r.completeSnapshot(range(1, 5));
  assert.equal(r.acceptLive(ev(6)), 'applied');
  assert.equal(r.acceptLive(ev(6)), 'duplicate');
  assert.equal(r.acceptLive(ev(3)), 'duplicate');
});

test('a reconnect mid-stream: drop, events during the outage, new snapshot', () => {
  const r = new FeedReconciler(500);
  r.beginSnapshot();
  let shown = r.completeSnapshot(range(1, 5)).events;
  for (const e of range(6, 8)) {
    assert.equal(r.acceptLive(e), 'applied');
    shown = mergeById([shown, [e]], 500);
  }
  // socket drops; 9..15 are committed while disconnected; reconnect starts a
  // snapshot, and 16..17 arrive on the new socket before it returns
  r.beginSnapshot();
  for (const e of range(16, 17)) r.acceptLive(e);
  const out = r.completeSnapshot(range(1, 15), shown);
  assertExactly(out.events, range(1, 17).map((e) => e.seq));
});

test('overlapping snapshot loads: the superseded one is abandoned, nothing sticks in buffering', () => {
  const r = new FeedReconciler(500);
  r.beginSnapshot(); // mount
  r.acceptLive(ev(4));
  r.beginSnapshot(); // socket connected: a second load
  r.acceptLive(ev(5));
  r.abandonSnapshot(); // the first result is discarded by the store's token guard
  assert.equal(r.snapshotInFlight, true);
  const out = r.completeSnapshot(range(1, 3));
  assertExactly(out.events, [1, 2, 3, 4, 5]);
  assert.equal(r.snapshotInFlight, false);
  assert.equal(r.acceptLive(ev(6)), 'applied');
});

test('a failed snapshot keeps what was on screen plus the buffer', () => {
  const r = new FeedReconciler(500);
  r.beginSnapshot();
  const shown = r.completeSnapshot(range(1, 3)).events;
  r.beginSnapshot();
  r.acceptLive(ev(4));
  const kept = r.failSnapshot(shown);
  assertExactly(kept, [1, 2, 3, 4]);
  assert.equal(r.snapshotInFlight, false);
});

test('the cap keeps the newest, still without duplicates', () => {
  const r = new FeedReconciler(5);
  r.beginSnapshot();
  for (const e of range(9, 12)) r.acceptLive(e);
  const out = r.completeSnapshot(range(1, 10));
  assert.deepEqual(ids(out.events), [12, 11, 10, 9, 8].map((s) => ev(s).event_id));
});

test('randomised: any interleaving of snapshot, overlap and socket order loses nothing', () => {
  let seed = 7;
  const rand = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
  for (let round = 0; round < 500; round += 1) {
    const r = new FeedReconciler(10_000);
    const total = 20 + Math.floor(rand() * 60);
    const boundary = Math.floor(rand() * total); // what the snapshot query saw
    const liveFrom = Math.max(1, boundary - Math.floor(rand() * 5)); // socket may overlap
    r.beginSnapshot();
    const live = range(liveFrom, total);
    const early = Math.floor(rand() * live.length);
    for (const e of live.slice(0, early)) r.acceptLive(e); // during the load
    let shown = r.completeSnapshot(range(1, boundary)).events;
    for (const e of live.slice(early)) {
      if (r.acceptLive(e) === 'applied') shown = mergeById([shown, [e]], 10_000);
    }
    for (const e of live) r.acceptLive(e); // a socket replay changes nothing
    assertExactly(shown, range(1, total).map((e) => e.seq));
  }
});
