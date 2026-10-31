/**
 * Fixture backend. Stands in for M3's API so the whole UI can be built before
 * the backend exists (M1_frontend.md step 0b).
 *
 * This module IS the mock backend, so it is the one place allowed to synthesise
 * backend-issued fields (event_id, seq, ingested_at, incident_id). Screens must
 * never do this — they display what the API gives them.
 *
 * The fixture is imported read-only from contracts/, which M3 owns. It is not
 * copied into frontend/, so it cannot drift from the contract.
 *
 * Behaviour: the first N-10 events come back from the REST snapshot, the last 10
 * arrive over the fake socket on a timer. That exercises both code paths — the
 * snapshot and the live append — which is the whole point of having fixtures.
 */

import fixtureFile from '../../../contracts/examples/events_p3.json';
import type {
  EventsPage,
  Health,
  IncidentSummary,
  IngestEvent,
  SocEvent,
  WsMessage,
} from '../types/api';
import type { EventsQuery } from './client';

/** How many trailing events are withheld from the snapshot and streamed live. */
const STREAMED_TAIL = 10;

/** Delay between streamed fixture events. */
const STREAM_INTERVAL_MS = 1200;

/** Simulated network latency, so loading states are actually visible in dev. */
const FAKE_LATENCY_MS = 180;

const rawEvents = (fixtureFile as { events: unknown[] }).events as unknown as IngestEvent[];

/**
 * Backend-issued fields, applied deterministically so a reload shows the same
 * IDs. incident_id groups by src_ip, which is what the real backend does
 * (AGENTS.md section 4: one incident per src_ip per lab_run_id).
 */
const ALL_EVENTS: SocEvent[] = (() => {
  const incidentBySrcIp = new Map<string, string>();
  return rawEvents.map((event, index) => {
    let incidentId = incidentBySrcIp.get(event.src_ip);
    if (!incidentId) {
      incidentId = `inc_${String(incidentBySrcIp.size + 1).padStart(2, '0')}`;
      incidentBySrcIp.set(event.src_ip, incidentId);
    }
    return {
      ...event,
      event_id: `evt_${event.source_record_id.slice(0, 8)}`,
      seq: index + 1,
      ingested_at: event.occurred_at,
      incident_id: incidentId,
    };
  });
})();

const SNAPSHOT_COUNT = Math.max(1, ALL_EVENTS.length - STREAMED_TAIL);

/**
 * Highest seq the fake backend has "committed". Grows as the stream advances, so
 * a reconnect-triggered snapshot reload returns everything released so far
 * rather than losing the streamed rows.
 */
let releasedSeq = ALL_EVENTS[SNAPSHOT_COUNT - 1]?.seq ?? 0;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function released(): SocEvent[] {
  return ALL_EVENTS.filter((event) => event.seq <= releasedSeq);
}

export async function fetchEvents(query: EventsQuery = {}): Promise<EventsPage> {
  await sleep(FAKE_LATENCY_MS);

  let items = released();
  if (query.incident_id) items = items.filter((e) => e.incident_id === query.incident_id);
  if (query.sensor_id) items = items.filter((e) => e.sensor_id === query.sensor_id);
  if (query.since_seq !== undefined) {
    const since = query.since_seq;
    items = items.filter((e) => e.seq > since);
  }

  const limit = query.limit ?? 200;
  // Newest first, matching how the feed renders.
  const ordered = [...items].sort((a, b) => b.seq - a.seq).slice(0, limit);
  const nextSeq = items.reduce((max, e) => Math.max(max, e.seq), 0);

  return { items: ordered, next_seq: nextSeq };
}

export async function fetchHealth(): Promise<Health> {
  await sleep(FAKE_LATENCY_MS);
  const sensors: Record<string, string | null> = {
    'ssh-decoy-01': null,
    'web-decoy-01': null,
  };
  for (const event of released()) {
    const current = sensors[event.sensor_id];
    if (current === null || current === undefined || event.occurred_at > current) {
      sensors[event.sensor_id] = event.occurred_at;
    }
  }
  return { ok: true, sensors };
}

/**
 * Placeholder incidents so sidebar counts and navigation work before M3 ships.
 * Score and severity here are NOT computed from the events — the real backend
 * owns scoring (config/scoring.yaml). These are stand-in values, and the
 * FIXTURES chip in the topbar makes that visible on screen.
 */
export async function fetchIncidents(): Promise<{ items: IncidentSummary[] }> {
  await sleep(FAKE_LATENCY_MS);
  const byIncident = new Map<string, SocEvent[]>();
  for (const event of released()) {
    const id = event.incident_id ?? 'inc_unknown';
    const bucket = byIncident.get(id);
    if (bucket) bucket.push(event);
    else byIncident.set(id, [event]);
  }

  const items: IncidentSummary[] = [];
  for (const [incidentId, events] of byIncident) {
    const first = events[0];
    if (!first) continue;
    const times = events.map((e) => e.occurred_at).sort();
    items.push({
      incident_id: incidentId,
      src_ip: first.src_ip,
      lab_run_id: first.lab_run_id,
      score: 0,
      severity: 'low',
      stages_observed: [],
      first_seen: times[0] ?? first.occurred_at,
      last_seen: times[times.length - 1] ?? first.occurred_at,
      event_count: events.length,
    });
  }
  return { items };
}

export interface FixtureSocket {
  close: () => void;
}

/**
 * Fake WebSocket. Emits the withheld tail of the fixture as `type: "event"`
 * messages, in order, then goes quiet while staying "open".
 */
export function openFixtureSocket(onMessage: (message: WsMessage) => void): FixtureSocket {
  let index = SNAPSHOT_COUNT;
  let stopped = false;

  const timer = setInterval(() => {
    if (stopped) return;
    const event = ALL_EVENTS[index];
    if (!event) {
      clearInterval(timer);
      return;
    }
    index += 1;
    releasedSeq = Math.max(releasedSeq, event.seq);
    onMessage({ seq: event.seq, type: 'event', data: event });
  }, STREAM_INTERVAL_MS);

  return {
    close: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}
