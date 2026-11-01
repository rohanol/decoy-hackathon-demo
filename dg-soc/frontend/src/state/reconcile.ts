/**
 * Snapshot/live reconciliation for the event feed. Pure: no React, no fetch,
 * no clock, only a type import, so it runs under `node --test` as-is.
 *
 * The protocol (contracts/API.md, review section 13):
 *   on every (re)connection, load a REST snapshot, then apply /ws/events.
 *
 * The race this closes: a snapshot query returns everything committed up to
 * the moment it ran. Events that arrive over the socket while the snapshot is
 * still loading may or may not be in it. The old store replaced its list with
 * the snapshot and reset its seq gate to the snapshot's maximum, so an event
 * delivered during the load but committed after the query vanished from the
 * feed and was never redelivered.
 *
 * Here, live events that arrive while a snapshot is in flight are buffered,
 * and the snapshot is merged with that buffer by event_id when it lands.
 * Nothing is ever replaced blindly, so there is no window in which an event
 * can be dropped, and nothing is ever appended twice.
 */

import type { SocEvent } from '../types/api';

export type LiveResult =
  /** New: render it. */
  | 'applied'
  /** A snapshot is loading: held for the merge, and safe to render now. */
  | 'buffered'
  /** Already held, by event_id. Ignore. */
  | 'duplicate';

export interface SnapshotResult {
  /** Newest first, capped. */
  events: SocEvent[];
  /** Highest seq now known, from either the snapshot or the buffer. */
  lastSeq: number;
  /** How many buffered live events were not in the snapshot. */
  rescued: number;
  /** Distinct events in the snapshot plus the buffer, before the cap. */
  total: number;
}

/** Newest first by seq; event_id breaks ties so the order is total. */
function newestFirst(a: SocEvent, b: SocEvent): number {
  if (b.seq !== a.seq) return b.seq - a.seq;
  return a.event_id < b.event_id ? -1 : a.event_id > b.event_id ? 1 : 0;
}

/** Union by event_id, newest first, capped. The later copy of an id wins. */
export function mergeById(lists: SocEvent[][], cap: number): SocEvent[] {
  const byId = new Map<string, SocEvent>();
  for (const list of lists) for (const event of list) byId.set(event.event_id, event);
  return [...byId.values()].sort(newestFirst).slice(0, cap);
}

export class FeedReconciler {
  private readonly cap: number;
  private lastSeq = 0;
  /** Every id currently held, so a socket replay or an overlap is never shown twice. */
  private known = new Set<string>();
  /** Live events seen since the oldest snapshot still in flight began. */
  private pending: SocEvent[] = [];
  private inFlight = 0;

  constructor(cap: number) {
    this.cap = cap;
  }

  /** Call before issuing the snapshot query. Loads may overlap; each is counted. */
  beginSnapshot(): void {
    this.inFlight += 1;
  }

  /** A live event from the socket. */
  acceptLive(event: SocEvent): LiveResult {
    if (this.inFlight > 0) {
      // Seq cannot be trusted as a gate mid-snapshot: hold everything, dedupe
      // by id at the merge.
      if (this.pending.some((held) => held.event_id === event.event_id)) return 'duplicate';
      this.pending.push(event);
      this.lastSeq = Math.max(this.lastSeq, event.seq);
      return 'buffered';
    }
    if (this.known.has(event.event_id)) return 'duplicate';
    // Steady state: the socket delivers in seq order, so anything at or below
    // the gate has already been applied.
    if (event.seq <= this.lastSeq) return 'duplicate';
    this.known.add(event.event_id);
    this.lastSeq = event.seq;
    return 'applied';
  }

  /**
   * The snapshot returned. Merges it with every live event buffered since the
   * load began. Pass `current` = what is on screen, which is kept only when
   * `keepCurrent` is set (a snapshot that failed part-way).
   */
  completeSnapshot(snapshot: SocEvent[], current: SocEvent[] = [], keepCurrent = false): SnapshotResult {
    this.inFlight = Math.max(0, this.inFlight - 1);
    const snapshotIds = new Set(snapshot.map((event) => event.event_id));
    const rescued = this.pending.filter((event) => !snapshotIds.has(event.event_id)).length;
    const lists = keepCurrent ? [current, snapshot, this.pending] : [snapshot, this.pending];
    const total = new Set(lists.flat().map((event) => event.event_id)).size;
    const events = mergeById(lists, this.cap);
    const snapshotMax = snapshot.reduce((max, event) => Math.max(max, event.seq), 0);
    const pendingMax = this.pending.reduce((max, event) => Math.max(max, event.seq), 0);
    this.lastSeq = Math.max(snapshotMax, pendingMax, keepCurrent ? this.lastSeq : 0);
    this.known = new Set(events.map((event) => event.event_id));
    if (this.inFlight === 0) this.pending = [];
    return { events, lastSeq: this.lastSeq, rescued, total };
  }

  /**
   * A newer snapshot superseded this one, so its result is discarded. Every
   * beginSnapshot must end in complete, fail or abandon, or the feed would
   * buffer forever.
   */
  abandonSnapshot(): void {
    this.inFlight = Math.max(0, this.inFlight - 1);
  }

  /** A snapshot load failed. Keep what is on screen plus anything buffered. */
  failSnapshot(current: SocEvent[]): SocEvent[] {
    this.inFlight = Math.max(0, this.inFlight - 1);
    const events = mergeById([current, this.pending], this.cap);
    for (const event of events) this.known.add(event.event_id);
    if (this.inFlight === 0) this.pending = [];
    return events;
  }

  get highestSeq(): number {
    return this.lastSeq;
  }

  get snapshotInFlight(): boolean {
    return this.inFlight > 0;
  }
}
