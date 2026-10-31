/**
 * Pure wheel model: API data in, what the wheel should show out.
 *
 * No fetching, no React, no clock. Everything here is a lookup or a count over
 * what the backend reported, so a reviewer can check any lit node by following
 * its event ids back to GET /api/events. Nothing is scored or detected here.
 */

import type { Finding, Link, ResponseAction, RuleId, SocEvent } from '../types/api';
import {
  LURES,
  RING_DEPTH,
  TOKEN_BY_ID,
  classify,
  gateOf,
  sectorOfSensor,
  type Lure,
  type LureId,
  type RingId,
  type Token,
} from './manifest';

export type LureState = 'untouched' | 'touched' | 'flagged';

export interface LureView {
  lure: Lure;
  state: LureState;
  /** Events placed on this lure, oldest first. */
  events: SocEvent[];
  /** A gate with no events of its own, lit because traffic in its sector passed it. */
  passedThrough: boolean;
  /** 1-based position in the order the source first reached each lure. */
  order: number | null;
  firstAt: string | null;
  /** Rules whose counted findings cite an event on this lure. */
  rules: RuleId[];
  /** Rules citing this lure that still wait for the analyst. */
  pendingRules: RuleId[];
  findings: Finding[];
}

export type Provenance =
  /** The planted-side event is at the lure that holds the token. */
  | 'bait_read'
  /** Honeytoken link, but the planted-side event is somewhere else. */
  | 'bait_not_read'
  /** Not a honeytoken link: timing and address only. */
  | 'not_token';

export interface ChordView {
  link: Link;
  from: LureId;
  to: LureId;
  token: Token | null;
  fromEvent: SocEvent | undefined;
  toEvent: SocEvent | undefined;
  provenance: Provenance;
  gapSeconds: number | null;
}

export interface GateView {
  /** The newest applied or verified block on this source, if any. */
  action: ResponseAction | null;
  /** blocked_request events: requests that bounced off the closed gate. */
  bounced: SocEvent[];
}

export interface WheelModel {
  lures: Map<LureId, LureView>;
  /** Lures in the order first reached. */
  trail: LureId[];
  chords: ChordView[];
  gate: GateView;
  /** The deepest ring with a touched lure, or null if nothing has. */
  depth: RingId | null;
  touchedCount: number;
  total: number;
  /** event_id -> lure, for chord endpoints and the evidence panel. */
  eventLure: Map<string, LureId>;
}

function chronological(a: SocEvent, b: SocEvent): number {
  const byTime = Date.parse(a.occurred_at) - Date.parse(b.occurred_at);
  return byTime !== 0 ? byTime : a.seq - b.seq;
}

const TOKEN_IN_BASIS = /honeytoken\s+(\S+)/i;

export function tokenOfLink(link: Link): Token | null {
  const match = TOKEN_IN_BASIS.exec(link.basis);
  return match?.[1] ? (TOKEN_BY_ID.get(match[1]) ?? null) : null;
}

export function buildWheel(input: {
  events: SocEvent[];
  findings: Finding[];
  links: Link[];
  actions: ResponseAction[];
  srcIp: string | null;
}): WheelModel {
  const lures = new Map<LureId, LureView>();
  for (const lure of LURES) {
    lures.set(lure.id, {
      lure,
      state: 'untouched',
      events: [],
      passedThrough: false,
      order: null,
      firstAt: null,
      rules: [],
      pendingRules: [],
      findings: [],
    });
  }

  const eventLure = new Map<string, LureId>();
  const trail: LureId[] = [];
  const bounced: SocEvent[] = [];

  const touch = (id: LureId, at: string) => {
    const view = lures.get(id);
    if (!view || view.order !== null) return;
    trail.push(id);
    view.order = trail.length;
    view.firstAt = at;
    view.state = 'touched';
  };

  for (const event of [...input.events].sort(chronological)) {
    const id = classify(event);
    if (id === null) {
      if (event.event_type === 'blocked_request') bounced.push(event);
      continue;
    }
    // A gate is passed on the way in, so it is reached first.
    const gate = gateOf(sectorOfSensor(event.sensor_id));
    if (gate) touch(gate, event.occurred_at);
    touch(id, event.occurred_at);
    lures.get(id)?.events.push(event);
    eventLure.set(event.event_id, id);
  }

  for (const view of lures.values()) {
    view.passedThrough = Boolean(view.lure.gate) && view.order !== null && view.events.length === 0;
  }

  // Findings light a lure when they cite one of its events. Pending findings
  // (R05/R09 before the analyst decides) are listed but do not flag.
  for (const finding of input.findings) {
    const cited = new Set<LureId>();
    for (const eventId of finding.evidence_event_ids) {
      const id = eventLure.get(eventId);
      if (id) cited.add(id);
    }
    for (const id of cited) {
      const view = lures.get(id);
      if (!view) continue;
      view.findings.push(finding);
      const bucket = finding.pending_confirmation ? view.pendingRules : view.rules;
      if (!bucket.includes(finding.rule_id)) bucket.push(finding.rule_id);
    }
  }
  for (const view of lures.values()) {
    if (view.rules.length > 0) view.state = 'flagged';
  }

  const eventsById = new Map(input.events.map((event) => [event.event_id, event]));
  const chords: ChordView[] = input.links.map((link) => {
    const token = tokenOfLink(link);
    const from =
      eventLure.get(link.from_event_id) ?? gateOf(sectorOfSensor(link.from_sensor)) ?? 'ssh:gate';
    const to =
      eventLure.get(link.to_event_id) ?? gateOf(sectorOfSensor(link.to_sensor)) ?? 'web:gate';
    const fromEvent = eventsById.get(link.from_event_id);
    const toEvent = eventsById.get(link.to_event_id);
    const gapSeconds =
      fromEvent && toEvent
        ? Math.round((Date.parse(toEvent.occurred_at) - Date.parse(fromEvent.occurred_at)) / 1000)
        : null;
    const provenance: Provenance = token
      ? from === token.plantedAt
        ? 'bait_read'
        : 'bait_not_read'
      : 'not_token';
    return { link, from, to, token, fromEvent, toEvent, provenance, gapSeconds };
  });

  const live = input.actions
    .filter(
      (action) =>
        action.target_ip === input.srcIp &&
        (action.status === 'applied' || action.status === 'verified'),
    )
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));

  let depth: RingId | null = null;
  let touchedCount = 0;
  for (const view of lures.values()) {
    if (view.state === 'untouched') continue;
    touchedCount += 1;
    if (depth === null || RING_DEPTH[view.lure.ring] > RING_DEPTH[depth]) depth = view.lure.ring;
  }

  return {
    lures,
    trail,
    chords,
    gate: { action: live[0] ?? null, bounced },
    depth,
    touchedCount,
    total: LURES.length,
    eventLure,
  };
}
