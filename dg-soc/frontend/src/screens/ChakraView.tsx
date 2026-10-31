/**
 * ChakraView — the fiction, and how far into it a source walked.
 *
 * The wheel is the lie the lab tells: every lure on its own spoke, the
 * perimeter outside, the synthetic crown jewel at the centre, the SSH decoy on
 * the left half and the web decoy on the right. It starts complete and dim,
 * then lights lure by lure as events arrive.
 *
 * Encoding (fixed, so it can be explained in one breath):
 *   radius    depth into the fiction
 *   half      which decoy
 *   number    the order the source first reached each lure
 *   red ring  a backend finding cites an event on that lure
 *   chord     a cross-decoy link, arcing over the crown. Dashed while it is a
 *             candidate, solid once the analyst confirms it
 *   outer arc a block on the web decoy's gate, solid once verified
 *
 * Law 1 holds: a lure is lit because GET /api/events placed an event on it, a
 * ring is red because a finding cites one of its events, a chord exists
 * because the API reported a link. The wheel never decides anything; the
 * manifest only says where in the fiction each event landed.
 *
 * Inline SVG, no library, deterministic layout, and nothing ever spins.
 */

import { Box, Eye, Layers, RefreshCw } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import type { CameraView } from '../chakra/Chakra3D';
import { Timeline } from '../chakra/Timeline';
import { ErrorBoundary, webglAvailable } from '../components/ErrorBoundary';
import {
  ApiError,
  fetchActions,
  fetchEvents,
  fetchIncident,
  fetchIncidents,
} from '../api/client';
import { EVENTS_PAGE_LIMIT, MAX_SNAPSHOT_PAGES } from '../api/config';
import { LinkDecisionModal } from '../components/LinkDecisionModal';
import { AttackerText, ErrorCard } from '../components/primitives';
import { ACTION_STATUS_LABEL, SENSOR_LABEL, eventTypeLabel, linkPhrase } from '../copy';
import { buildWheel, type ChordView, type LureView, type WheelModel } from '../chakra/model';
import {
  LURES,
  LURE_BY_ID,
  RINGS,
  type LureId,
  type Ring,
  type RingId,
} from '../chakra/manifest';
import { number, timeUtcZ } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import type {
  Incident,
  IncidentSummary,
  Link,
  ResponseAction,
  SocEvent,
} from '../types/api';
import { GraphViewToggle } from './GraphViewToggle';

/* ---------- geometry ---------- */

const W = 880;
const H = 800;
const CX = 440;
const CY = 400;
const NODE_R = 13;
const CROWN_R = 44;
const GATE_ARC_R = 340;
const BOUNCE_R = 372;
const PERIMETER_R = RINGS[0]?.radius ?? 316;
/** Gate labels sit outside the block arc, so they never collide with it. */
const GATE_LABEL_GAP = 44;

const ACTIONS_POLL_MS = 2000;
/** Slower while the response router is not installed, so it is noticed when it lands. */
const ACTIONS_POLL_UNAVAILABLE_MS = 10_000;

// three.js is heavy; the 3D scene loads only when ChakraView is opened.
const Chakra3D = lazy(() => import('../chakra/Chakra3D'));

const CAMERA_VIEWS: { id: CameraView; label: string; icon: typeof Box }[] = [
  { id: 'orbit', label: 'Orbit', icon: Box },
  { id: 'top', label: 'Top', icon: Eye },
  { id: 'side', label: 'Depth', icon: Layers },
];

function polar(radius: number, degrees: number): [number, number] {
  const radians = (degrees * Math.PI) / 180;
  return [CX + radius * Math.cos(radians), CY + radius * Math.sin(radians)];
}

function ringRadius(id: RingId): number {
  return RINGS.find((ring) => ring.id === id)?.radius ?? 0;
}

function lurePoint(id: LureId): [number, number] {
  const lure = LURE_BY_ID.get(id);
  if (!lure || lure.ring === 'crown') return [CX, CY];
  return polar(ringRadius(lure.ring), lure.angle);
}

/** Which decoy a lure's traffic arrives on. The crown sits behind the web decoy. */
function lureSide(id: LureId): 'ssh' | 'web' {
  const lure = LURE_BY_ID.get(id);
  return lure?.sector === 'ssh' ? 'ssh' : 'web';
}

/**
 * A chord between two lures, bowed away from the centre and biased upward so
 * every chord arcs over the crown instead of through it. Returns the path and
 * its midpoint, where the label sits.
 */
interface ChordGeometry {
  d: string;
  /** Endpoints and control point, so a label can be placed anywhere along the curve. */
  a: [number, number];
  c: [number, number];
  b: [number, number];
}

function chordGeometry(from: LureId, to: LureId, bow: number): ChordGeometry {
  const [ax, ay] = lurePoint(from);
  const [bx, by] = lurePoint(to);
  const mx = (ax + bx) / 2;
  const my = (ay + by) / 2;
  let vx = (mx - CX) * 0.5;
  let vy = (my - CY) * 0.5 - 100;
  const length = Math.hypot(vx, vy) || 1;
  vx /= length;
  vy /= length;
  const cx = mx + vx * bow;
  const cy = my + vy * bow;
  return { d: `M ${ax} ${ay} Q ${cx} ${cy} ${bx} ${by}`, a: [ax, ay], c: [cx, cy], b: [bx, by] };
}

function pointOnChord(g: ChordGeometry, t: number): [number, number] {
  const u = 1 - t;
  return [
    u * u * g.a[0] + 2 * u * t * g.c[0] + t * t * g.b[0],
    u * u * g.a[1] + 2 * u * t * g.c[1] + t * t * g.b[1],
  ];
}

function chordLabel(chord: ChordView): string {
  const subject = chord.token ? chord.token.id : 'same source';
  const status =
    chord.link.status === 'confirmed'
      ? 'confirmed'
      : chord.link.status === 'rejected'
        ? 'rejected'
        : 'awaiting analyst';
  return `${subject} · ${status}`;
}

const LABEL_H = 24;
const labelWidth = (label: string) => label.length * 6.4 + 18;

interface PlacedChord {
  chord: ChordView;
  geometry: ChordGeometry;
  label: string;
  at: [number, number];
}

/**
 * Lay out every chord, then place its label where it collides with no label
 * already placed. Honeytoken links are placed first and drawn last, so the
 * strong evidence always reads on top of the weak.
 */
function placeChords(chords: ChordView[]): PlacedChord[] {
  const strong = chords.filter((chord) => chord.token !== null);
  const weak = chords.filter((chord) => chord.token === null);
  const ordered = [...strong, ...weak];
  const boxes: Array<{ x: number; y: number; w: number }> = [];
  const placed: PlacedChord[] = [];

  ordered.forEach((chord) => {
    const strongIndex = strong.indexOf(chord);
    const bow = strongIndex >= 0 ? 150 + strongIndex * 60 : 240 + weak.indexOf(chord) * 60;
    const geometry = chordGeometry(chord.from, chord.to, bow);
    const label = chordLabel(chord);
    const w = labelWidth(label);
    let at = pointOnChord(geometry, 0.5);
    for (const t of [0.5, 0.38, 0.62, 0.28, 0.72, 0.2, 0.8]) {
      const candidate = pointOnChord(geometry, t);
      const clear = boxes.every(
        (box) =>
          Math.abs(box.x - candidate[0]) > (box.w + w) / 2 + 4 ||
          Math.abs(box.y - candidate[1]) > LABEL_H + 4,
      );
      if (clear) {
        at = candidate;
        break;
      }
    }
    boxes.push({ x: at[0], y: at[1], w });
    placed.push({ chord, geometry, label, at });
  });

  // Paint order: weak underneath, strong on top.
  return placed.reverse();
}

/** Arc on the web half of the wheel: the gate a block closes. */
function webGateArc(): string {
  const [x1, y1] = polar(GATE_ARC_R, -78);
  const [x2, y2] = polar(GATE_ARC_R, 78);
  return `M ${x1} ${y1} A ${GATE_ARC_R} ${GATE_ARC_R} 0 0 1 ${x2} ${y2}`;
}

/* ---------- data ---------- */

async function fetchIncidentEvents(incidentId: string): Promise<SocEvent[]> {
  const collected: SocEvent[] = [];
  let cursor = 0;
  for (let guard = 0; guard < MAX_SNAPSHOT_PAGES; guard += 1) {
    const page = await fetchEvents({
      incident_id: incidentId,
      since_seq: cursor,
      limit: EVENTS_PAGE_LIMIT,
    });
    collected.push(...page.items);
    if (page.items.length < EVENTS_PAGE_LIMIT) break;
    if (page.next_seq === undefined || page.next_seq <= cursor) break;
    cursor = page.next_seq;
  }
  return collected;
}

/** A one-line, attacker-controlled description of an event. Always rendered escaped. */
function eventGist(event: SocEvent): string {
  const attributes = event.attributes ?? {};
  if (typeof attributes.command === 'string') return attributes.command;
  if (typeof attributes.path === 'string') {
    const method = typeof attributes.method === 'string' ? `${attributes.method} ` : '';
    const query = typeof attributes.query_redacted === 'string' && attributes.query_redacted
      ? `?${attributes.query_redacted}`
      : '';
    return `${method}${attributes.path}${query}`;
  }
  if (typeof attributes.asset_id === 'string') return attributes.asset_id;
  if (typeof attributes.username === 'string') return `username=${attributes.username}`;
  return eventTypeLabel(event.event_type);
}

type Selection = { kind: 'lure'; id: LureId } | { kind: 'chord'; linkId: string } | null;

/* ---------- the wheel ---------- */

function RingCircle({ ring, reached }: { ring: Ring; reached: boolean }) {
  return (
    <circle
      className={reached ? 'cring cring--reached' : 'cring'}
      cx={CX}
      cy={CY}
      r={ring.radius}
    />
  );
}

function LureNode({
  view,
  selected,
  awaiting,
  igniteKey,
  onSelect,
}: {
  view: LureView;
  selected: boolean;
  awaiting: boolean;
  igniteKey: number | undefined;
  onSelect: () => void;
}) {
  const { lure } = view;
  const isCrown = lure.ring === 'crown';
  const [x, y] = lurePoint(lure.id);
  const radius = isCrown ? CROWN_R : NODE_R;
  const right = Math.cos((lure.angle * Math.PI) / 180) >= 0;
  const below = isCrown || Boolean(lure.labelBelow);
  const labelGap = lure.gate ? GATE_LABEL_GAP : NODE_R + 10;
  const labelX = below ? 0 : right ? labelGap : -labelGap;
  const anchor = below ? 'middle' : right ? 'start' : 'end';
  const labelY = isCrown ? CROWN_R + 18 : below ? NODE_R + (lure.holds ? 22 : 17) : -1;
  // The order badge sits on the side away from the label.
  const badgeX = isCrown ? CROWN_R * 0.72 : right ? -NODE_R : NODE_R;
  const badgeY = isCrown ? -CROWN_R * 0.72 : -NODE_R;

  const classes = [
    'cnode',
    `cnode--${view.state}`,
    isCrown ? 'cnode--crown' : '',
    lure.holds ? 'cnode--bait' : '',
    selected ? 'cnode--selected' : '',
    awaiting ? 'cnode--awaiting' : '',
  ]
    .filter(Boolean)
    .join(' ');

  const stateWord =
    view.state === 'flagged'
      ? `flagged by ${view.rules.join(', ')}`
      : view.state === 'touched'
        ? 'reached'
        : 'not reached';

  return (
    <g
      className={classes}
      transform={`translate(${x} ${y})`}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      aria-label={`${lure.label}, ${stateWord}${view.order ? `, step ${view.order}` : ''}`}
      onClick={onSelect}
      onKeyDown={(keyEvent) => {
        if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
          keyEvent.preventDefault();
          onSelect();
        }
      }}
    >
      {igniteKey !== undefined ? (
        <circle key={igniteKey} className="cnode__ignite" r={radius} />
      ) : null}
      {lure.holds ? <circle className="cnode__bait" r={radius + 6} /> : null}
      <circle className="cnode__core" r={radius} />
      {isCrown ? (
        <>
          <text className="cnode__crownword" y={-4}>
            CROWN
          </text>
          <text className="cnode__crownstate" y={12}>
            {view.state === 'untouched' ? 'untouched' : view.rules.join(' · ') || 'reached'}
          </text>
        </>
      ) : null}
      {view.order !== null ? (
        <g className="cnode__badge" transform={`translate(${badgeX} ${badgeY})`}>
          <circle r={9} />
          <text y={3.5}>{view.order}</text>
        </g>
      ) : null}
      <text className="cnode__label" x={labelX} y={labelY} textAnchor={anchor}>
        {lure.label}
      </text>
      <text className="cnode__sub" x={labelX} y={labelY + 14} textAnchor={anchor}>
        {lure.sublabel}
      </text>
      {!isCrown && view.rules.length > 0 ? (
        <text className="cnode__rules" x={labelX} y={labelY + 28} textAnchor={anchor}>
          {view.rules.join(' · ')}
        </text>
      ) : null}
    </g>
  );
}

function Chord({
  placed,
  selected,
  comet,
  onSelect,
}: {
  placed: PlacedChord;
  selected: boolean;
  comet: boolean;
  onSelect: () => void;
}) {
  const { chord, label, at } = placed;
  const { link } = chord;
  const d = placed.geometry.d;
  const width = labelWidth(label);

  return (
    <g
      className={[
        'cchord',
        `cchord--${link.status}`,
        `cchord--${link.kind}`,
        selected ? 'cchord--selected' : '',
      ]
        .filter(Boolean)
        .join(' ')}
      role="button"
      tabIndex={0}
      aria-label={`${linkPhrase(link.kind, link.status)}: ${label}`}
      onClick={onSelect}
      onKeyDown={(keyEvent) => {
        if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
          keyEvent.preventDefault();
          onSelect();
        }
      }}
    >
      <path className="cchord__hit" d={d} />
      <path className="cchord__line" d={d} />
      {comet ? (
        // The credential travelling from where it was planted to where it was
        // presented. Plays once when the chord appears or changes status.
        <circle className="cchord__comet" r={5}>
          <animateMotion dur="1.3s" repeatCount="1" fill="freeze" path={d} />
          <animate
            attributeName="opacity"
            values="0;1;1;0"
            keyTimes="0;0.1;0.8;1"
            dur="1.3s"
            fill="freeze"
          />
        </circle>
      ) : null}
      <rect
        className="cchord__labelbg"
        x={at[0] - width / 2}
        y={at[1] - LABEL_H / 2}
        width={width}
        height={LABEL_H}
        rx={LABEL_H / 2}
      />
      <text className="cchord__label" x={at[0]} y={at[1] + 4}>
        {label}
      </text>
    </g>
  );
}

function GateBlock({ action, bounced }: { action: ResponseAction | null; bounced: SocEvent[] }) {
  // Bounced requests stack upward from just above the web gate (bearing 0).
  const marks = bounced.slice(-8);
  const step = -4.5;
  const start = -9;
  return (
    <g>
      {action ? (
        <g className={`cgate cgate--${action.status}`}>
          <path className="cgate__arc" d={webGateArc()} />
          {(() => {
            const [lx, ly] = polar(GATE_ARC_R + 22, -66);
            return (
              <>
                <text className="cgate__label" x={lx} y={ly}>
                  {action.status === 'verified' ? 'GATE CLOSED · VERIFIED' : 'GATE CLOSING · APPLIED'}
                </text>
                <text className="cgate__sub" x={lx} y={ly + 15}>
                  {action.status === 'verified'
                    ? `${action.action_id} · a blocked request arrived`
                    : `${action.action_id} · waiting for a blocked request`}
                </text>
              </>
            );
          })()}
        </g>
      ) : null}
      {marks.map((event, index) => {
        const [bx, by] = polar(BOUNCE_R, start + index * step);
        return (
          <g key={event.event_id} className="cbounce" transform={`translate(${bx} ${by})`}>
            <title>{`${event.event_id} · ${timeUtcZ(event.occurred_at)} · rejected at the gate`}</title>
            <circle r={6} />
            <line x1={-4} y1={4} x2={4} y2={-4} />
          </g>
        );
      })}
      {bounced.length > 0 ? (
        (() => {
          // Anchored outward so the text never crosses the gate arc.
          const [tx, ty] = polar(BOUNCE_R - 4, start + step * (marks.length - 1) - 7);
          return (
            <text className="cbounce__label" x={tx} y={ty} textAnchor="start">
              {`${bounced.length} rejected`}
            </text>
          );
        })()
      ) : null}
    </g>
  );
}

function Wheel({
  model,
  selection,
  ignites,
  comets,
  awaitingLures,
  onSelect,
}: {
  model: WheelModel;
  selection: Selection;
  ignites: Map<LureId, number>;
  comets: boolean;
  awaitingLures: Set<LureId>;
  onSelect: (selection: Selection) => void;
}) {
  const reachedRings = new Set<RingId>();
  for (const view of model.lures.values()) {
    if (view.state !== 'untouched') reachedRings.add(view.lure.ring);
  }

  // The trail is drawn within a decoy only. A jump between decoys is exactly
  // the claim the analyst has to make, so only a chord (an API-reported link)
  // is allowed to draw it.
  const trailSegments: Array<[LureId, LureId]> = [];
  for (let index = 1; index < model.trail.length; index += 1) {
    const previous = model.trail[index - 1];
    const current = model.trail[index];
    if (previous && current && lureSide(previous) === lureSide(current)) {
      trailSegments.push([previous, current]);
    }
  }

  const [sshTitleX, sshTitleY] = [CX - PERIMETER_R, 36];
  const [webTitleX, webTitleY] = [CX + PERIMETER_R, 36];

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="chakra__svg"
      role="group"
      aria-label="ChakraView: the planted fiction as concentric rings, SSH decoy on the left, web decoy on the right, the synthetic crown jewel at the centre"
    >
      <defs>
        <radialGradient id="chakra-crown-glow">
          <stop offset="0%" stopColor="var(--sev-critical)" stopOpacity="0.45" />
          <stop offset="100%" stopColor="var(--sev-critical)" stopOpacity="0" />
        </radialGradient>
      </defs>

      <text className="chakra__sector" x={sshTitleX} y={sshTitleY} textAnchor="start">
        {SENSOR_LABEL['ssh-decoy-01']?.toUpperCase()} · ssh-decoy-01
      </text>
      <text className="chakra__sector" x={webTitleX} y={webTitleY} textAnchor="end">
        {SENSOR_LABEL['web-decoy-01']?.toUpperCase()} · web-decoy-01
      </text>

      {model.lures.get('crown')?.state !== 'untouched' ? (
        <circle className="chakra__glow" cx={CX} cy={CY} r={CROWN_R * 2.6} fill="url(#chakra-crown-glow)" />
      ) : null}

      {RINGS.filter((ring) => ring.radius > 0).map((ring) => (
        <RingCircle key={ring.id} ring={ring} reached={reachedRings.has(ring.id)} />
      ))}

      {/* The seam between the two decoys. */}
      <line className="chakra__seam" x1={CX} y1={CY - PERIMETER_R - 24} x2={CX} y2={CY - CROWN_R - 8} />
      <line className="chakra__seam" x1={CX} y1={CY + CROWN_R + 34} x2={CX} y2={CY + PERIMETER_R + 24} />

      {/* Spokes: one bearing per lure. The chakra's spokes are the lures themselves. */}
      {LURES.filter((lure) => lure.ring !== 'crown').map((lure) => {
        const [x1, y1] = polar(CROWN_R + 8, lure.angle);
        const [x2, y2] = polar(PERIMETER_R, lure.angle);
        const lit = model.lures.get(lure.id)?.state !== 'untouched';
        return (
          <line
            key={lure.id}
            className={lit ? 'cspoke cspoke--lit' : 'cspoke'}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
          />
        );
      })}

      {RINGS.filter((ring) => ring.radius > 0).map((ring) => (
        <text
          key={ring.id}
          className={reachedRings.has(ring.id) ? 'cring__label cring__label--reached' : 'cring__label'}
          x={CX}
          y={CY - ring.radius + 4}
        >
          {ring.label}
        </text>
      ))}

      {trailSegments.map(([a, b]) => {
        const [ax, ay] = lurePoint(a);
        const [bx, by] = lurePoint(b);
        return <line key={`${a}>${b}`} className="ctrail" x1={ax} y1={ay} x2={bx} y2={by} />;
      })}

      <GateBlock action={model.gate.action} bounced={model.gate.bounced} />

      {placeChords(model.chords).map((placed) => (
        <Chord
          key={`${placed.chord.link.link_id}-${placed.chord.link.status}`}
          placed={placed}
          comet={comets}
          selected={selection?.kind === 'chord' && selection.linkId === placed.chord.link.link_id}
          onSelect={() => onSelect({ kind: 'chord', linkId: placed.chord.link.link_id })}
        />
      ))}

      {[...model.lures.values()].map((view) => (
        <LureNode
          key={view.lure.id}
          view={view}
          selected={selection?.kind === 'lure' && selection.id === view.lure.id}
          awaiting={awaitingLures.has(view.lure.id)}
          igniteKey={ignites.get(view.lure.id)}
          onSelect={() =>
            onSelect(
              selection?.kind === 'lure' && selection.id === view.lure.id
                ? null
                : { kind: 'lure', id: view.lure.id },
            )
          }
        />
      ))}
    </svg>
  );
}

/* ---------- the panel ---------- */

function EventList({ events }: { events: SocEvent[] }) {
  const shown = events.slice(-12);
  return (
    <ul className="cpanel__events">
      {events.length > shown.length ? (
        <li className="cpanel__more">{number(events.length - shown.length)} earlier events not shown</li>
      ) : null}
      {shown.map((event) => (
        <li key={event.event_id} className="cpanel__event">
          <span className="mono cpanel__time">{timeUtcZ(event.occurred_at)}</span>
          <span className="cpanel__etype">{eventTypeLabel(event.event_type)}</span>
          <span className="cpanel__gist">
            <AttackerText value={eventGist(event)} />
          </span>
          <span className="mono cpanel__eid">{event.event_id}</span>
        </li>
      ))}
    </ul>
  );
}

function SummaryPanel({
  model,
  incident,
  actionsUnavailable,
  onSelect,
}: {
  model: WheelModel;
  incident: IncidentSummary | null;
  actionsUnavailable: boolean;
  onSelect: (selection: Selection) => void;
}) {
  const untouched = [...model.lures.values()].filter((view) => view.state === 'untouched');
  const depthRing = RINGS.find((ring) => ring.id === model.depth);

  if (!incident) {
    return (
      <div className="cpanel">
        <div className="cpanel__eyebrow">Nothing has reached the fiction</div>
        <h2 className="cpanel__title">The trap is set</h2>
        <p className="cpanel__text">
          Every lure on the wheel is planted and waiting: {model.total} places across two decoys,
          with the synthetic crown jewel at the centre. Each one lights up, in order, the moment a
          source reaches it.
        </p>
        <p className="cpanel__hint">Select any lure to see what it is and where it is defined.</p>
      </div>
    );
  }

  return (
    <div className="cpanel">
      <div className="cpanel__eyebrow">Source</div>
      <div className="cpanel__source">
        <span className="mono cpanel__ip">{incident.src_ip}</span>
        <span className={`badge badge--${incident.severity}`}>
          {number(incident.score)} {incident.severity}
        </span>
      </div>

      <div className="cpanel__stats">
        <div className="cstat">
          <div className="cstat__value">{depthRing ? depthRing.label : '—'}</div>
          <div className="cstat__label">deepest ring reached</div>
        </div>
        <div className="cstat">
          <div className="cstat__value">
            {model.touchedCount}
            <span className="cstat__of"> / {model.total}</span>
          </div>
          <div className="cstat__label">lures reached</div>
        </div>
      </div>
      {depthRing ? <p className="cpanel__text">{depthRing.meaning}.</p> : null}

      {model.chords.length > 0 ? (
        <>
          <div className="cpanel__eyebrow">Cross-decoy links</div>
          <ul className="cpanel__chords">
            {model.chords.map((chord) => (
              <li key={chord.link.link_id}>
                <button
                  type="button"
                  className={`cchip cchip--${chord.link.status}`}
                  onClick={() => onSelect({ kind: 'chord', linkId: chord.link.link_id })}
                >
                  <span className="mono">{chord.token ? chord.token.id : 'same source'}</span>
                  <span>{linkPhrase(chord.link.kind, chord.link.status)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <div className="cpanel__eyebrow">Never reached</div>
      {untouched.length === 0 ? (
        <p className="cpanel__text">Every lure in the fiction was reached.</p>
      ) : (
        <div className="cpanel__untouched">
          {untouched.map((view) => (
            <button
              key={view.lure.id}
              type="button"
              className="cchip cchip--dim"
              onClick={() => onSelect({ kind: 'lure', id: view.lure.id })}
            >
              {view.lure.label}
            </button>
          ))}
        </div>
      )}

      <div className="cpanel__eyebrow">Web gate</div>
      {model.gate.action ? (
        <p className="cpanel__text">
          <span className={`pill ${model.gate.action.status === 'verified' ? 'pill--ok' : 'pill--pending'}`}>
            {ACTION_STATUS_LABEL[model.gate.action.status]}
          </span>{' '}
          <span className="mono">{model.gate.action.action_id}</span>, blocking{' '}
          <span className="mono">{model.gate.action.target_ip}</span> on the web decoy only.
        </p>
      ) : actionsUnavailable ? (
        <p className="cpanel__hint">
          Block status unavailable: the backend answers <span className="mono">503 response_unavailable</span>{' '}
          until M2&apos;s <span className="mono">response/router.py</span> is installed.
        </p>
      ) : (
        <p className="cpanel__text">Open. No active block on this source.</p>
      )}
      {model.gate.bounced.length > 0 ? (
        <p className="cpanel__text">
          {number(model.gate.bounced.length)} request{model.gate.bounced.length === 1 ? '' : 's'}{' '}
          rejected at the gate.
        </p>
      ) : null}

      <p className="cpanel__hint">Select a lure or a chord to see the evidence behind it.</p>
    </div>
  );
}

function LurePanel({
  view,
  incidentId,
  onBack,
}: {
  view: LureView;
  incidentId: string | null;
  onBack: () => void;
}) {
  const navigate = useNavigate();
  const { lure } = view;
  const ring = RINGS.find((r) => r.id === lure.ring);
  const side = lure.sector === 'ssh' ? 'SSH decoy' : lure.sector === 'web' ? 'Web decoy' : 'Behind the web decoy';

  return (
    <div className="cpanel">
      <button type="button" className="cpanel__back" onClick={onBack}>
        ← Overview
      </button>
      <div className="cpanel__eyebrow">
        {ring?.label} · {side}
      </div>
      <h2 className="cpanel__title">{lure.label}</h2>
      <div className="cpanel__statusline">
        {view.state === 'flagged' ? (
          <span className="pill pill--danger">flagged · {view.rules.join(', ')}</span>
        ) : view.state === 'touched' ? (
          <span className="pill">reached</span>
        ) : (
          <span className="pill cpill--dim">not reached</span>
        )}
        {view.order !== null ? <span className="cpanel__step">step {view.order}</span> : null}
        {view.firstAt ? <span className="mono cpanel__time">first {timeUtcZ(view.firstAt)}</span> : null}
      </div>

      <div className="cpanel__eyebrow">In the fiction</div>
      <p className="cpanel__text">{lure.detail}</p>
      {lure.holds ? (
        <p className="cpanel__text">
          Planted here:{' '}
          {lure.holds.map((token) => (
            <span key={token} className="mono ctoken">
              {token}
            </span>
          ))}
        </p>
      ) : null}
      <p className="cpanel__source-file">
        defined in <span className="mono">{lure.source}</span>
      </p>

      {view.findings.length > 0 ? (
        <>
          <div className="cpanel__eyebrow">Findings citing this lure</div>
          <ul className="cpanel__findings">
            {view.findings.map((finding) => (
              <li key={finding.finding_id}>
                <span className="mono cpanel__rule">{finding.rule_id}</span>
                <span>
                  {finding.label}
                  {finding.pending_confirmation ? (
                    <span className="pill pill--pending cpanel__pending">waits for analyst</span>
                  ) : null}
                  <span className="cpanel__limit">{finding.limitation}</span>
                </span>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <div className="cpanel__eyebrow">Evidence</div>
      {view.events.length > 0 ? (
        <EventList events={view.events} />
      ) : view.passedThrough ? (
        <p className="cpanel__text">
          No event stopped here. It is lit because traffic passed through this gate on the way to
          a deeper lure.
        </p>
      ) : (
        <p className="cpanel__hint">No event from this source has reached this lure.</p>
      )}

      {incidentId && view.events.length > 0 ? (
        <button
          type="button"
          className="btn btn--ghost cpanel__open"
          onClick={() => navigate(`/incidents/${incidentId}`)}
        >
          Open incident {incidentId}
        </button>
      ) : null}
    </div>
  );
}

function ChordPanel({
  chord,
  onBack,
  onDecide,
}: {
  chord: ChordView;
  onBack: () => void;
  onDecide: () => void;
}) {
  const { link, token } = chord;
  const fromLure = LURE_BY_ID.get(chord.from);
  const toLure = LURE_BY_ID.get(chord.to);
  const plantedLure = token ? LURE_BY_ID.get(token.plantedAt) : undefined;

  return (
    <div className="cpanel">
      <button type="button" className="cpanel__back" onClick={onBack}>
        ← Overview
      </button>
      <div className="cpanel__eyebrow">Cross-decoy link</div>
      <h2 className="cpanel__title">{token ? token.id : 'Same source, close in time'}</h2>
      <div className="cpanel__statusline">
        <span
          className={`pill ${
            link.status === 'confirmed' ? 'pill--ok' : link.status === 'rejected' ? '' : 'pill--pending'
          }`}
        >
          {linkPhrase(link.kind, link.status)}
        </span>
      </div>

      <div className="cpanel__eyebrow">Provenance</div>
      <ol className="cprov">
        {token && plantedLure ? (
          <li>
            <span className="cprov__step">Planted</span>
            <span>
              in <strong>{plantedLure.label}</strong> on the {SENSOR_LABEL[link.from_sensor] ?? link.from_sensor}.{' '}
              It exists nowhere else in the lab.
            </span>
          </li>
        ) : null}
        <li>
          <span className="cprov__step">{token ? 'Read' : 'Seen'}</span>
          <span>
            {chord.fromEvent ? (
              <>
                <AttackerText value={eventGist(chord.fromEvent)} /> at{' '}
                <strong>{fromLure?.label}</strong>
                {chord.fromEvent.session_id ? (
                  <>
                    , session <span className="mono">{chord.fromEvent.session_id}</span>
                  </>
                ) : null}
                <span className="cprov__meta mono">
                  {timeUtcZ(chord.fromEvent.occurred_at)} · {chord.fromEvent.event_id}
                </span>
              </>
            ) : (
              <span className="mono">{link.from_event_id}</span>
            )}
          </span>
        </li>
        <li>
          <span className="cprov__step">{token ? 'Presented' : 'Then'}</span>
          <span>
            {chord.toEvent ? (
              <>
                <AttackerText value={eventGist(chord.toEvent)} /> at <strong>{toLure?.label}</strong>
                <span className="cprov__meta mono">
                  {timeUtcZ(chord.toEvent.occurred_at)} · {chord.toEvent.event_id}
                  {chord.gapSeconds !== null ? ` · ${chord.gapSeconds}s later` : ''}
                </span>
              </>
            ) : (
              <span className="mono">{link.to_event_id}</span>
            )}
          </span>
        </li>
      </ol>

      {chord.provenance === 'bait_read' ? (
        // Amber, not green: v1.0 records the read command being submitted, not
        // the file being served (review F3 and section 11). The token itself
        // exists only in that file, which is why this is still the strongest
        // v1.0 link, but it is not proof of a read.
        <p className="cverdict cverdict--weak">
          The planted-side event is a command submitted to read the file that holds this token,
          and that token exists nowhere else in the lab. Contract v1.0 does not record the file
          being served, so this is consistent with the planted trail, not proof of a read.
        </p>
      ) : chord.provenance === 'bait_not_read' ? (
        <p className="cverdict cverdict--weak">
          The token was presented, but the planted-side event the backend linked is not a read of{' '}
          {plantedLure?.label ?? 'the bait'}. Check the transcript before confirming.
        </p>
      ) : (
        <p className="cverdict cverdict--weak">
          Weak basis: {link.basis}. Address and timing only; no planted credential connects the two.
        </p>
      )}

      <p className="cpanel__hint">
        A link means the same source followed the planted trail. It does not identify a person.
      </p>

      {link.rationale ? (
        <p className="cpanel__text">
          Analyst rationale: <AttackerText value={link.rationale} />
        </p>
      ) : null}

      <button type="button" className="btn btn--primary cpanel__open" onClick={onDecide}>
        {link.status === 'open' ? 'Confirm or reject…' : 'Change decision…'}
      </button>
    </div>
  );
}

/* ---------- screen ---------- */

export function ChakraView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { subscribe, connectionEpoch } = useLiveStore();

  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null);
  const [detail, setDetail] = useState<Incident | null>(null);
  const [events, setEvents] = useState<SocEvent[]>([]);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [actionsUnavailable, setActionsUnavailable] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [selection, setSelection] = useState<Selection>(null);
  const [deciding, setDeciding] = useState<Link | null>(null);
  const [ignites, setIgnites] = useState<Map<LureId, number>>(new Map());

  const requested = searchParams.get('incident');
  const selectedId = useMemo(() => {
    if (!incidents || incidents.length === 0) return null;
    if (requested && incidents.some((incident) => incident.incident_id === requested)) return requested;
    const top = [...incidents].sort((a, b) => b.score - a.score)[0];
    return top?.incident_id ?? null;
  }, [incidents, requested]);
  const selectedIdRef = useRef<string | null>(null);
  selectedIdRef.current = selectedId;

  const incident = incidents?.find((item) => item.incident_id === selectedId) ?? null;

  const loadIncidents = useCallback(async () => {
    try {
      const page = await fetchIncidents();
      setIncidents(page.items);
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('chakra_load_failed', 'Could not load incidents.', 0),
      );
    }
  }, []);

  const detailTokenRef = useRef(0);
  const loadDetail = useCallback(async (incidentId: string) => {
    const token = ++detailTokenRef.current;
    try {
      const [incidentDetail, incidentEvents] = await Promise.all([
        fetchIncident(incidentId),
        fetchIncidentEvents(incidentId),
      ]);
      if (token !== detailTokenRef.current) return;
      setDetail(incidentDetail);
      setEvents(incidentEvents);
      setLoadedFor(incidentId);
      setError(null);
    } catch (cause) {
      if (token !== detailTokenRef.current) return;
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('chakra_load_failed', 'Could not load this incident.', 0),
      );
    }
  }, []);

  const loadActions = useCallback(async () => {
    try {
      const page = await fetchActions();
      setActions(page.items);
      setActionsUnavailable(false);
    } catch (cause) {
      // A missing router is a dependency that has not arrived, not an error
      // worth a red card on this screen. Anything else keeps the last state.
      if (cause instanceof ApiError && cause.code === 'response_unavailable') {
        setActionsUnavailable(true);
        setActions([]);
      }
    }
  }, []);

  useEffect(() => {
    void loadIncidents();
    void loadActions();
  }, [loadIncidents, loadActions]);

  useEffect(() => {
    setSelection(null);
    if (selectedId) void loadDetail(selectedId);
    else {
      setDetail(null);
      setEvents([]);
      setLoadedFor(null);
    }
  }, [selectedId, loadDetail]);

  // API.md: reload the whole snapshot on every reconnect.
  useEffect(() => {
    if (connectionEpoch === 0) return;
    void loadIncidents();
    if (selectedIdRef.current) void loadDetail(selectedIdRef.current);
  }, [connectionEpoch, loadIncidents, loadDetail]);

  // Live: events light lures immediately; findings, links and incident changes
  // re-read the incident so flags and chords come from the backend.
  const refreshTimerRef = useRef<number | null>(null);
  useEffect(() => {
    const scheduleRefresh = () => {
      if (refreshTimerRef.current !== null) window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = window.setTimeout(() => {
        refreshTimerRef.current = null;
        void loadIncidents();
        if (selectedIdRef.current) void loadDetail(selectedIdRef.current);
      }, 250);
    };

    const unsubscribe = subscribe((message) => {
      if (message.type === 'event') {
        const event = message.data as SocEvent;
        if (event.incident_id && event.incident_id === selectedIdRef.current) {
          setEvents((current) =>
            current.some((existing) => existing.event_id === event.event_id) ? current : [...current, event],
          );
          if (event.event_type === 'blocked_request') void loadActions();
        } else {
          // A new source, or the first one: find out about it.
          scheduleRefresh();
        }
        return;
      }
      if (message.type === 'action') {
        void loadActions();
        return;
      }
      scheduleRefresh();
    });
    return () => {
      unsubscribe();
      if (refreshTimerRef.current !== null) window.clearTimeout(refreshTimerRef.current);
    };
  }, [subscribe, loadIncidents, loadDetail, loadActions]);

  // Block status has no WebSocket message yet (API.md: poll).
  useEffect(() => {
    const timer = window.setInterval(
      () => void loadActions(),
      actionsUnavailable ? ACTIONS_POLL_UNAVAILABLE_MS : ACTIONS_POLL_MS,
    );
    return () => window.clearInterval(timer);
  }, [actionsUnavailable, loadActions]);

  const model = useMemo(
    () =>
      buildWheel({
        events: loadedFor === selectedId ? events : [],
        findings: loadedFor === selectedId ? (detail?.findings ?? []) : [],
        links: loadedFor === selectedId ? (detail?.links ?? []) : [],
        actions,
        srcIp: incident?.src_ip ?? null,
      }),
    [events, detail, loadedFor, selectedId, actions, incident],
  );

  // 3D by default; the original 2D wheel stays one click away, and is the only
  // view when the browser has no WebGL.
  const canRender3d = useMemo(() => webglAvailable(), []);
  const [mode, setMode] = useState<'3d' | '2d'>(() => (canRender3d ? '3d' : '2d'));
  const [cameraView, setCameraView] = useState<CameraView>('orbit');
  const [autoRotate, setAutoRotate] = useState(true);

  // The fourth dimension: a time cursor over this incident's events (null = live).
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  useEffect(() => {
    setCursor(null);
    setPlaying(false);
  }, [selectedId]);

  const incidentEvents = useMemo(
    () => (loadedFor === selectedId ? events : []),
    [events, loadedFor, selectedId],
  );

  /**
   * The wheel as it stood at the cursor: only events that had occurred, only
   * findings whose evidence had all occurred, only links whose two events had.
   * Blocks are shown live only. Same buildWheel, same rules, less input.
   */
  const shown = useMemo(() => {
    if (cursor === null) return model;
    const visible = incidentEvents.filter((event) => Date.parse(event.occurred_at) <= cursor);
    const ids = new Set(visible.map((event) => event.event_id));
    return buildWheel({
      events: visible,
      findings: (detail?.findings ?? []).filter((finding) =>
        finding.evidence_event_ids.every((id) => ids.has(id)),
      ),
      links: (detail?.links ?? []).filter(
        (link) => ids.has(link.from_event_id) && ids.has(link.to_event_id),
      ),
      actions: [],
      srcIp: incident?.src_ip ?? null,
    });
  }, [cursor, model, incidentEvents, detail, incident]);

  const sortedEvents = useMemo(
    () => [...incidentEvents].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at)),
    [incidentEvents],
  );

  // Ignite only lures reached while the screen is open. On the first load of an
  // incident everything already reached is simply shown lit: replaying history
  // as fireworks would be decoration.
  const seenRef = useRef<{ incidentId: string | null; touched: Set<LureId> }>({
    incidentId: null,
    touched: new Set(),
  });
  useEffect(() => {
    if (loadedFor !== selectedId) return;
    const touchedNow = new Set<LureId>();
    for (const view of model.lures.values()) {
      if (view.state !== 'untouched') touchedNow.add(view.lure.id);
    }
    const seen = seenRef.current;
    if (seen.incidentId !== selectedId) {
      seenRef.current = { incidentId: selectedId, touched: touchedNow };
      setIgnites(new Map());
      return;
    }
    const fresh = [...touchedNow].filter((id) => !seen.touched.has(id));
    if (fresh.length === 0) return;
    seen.touched = touchedNow;
    setIgnites((current) => {
      const next = new Map(current);
      for (const id of fresh) next.set(id, (next.get(id) ?? 0) + 1);
      return next;
    });
  }, [model, loadedFor, selectedId]);

  const reducedMotion = useMemo(
    () =>
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    [],
  );

  // A bait lure pulses while its token's link waits for the analyst.
  const awaitingLures = useMemo(() => {
    const out = new Set<LureId>();
    for (const chord of shown.chords) {
      if (chord.link.status === 'open' && chord.token) out.add(chord.token.plantedAt);
    }
    return out;
  }, [shown]);

  const eventsById = useMemo(() => new Map(events.map((event) => [event.event_id, event])), [events]);
  const openLinks = model.chords.filter((chord) => chord.link.status === 'open').length;

  const selectedLure = selection?.kind === 'lure' ? shown.lures.get(selection.id) : undefined;
  const selectedChord =
    selection?.kind === 'chord'
      ? shown.chords.find((chord) => chord.link.link_id === selection.linkId)
      : undefined;
  const deepest = shown.depth ? RINGS.find((ring) => ring.id === shown.depth) : undefined;

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">ChakraView</h1>
        <span className="chakra__tagline">the fiction, and how far into it a source walked</span>
        <span className="page__head-spacer" />
        {openLinks > 0 ? (
          <span className="pill pill--pending">
            {openLinks} link{openLinks === 1 ? '' : 's'} awaiting decision
          </span>
        ) : null}
        {canRender3d ? (
          <div className="segmented" role="group" aria-label="Dimensions">
            {(['3d', '2d'] as const).map((item) => (
              <button
                key={item}
                type="button"
                className={mode === item ? 'segmented__btn segmented__btn--active' : 'segmented__btn'}
                aria-pressed={mode === item}
                onClick={() => setMode(item)}
              >
                {item.toUpperCase()}
              </button>
            ))}
          </div>
        ) : null}
        <GraphViewToggle current="chakra" />
      </div>

      {incidents && incidents.length > 1 ? (
        <div className="chakra__sources" role="tablist" aria-label="Source">
          {[...incidents]
            .sort((a, b) => b.score - a.score)
            .map((item) => (
              <button
                key={item.incident_id}
                type="button"
                role="tab"
                aria-selected={item.incident_id === selectedId}
                className={item.incident_id === selectedId ? 'csource csource--active' : 'csource'}
                onClick={() => {
                  const next = new URLSearchParams(searchParams);
                  next.set('incident', item.incident_id);
                  setSearchParams(next, { replace: true });
                }}
              >
                <span className="mono">{item.src_ip}</span>
                <span className={`badge badge--${item.severity}`}>{number(item.score)}</span>
              </button>
            ))}
        </div>
      ) : null}

      {error ? (
        <ErrorCard
          error={error}
          onRetry={() => {
            void loadIncidents();
            if (selectedId) void loadDetail(selectedId);
          }}
        />
      ) : null}

      <section className={mode === '3d' ? 'card chakra chakra--3d' : 'card chakra'}>
        <div className="chakra__wheel">
          {mode === '3d' ? (
            <div className="c3stage">
              <ErrorBoundary
                fallback={
                  <div className="c3stage__fallback">
                    The 3D view could not start on this browser.{' '}
                    <button type="button" className="btn" onClick={() => setMode('2d')}>
                      Use the 2D wheel
                    </button>
                  </div>
                }
              >
                <Suspense fallback={<div className="c3stage__fallback">Building the scene…</div>}>
                  <Chakra3D
                    model={shown}
                    selection={selection}
                    awaitingLures={awaitingLures}
                    view={cameraView}
                    autoRotate={autoRotate && !reducedMotion}
                    animate={!reducedMotion}
                    onSelect={setSelection}
                  />
                </Suspense>
              </ErrorBoundary>

              <div className="c3hud c3hud--stats" aria-live="polite">
                <span className="c3hud__label">Deepest ring reached</span>
                <AnimatePresence mode="popLayout" initial={false}>
                  <motion.span
                    key={deepest?.id ?? 'none'}
                    className="c3hud__value"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.25 }}
                  >
                    {deepest ? deepest.label : 'None yet'}
                  </motion.span>
                </AnimatePresence>
                <span className="c3hud__sub">
                  {shown.touchedCount} of {shown.total} lures reached
                </span>
              </div>

              <div className="c3hud c3hud--controls">
                <div className="segmented" role="group" aria-label="Camera">
                  {CAMERA_VIEWS.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={
                        cameraView === item.id
                          ? 'segmented__btn segmented__btn--active'
                          : 'segmented__btn'
                      }
                      aria-pressed={cameraView === item.id}
                      onClick={() => {
                        setSelection(null);
                        setCameraView(item.id);
                      }}
                    >
                      <item.icon size={14} /> {item.label}
                    </button>
                  ))}
                </div>
                <button
                  type="button"
                  className={autoRotate ? 'iconbtn iconbtn--on' : 'iconbtn'}
                  title={autoRotate ? 'Stop rotating' : 'Rotate slowly'}
                  aria-pressed={autoRotate}
                  onClick={() => setAutoRotate((on) => !on)}
                >
                  <RefreshCw size={15} />
                </button>
              </div>

              <div className="c3hud c3hud--hint">Drag to orbit · scroll to zoom · click a lure</div>
            </div>
          ) : (
            <Wheel
              model={shown}
              selection={selection}
              ignites={ignites}
              comets={!reducedMotion}
              awaitingLures={awaitingLures}
              onSelect={setSelection}
            />
          )}

          <Timeline
            events={sortedEvents}
            cursor={cursor}
            playing={playing}
            onCursor={setCursor}
            onPlaying={setPlaying}
          />

          <div className="legend chakra__legend">
            <span className="legend__item">
              <span className="clegend clegend--untouched" /> not reached
            </span>
            <span className="legend__item">
              <span className="clegend clegend--touched" /> reached
            </span>
            <span className="legend__item">
              <span className="clegend clegend--flagged" /> finding cites it
            </span>
            <span className="legend__item">
              <span className="clegend clegend--bait" /> holds a honeytoken
            </span>
            <span className="legend__item">
              <span className="legend__swatch legend__swatch--strong" /> link, awaiting analyst
            </span>
            <span className="legend__item">
              <span className="legend__swatch legend__swatch--confirmed" /> analyst-confirmed
            </span>
          </div>
        </div>

        <aside className="chakra__panel" aria-live="polite">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={
                selectedLure
                  ? `lure-${selectedLure.lure.id}`
                  : selectedChord
                    ? `chord-${selectedChord.link.link_id}`
                    : 'summary'
              }
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
            >
              {selectedLure ? (
                <LurePanel
                  view={selectedLure}
                  incidentId={selectedId}
                  onBack={() => setSelection(null)}
                />
              ) : selectedChord ? (
                <ChordPanel
                  chord={selectedChord}
                  onBack={() => setSelection(null)}
                  onDecide={() => setDeciding(selectedChord.link)}
                />
              ) : (
                <SummaryPanel
                  model={shown}
                  incident={incident}
                  actionsUnavailable={actionsUnavailable}
                  onSelect={setSelection}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </aside>
      </section>

      <p className="graph__note">
        Radius is depth into the planted fiction; numbers are the order this source first reached
        each lure. A lit lure cites real event ids, a red ring cites a backend finding, and a chord
        is a link the backend reported. A confirmed link means the same source followed the planted
        trail. It does not identify a person.
      </p>

      {deciding ? (
        <LinkDecisionModal
          link={deciding}
          eventsById={eventsById}
          onClose={() => setDeciding(null)}
          onDecided={() => {
            setDeciding(null);
            void loadIncidents();
            if (selectedId) void loadDetail(selectedId);
          }}
        />
      ) : null}
    </div>
  );
}
