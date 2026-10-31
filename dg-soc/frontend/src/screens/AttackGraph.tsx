/**
 * Screen 6 — Attack Graph. DESIGN_SPEC.md section 11.
 *
 * Three kinds of node: the attacker IPs on the left, the two decoys on the
 * right. Thin edges are observed traffic. The edge between the two decoys is
 * the cross-decoy link, and its dashed-to-solid transition on confirmation is
 * the visual climax of the demo.
 *
 * Built as inline SVG, with no graph library. The layout is fixed and
 * deterministic by design (section 11), so a library's layout engine, pan/zoom
 * and edge routing would all go unused — roughly 50KB gzipped for a static
 * diagram. "Keep libraries minimal" (prompts/M1_frontend.md) is better served
 * this way, and hand-rolled SVG gives exact control over the confirm animation.
 *
 * Law 1 applies to topology too: an edge is drawn because the API reported
 * events or a link, never because the UI inferred a relationship.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiError, fetchEvents, fetchIncidents, fetchLinks } from '../api/client';
import { LinkDecisionModal } from '../components/LinkDecisionModal';
import { ErrorCard, SkeletonRows } from '../components/primitives';
import { SENSOR_LABEL, linkPhrase } from '../copy';
import { number } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { GraphViewToggle } from './GraphViewToggle';
import {
  SENSOR_IDS,
  type IncidentSummary,
  type Link,
  type SensorId,
  type SocEvent,
} from '../types/api';

/* Fixed geometry. Deterministic between rehearsals: a layout that jiggles
 * under a projector helps nobody. */
const CANVAS_W = 920;
const ATTACKER_X = 40;
const ATTACKER_W = 200;
const ATTACKER_H = 92;
const ATTACKER_GAP = 128;
const ATTACKER_Y0 = 56;
const SENSOR_X = 640;
const SENSOR_W = 220;
const SENSOR_H = 76;
const SSH_Y = 48;
const WEB_Y = 268;

interface GraphData {
  incidents: IncidentSummary[];
  links: Link[];
  /** incident_id -> sensors that source was observed on. */
  presence: Map<string, Set<SensorId>>;
  eventsById: Map<string, SocEvent>;
}

function sensorY(sensorId: SensorId): number {
  return sensorId === 'ssh-decoy-01' ? SSH_Y : WEB_Y;
}

/** A gentle cubic from the attacker's right edge to a sensor's left edge. */
function trafficPath(ay: number, sy: number): string {
  const x1 = ATTACKER_X + ATTACKER_W;
  const y1 = ay + ATTACKER_H / 2;
  const x2 = SENSOR_X;
  const y2 = sy + SENSOR_H / 2;
  const midX = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
}

/** The cross-decoy edge: a vertical run down the right-hand column. */
function linkPath(offset: number): string {
  const x = SENSOR_X + SENSOR_W / 2 + offset;
  return `M ${x} ${SSH_Y + SENSOR_H} L ${x} ${WEB_Y}`;
}

function AttackerNode({
  incident,
  y,
  onOpen,
}: {
  incident: IncidentSummary;
  y: number;
  onOpen: () => void;
}) {
  return (
    <g
      className={`gnode gnode--attacker gnode--${incident.severity}`}
      onClick={onOpen}
      role="button"
      tabIndex={0}
      aria-label={`Incident ${incident.incident_id}, source ${incident.src_ip}, ${incident.severity}`}
      onKeyDown={(keyEvent) => {
        if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
          keyEvent.preventDefault();
          onOpen();
        }
      }}
    >
      <rect x={ATTACKER_X} y={y} width={ATTACKER_W} height={ATTACKER_H} rx={8} />
      <text className="gnode__ip" x={ATTACKER_X + 14} y={y + 28}>
        {incident.src_ip}
      </text>
      <text className="gnode__score" x={ATTACKER_X + ATTACKER_W - 14} y={y + 28}>
        {number(incident.score)}
      </text>
      <text className="gnode__sev" x={ATTACKER_X + 14} y={y + 52}>
        {incident.severity.toUpperCase()}
      </text>
      <text className="gnode__sub" x={ATTACKER_X + 14} y={y + 76}>
        {number(incident.event_count)} events
      </text>
    </g>
  );
}

function SensorNode({
  sensorId,
  lastSeen,
  onOpen,
}: {
  sensorId: SensorId;
  lastSeen: string | null | undefined;
  onOpen: () => void;
}) {
  const y = sensorY(sensorId);
  const tone =
    lastSeen === null || lastSeen === undefined
      ? 'neutral'
      : (Date.now() - new Date(lastSeen).getTime()) / 1000 < 60
        ? 'ok'
        : 'warn';

  return (
    <g
      className="gnode gnode--sensor"
      onClick={onOpen}
      role="button"
      tabIndex={0}
      aria-label={`${SENSOR_LABEL[sensorId]} ${sensorId}`}
      onKeyDown={(keyEvent) => {
        if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
          keyEvent.preventDefault();
          onOpen();
        }
      }}
    >
      <rect x={SENSOR_X} y={y} width={SENSOR_W} height={SENSOR_H} rx={8} />
      <circle className={`gdot gdot--${tone}`} cx={SENSOR_X + 18} cy={y + 29} r={4} />
      <text className="gnode__sensor" x={SENSOR_X + 32} y={y + 33}>
        {sensorId}
      </text>
      <text className="gnode__sub" x={SENSOR_X + 32} y={y + 55}>
        {SENSOR_LABEL[sensorId]}
      </text>
    </g>
  );
}

export function AttackGraph() {
  const navigate = useNavigate();
  const { health, subscribe, connectionEpoch } = useLiveStore();

  const [data, setData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [decidingLink, setDecidingLink] = useState<Link | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [incidentsPage, linksPage] = await Promise.all([fetchIncidents(), fetchLinks()]);
      const incidents = incidentsPage.items;

      // Presence is a topology claim, so it is asked precisely rather than
      // inferred from a capped page: one tiny query per (incident, sensor).
      const presence = new Map<string, Set<SensorId>>();
      const eventsById = new Map<string, SocEvent>();

      await Promise.all(
        incidents.map(async (incident) => {
          const touched = new Set<SensorId>();
          const [detail, ...probes] = await Promise.all([
            fetchEvents({ incident_id: incident.incident_id, limit: 200 }),
            ...SENSOR_IDS.map((sensorId) =>
              fetchEvents({ incident_id: incident.incident_id, sensor_id: sensorId, limit: 1 }),
            ),
          ]);
          probes.forEach((page, index) => {
            const sensorId = SENSOR_IDS[index];
            if (sensorId && page.items.length > 0) touched.add(sensorId);
          });
          presence.set(incident.incident_id, touched);
          // Needed so the decision modal can show both evidence events.
          for (const event of detail?.items ?? []) eventsById.set(event.event_id, event);
        }),
      );

      setData({ incidents, links: linksPage.items, presence, eventsById });
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('graph_load_failed', 'Could not load the attack graph.', 0),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // API.md: reload the snapshot on every reconnect, incidents and links too.
  useEffect(() => {
    if (connectionEpoch > 0) void load();
  }, [connectionEpoch, load]);

  // A link decided elsewhere (the incident page) should show here too.
  useEffect(() => {
    const unsubscribe = subscribe((message) => {
      if (message.type === 'link' || message.type === 'incident') void load();
    });
    return unsubscribe;
  }, [subscribe, load]);

  const canvasHeight = useMemo(() => {
    const attackerCount = Math.max(1, data?.incidents.length ?? 1);
    return Math.max(400, ATTACKER_Y0 + attackerCount * ATTACKER_GAP + 24);
  }, [data]);

  const openLinks = data?.links.filter((link) => link.status === 'open').length ?? 0;

  if (loading && data === null) {
    return (
      <div className="page">
        <section className="card">
          <SkeletonRows rows={8} />
        </section>
      </div>
    );
  }

  if (error && data === null) {
    return (
      <div className="page">
        <div className="page__head">
          <h1 className="page__title">Attack Graph</h1>
        </div>
        <ErrorCard error={error} onRetry={() => void load()} />
      </div>
    );
  }

  const incidents = data?.incidents ?? [];
  const links = data?.links ?? [];

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Attack Graph</h1>
        <span className="page__head-spacer" />
        {openLinks > 0 ? (
          <span className="pill pill--pending">
            {openLinks} link{openLinks === 1 ? '' : 's'} awaiting decision
          </span>
        ) : null}
        <GraphViewToggle current="network" />
      </div>

      <section className="card">
        <div className="graph">
          <svg
            viewBox={`0 0 ${CANVAS_W} ${canvasHeight}`}
            className="graph__svg"
            role="img"
            aria-label="Attack graph: sources on the left, decoys on the right"
          >
            {/* Traffic edges first, so nodes and link edges paint over them. */}
            {incidents.map((incident, index) => {
              const y = ATTACKER_Y0 + index * ATTACKER_GAP;
              const touched = data?.presence.get(incident.incident_id) ?? new Set<SensorId>();
              return SENSOR_IDS.filter((sensorId) => touched.has(sensorId)).map((sensorId) => (
                <path
                  key={`${incident.incident_id}-${sensorId}`}
                  className="gedge gedge--traffic"
                  d={trafficPath(y, sensorY(sensorId))}
                />
              ));
            })}

            {/* Cross-decoy links. The key carries the status so a decided link
                remounts and its animation actually plays. */}
            {links.map((link, index) => {
              // Lines fan out horizontally, labels stack vertically. Both are
              // needed: the real backend emits more than one link (a honeytoken
              // strong_candidate and a same-IP candidate), and labels drawn at a
              // shared y overlap each other and cover the neighbouring line,
              // which makes that link impossible to click.
              const offset = (index - (links.length - 1) / 2) * 36;
              const centreY = (SSH_Y + SENSOR_H + WEB_Y) / 2;
              const midY = centreY + (index - (links.length - 1) / 2) * 30;
              const x = SENSOR_X + SENSOR_W / 2 + offset;
              const label =
                link.status === 'confirmed'
                  ? 'confirmed'
                  : link.status === 'rejected'
                    ? 'rejected'
                    : link.kind === 'strong_candidate'
                      ? `candidate · ${link.basis.replace(/^honeytoken\s+/, '')}`
                      : 'candidate';
              const labelWidth = label.length * 6.1 + 16;
              const interactive = true;

              return (
                <g
                  key={`${link.link_id}-${link.status}`}
                  className={`glink glink--${link.status} glink--${link.kind}`}
                  onClick={interactive ? () => setDecidingLink(link) : undefined}
                  role="button"
                  tabIndex={0}
                  aria-label={`${linkPhrase(link.kind, link.status)} between ${link.from_sensor} and ${link.to_sensor}`}
                  onKeyDown={(keyEvent) => {
                    if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
                      keyEvent.preventDefault();
                      setDecidingLink(link);
                    }
                  }}
                >
                  {/* Invisible fat path so the edge is easy to hit. */}
                  <path className="glink__hit" d={linkPath(offset)} />
                  <path className="glink__line" d={linkPath(offset)} />
                  <rect
                    className="glink__labelbg"
                    x={x - labelWidth / 2}
                    y={midY - 11}
                    width={labelWidth}
                    height={22}
                    rx={4}
                  />
                  <text className="glink__label" x={x} y={midY + 4}>
                    {label}
                  </text>
                </g>
              );
            })}

            {incidents.map((incident, index) => (
              <AttackerNode
                key={incident.incident_id}
                incident={incident}
                y={ATTACKER_Y0 + index * ATTACKER_GAP}
                onOpen={() => navigate(`/incidents/${incident.incident_id}`)}
              />
            ))}

            {SENSOR_IDS.map((sensorId) => (
              <SensorNode
                key={sensorId}
                sensorId={sensorId}
                lastSeen={health?.sensors[sensorId]}
                onOpen={() => navigate(`/events?sensor=${encodeURIComponent(sensorId)}`)}
              />
            ))}
          </svg>

          {/* Persistent: judges should not have to ask what dashed means. */}
          <div className="legend">
            <span className="legend__item">
              <span className="legend__swatch legend__swatch--traffic" /> observed traffic
            </span>
            <span className="legend__item">
              <span className="legend__swatch legend__swatch--candidate" /> candidate
            </span>
            <span className="legend__item">
              <span className="legend__swatch legend__swatch--strong" /> strong candidate
            </span>
            <span className="legend__item">
              <span className="legend__swatch legend__swatch--confirmed" /> analyst-confirmed
            </span>
          </div>
        </div>
      </section>

      <p className="graph__note">
        An edge means the API reported traffic from that source on that decoy. A link between
        the decoys is a claim about the same source following our planted trail — it does not
        identify a person.
      </p>

      {decidingLink && data ? (
        <LinkDecisionModal
          link={decidingLink}
          eventsById={data.eventsById}
          onClose={() => setDecidingLink(null)}
          onDecided={() => {
            setDecidingLink(null);
            void load();
          }}
        />
      ) : null}
    </div>
  );
}
