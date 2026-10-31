/**
 * Screen 4 — Incident Detail. DESIGN_SPEC.md section 9.
 *
 * The screen that is on the projector for most of the demo. Two columns:
 * evidence on the left, machinery on the right.
 *
 * Law 1 throughout: score, severity, stages, points and link status are all
 * displayed exactly as the API reported them. The only arithmetic here is the
 * raw sum in the score breakdown, which is labelled "raw" and sits next to the
 * cap note rather than replacing the real score.
 */

import { ArrowLeft, Download, Play, ShieldBan } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { ApiError, fetchEvents, fetchIncident, incidentExportUrl } from '../api/client';
import { USE_FIXTURES } from '../api/config';
import { FindingCard } from '../components/FindingCard';
import { KillChainBar } from '../components/KillChainBar';
import { ActionCard } from '../components/ActionCard';
import { BlockFlowModal } from '../components/BlockFlowModal';
import { LinkDecisionModal } from '../components/LinkDecisionModal';
import { RawEventDrawer } from '../components/RawEventDrawer';
import { ScoreBreakdown } from '../components/ScoreBreakdown';
import { EmptyState, ErrorCard, SkeletonRows } from '../components/primitives';
import { RULE_NAME, STAGE_LABEL, linkPhrase } from '../copy';
import { fullUtc, number, timeUtcZ } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { KILL_CHAIN_STAGES, type Incident, type Link, type SocEvent, type Stage } from '../types/api';

/** "2m 30s" between two timestamps. Presentation only. */
function duration(from: string, to: string): string {
  const seconds = Math.max(0, Math.round((new Date(to).getTime() - new Date(from).getTime()) / 1000));
  const minutes = Math.floor(seconds / 60);
  return minutes > 0 ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
}

/**
 * The summary cites evidence inline as "[evidence: id, id]". Split it into one
 * point per claim, each keeping its own citations, so it reads as a list of
 * findings instead of a wall of ids. Display only: the words are unchanged.
 */
function summaryPoints(text: string): { text: string; ids: string[] }[] {
  const points: { text: string; ids: string[] }[] = [];
  const pattern = /([^[]*?)\s*\[evidence:\s*([^\]]*)\]\.?\s*/g;
  let consumed = 0;
  for (const match of text.matchAll(pattern)) {
    const sentence = (match[1] ?? '').trim();
    const ids = (match[2] ?? '')
      .split(',')
      .map((id) => id.trim())
      .filter(Boolean);
    if (sentence) points.push({ text: /[.!?]$/.test(sentence) ? sentence : `${sentence}.`, ids });
    consumed = (match.index ?? 0) + match[0].length;
  }
  const rest = text.slice(consumed).trim();
  if (rest) points.push({ text: rest, ids: [] });
  return points.length > 0 ? points : [{ text, ids: [] }];
}

function EvidenceButton({
  ids,
  eventsById,
  onOpen,
}: {
  ids: string[];
  eventsById: Map<string, SocEvent>;
  onOpen: (event: SocEvent) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? ids : ids.slice(0, 1);
  return (
    <span className="keypoint__ev">
      {shown.map((id) => {
        const event = eventsById.get(id);
        return (
          <button
            key={id}
            type="button"
            className="chip"
            disabled={!event}
            onClick={() => event && onOpen(event)}
            title={event ? 'Open the raw event' : 'Event not in the loaded window'}
          >
            {id}
          </button>
        );
      })}
      {!expanded && ids.length > 1 ? (
        <button type="button" className="chip" onClick={() => setExpanded(true)}>
          +{ids.length - 1} more
        </button>
      ) : null}
    </span>
  );
}

function LinkRow({ link, onDecide }: { link: Link; onDecide: (link: Link) => void }) {
  const classes = [
    'linkrow',
    `linkrow--${link.status}`,
    link.status === 'open' && link.kind === 'strong_candidate' ? 'linkrow--strong' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={classes}>
      <div className="linkrow__sensors">
        <span className="mono">{link.from_sensor}</span>
        <span className="linkhead__arrow">⇢</span>
        <span className="mono">{link.to_sensor}</span>
      </div>
      <div className="linkrow__phrase">{linkPhrase(link.kind, link.status)}</div>
      <div className="linkrow__basis mono">{link.basis}</div>
      {link.rationale ? (
        <div className="linkrow__rationale">
          “{link.rationale}”
          {link.decided_at ? <span className="mono"> {timeUtcZ(link.decided_at)}</span> : null}
        </div>
      ) : null}
      <div className="linkrow__actions">
        <button type="button" className="btn" onClick={() => onDecide(link)}>
          {link.status === 'open' ? 'Confirm or reject' : 'Change decision'}
        </button>
      </div>
    </div>
  );
}

export function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const { subscribe, connectionEpoch } = useLiveStore();
  const refetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [incident, setIncident] = useState<Incident | null>(null);
  const [eventsById, setEventsById] = useState<Map<string, SocEvent>>(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);

  const [stageFilter, setStageFilter] = useState<Stage | null>(null);
  const [openEvent, setOpenEvent] = useState<SocEvent | null>(null);
  const [decidingLink, setDecidingLink] = useState<Link | null>(null);
  const [blocking, setBlocking] = useState(false);

  const load = useCallback(async () => {
    if (!incidentId) return;
    setLoading(true);
    try {
      // The incident drives the page; the events are fetched alongside it so
      // every evidence id on screen can open its raw event.
      const [loadedIncident, eventsPage] = await Promise.all([
        fetchIncident(incidentId),
        fetchEvents({ incident_id: incidentId, limit: 200 }),
      ]);
      setIncident(loadedIncident);
      setEventsById(new Map(eventsPage.items.map((event) => [event.event_id, event])));
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('incident_load_failed', 'Could not load this incident.', 0),
      );
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Resync after a dropped connection: API.md requires the whole snapshot to be
  // reloaded on reconnect, not just the event feed.
  useEffect(() => {
    if (connectionEpoch > 0) void load();
  }, [connectionEpoch, load]);

  /**
   * Live updates. API.md: when an `incident` message arrives for the page you
   * have open, re-fetch GET /api/incidents/{id}.
   *
   * We re-fetch on `finding` and `link` too, rather than patching items in
   * place. The whole page is derived from one GET, and in-place replacement
   * cannot express a removal — a rejected link drops its R05 finding and no
   * delete message is sent, so a patched page would keep showing a finding the
   * backend no longer has. Re-fetching is always correct.
   *
   * Debounced, because a single analyst decision produces a burst of messages.
   */
  useEffect(() => {
    const unsubscribe = subscribe((message) => {
      if (message.type === 'event' || message.type === 'action') return;

      // `link` carries no incident_id, so it cannot be filtered by incident.
      // Findings and incidents can be, and are.
      if (message.type === 'incident') {
        const summary = message.data as { incident_id?: string };
        if (summary?.incident_id !== incidentId) return;
      } else if (message.type === 'finding') {
        const finding = message.data as { incident_id?: string };
        if (finding?.incident_id !== incidentId) return;
      }

      if (refetchTimer.current) clearTimeout(refetchTimer.current);
      refetchTimer.current = setTimeout(() => void load(), 250);
    });

    return () => {
      unsubscribe();
      if (refetchTimer.current) clearTimeout(refetchTimer.current);
    };
  }, [subscribe, incidentId, load]);

  const visibleFindings = useMemo(() => {
    if (!incident) return [];
    if (stageFilter === null) return incident.findings;
    return incident.findings.filter((finding) => finding.stage === stageFilter);
  }, [incident, stageFilter]);

  if (loading && incident === null) {
    return (
      <div className="page">
        <section className="card">
          <SkeletonRows rows={10} />
        </section>
      </div>
    );
  }

  if (error && incident === null) {
    return (
      <div className="page">
        <div className="page__head">
          <RouterLink to="/incidents" className="btn btn--ghost">
            ← Incidents
          </RouterLink>
        </div>
        <ErrorCard error={error} onRetry={() => void load()} />
      </div>
    );
  }

  if (!incident) return null;

  const openLinks = incident.links.filter((link) => link.status === 'open');
  const pendingFindings = incident.findings.filter((finding) => finding.pending_confirmation);
  const points = summaryPoints(incident.summary.text);
  const reached = incident.stages_observed.filter((stage) => stage !== 'none').length;

  return (
    <div className="page incpage">
      <div className="page__head">
        <RouterLink to="/incidents" className="btn btn--ghost">
          <ArrowLeft size={15} /> Incidents
        </RouterLink>
        <span className="page__head-spacer" />
        <a
          className={USE_FIXTURES ? 'btn btn--disabled' : 'btn'}
          href={USE_FIXTURES ? undefined : incidentExportUrl(incident.incident_id)}
          title={
            USE_FIXTURES
              ? 'Export needs the live backend'
              : 'JSON export, password hashes excluded.'
          }
          aria-disabled={USE_FIXTURES}
        >
          <Download size={15} /> Export report
        </a>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => setBlocking(true)}
          title="Preview a 120 s block of this source on the web decoy"
        >
          <ShieldBan size={15} /> Block source
        </button>
      </div>

      <header className={`inchero inchero--${incident.severity}`}>
        <div className="inchero__main">
          <div className="inchero__eyebrow">
            <span className={`badge badge--${incident.severity}`}>{incident.severity}</span>
            <span>
              {incident.incident_id} · {incident.lab_run_id}
            </span>
          </div>
          <h1 className="inchero__ip">{incident.src_ip}</h1>
          <dl className="inchero__facts">
            <div>
              <dt>Events</dt>
              <dd>{number(incident.event_count)}</dd>
            </div>
            <div>
              <dt>Stages reached</dt>
              <dd>
                {reached} of {KILL_CHAIN_STAGES.length}
              </dd>
            </div>
            <div>
              <dt>First seen</dt>
              <dd>{fullUtc(incident.first_seen)}</dd>
            </div>
            <div>
              <dt>Last seen</dt>
              <dd>{timeUtcZ(incident.last_seen)}</dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd>{duration(incident.first_seen, incident.last_seen)}</dd>
            </div>
          </dl>
        </div>
        <div className="inchero__score">
          <span className="inchero__score-label">Risk score</span>
          <span className={`inchero__score-value inchero__score-value--${incident.severity}`}>
            {number(incident.score)}
          </span>
          <span className="inchero__score-hint">from {incident.findings.length} findings</span>
        </div>
      </header>

      <section className="incsec">
        <h2 className="incsec__title">What happened</h2>
        <div className="incsummary">
          <div className="incsummary__text">
            <div className="incsummary__source">
              <span className="chip">{incident.summary.source}</span>
              <span>
                {incident.summary.source === 'rules'
                  ? 'Written from rule findings.'
                  : 'Generated text — all claims cite the event IDs below.'}
              </span>
            </div>
            <ol className="keypoints">
              {points.map((point, index) => (
                <li key={index} className="keypoint">
                  <span className="keypoint__n">{index + 1}</span>
                  <span className="keypoint__body">
                    <span className="keypoint__text">{point.text}</span>
                    {point.ids.length > 0 ? (
                      <EvidenceButton ids={point.ids} eventsById={eventsById} onOpen={setOpenEvent} />
                    ) : null}
                  </span>
                </li>
              ))}
            </ol>
          </div>

          <aside className="incsummary__side">
            <div
              className={
                openLinks.length + pendingFindings.length > 0 ? 'decide decide--open' : 'decide'
              }
            >
              <h3 className="decide__title">Needs your decision</h3>
              {openLinks.length === 0 && pendingFindings.length === 0 ? (
                <p className="decide__none">Nothing waiting on an analyst.</p>
              ) : (
                <ul className="decide__list">
                  {openLinks.map((link) => (
                    <li key={link.link_id}>
                      <span>
                        {link.from_sensor} → {link.to_sensor}: {linkPhrase(link.kind, link.status)}
                      </span>
                      <button type="button" className="btn" onClick={() => setDecidingLink(link)}>
                        Review
                      </button>
                    </li>
                  ))}
                  {pendingFindings.map((finding) => (
                    <li key={finding.finding_id}>
                      <span>
                        {finding.rule_id} {RULE_NAME[finding.rule_id] ?? ''} counts once its link
                        is confirmed
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="decide">
              <h3 className="decide__title">Response</h3>
              {incident.active_block === null ? (
                <>
                  <p className="decide__none">No action applied.</p>
                  <button
                    type="button"
                    className="btn btn--block"
                    onClick={() => setBlocking(true)}
                  >
                    Preview block
                  </button>
                </>
              ) : (
                <ActionCard action={incident.active_block} onExpired={() => void load()} />
              )}
            </div>
          </aside>
        </div>
      </section>

      <section className="incsec">
        <h2 className="incsec__title">How far it got</h2>
        <KillChainBar
          stagesObserved={incident.stages_observed}
          findings={incident.findings}
          severity={incident.severity}
          activeStage={stageFilter}
          onStageClick={(stage) => setStageFilter((current) => (current === stage ? null : stage))}
        />
      </section>

      <section className="incsec">
        <div className="incsec__head">
          <h2 className="incsec__title">
            Findings <span className="incsec__count">{visibleFindings.length}</span>
          </h2>
          {stageFilter ? (
            <button type="button" className="btn btn--ghost" onClick={() => setStageFilter(null)}>
              Clear {STAGE_LABEL[stageFilter]} filter
            </button>
          ) : null}
        </div>
        {visibleFindings.length === 0 ? (
          <EmptyState
            title="No findings for this stage."
            hint="Clear the filter to see every finding on this incident."
          />
        ) : (
          <div className="findgrid">
            {visibleFindings.map((finding) => (
              <FindingCard
                key={finding.finding_id}
                finding={finding}
                eventsById={eventsById}
                onOpenEvent={setOpenEvent}
              />
            ))}
          </div>
        )}
      </section>

      <div className="incsec incsec--split">
        <section>
          <h2 className="incsec__title">
            Cross-decoy links <span className="incsec__count">{incident.links.length}</span>
          </h2>
          {incident.links.length === 0 ? (
            <EmptyState
              title="No cross-decoy links."
              hint="A link appears when the same source touches both decoys within 5 minutes."
            />
          ) : (
            <div className="stack">
              {incident.links.map((link) => (
                <LinkRow key={link.link_id} link={link} onDecide={setDecidingLink} />
              ))}
            </div>
          )}
        </section>

        <section>
          <h2 className="incsec__title">
            Sessions <span className="incsec__count">{incident.sessions.length}</span>
          </h2>
          {incident.sessions.length === 0 ? (
            <EmptyState
              title="No sessions."
              hint="SSH sessions appear here once a connection is opened."
            />
          ) : (
            <div className="sessions">
              {[...incident.sessions]
                .sort((a, b) => b.commands - a.commands)
                .map((session) => (
                  <div
                    key={session.session_id}
                    className={session.commands > 0 ? 'sessionrow' : 'sessionrow sessionrow--empty'}
                  >
                    <span className="mono">{session.session_id}</span>
                    <span className="sessionrow__sensor mono">{session.sensor_id}</span>
                    <span className="sessionrow__count">
                      {session.commands} cmd{session.commands === 1 ? '' : 's'}
                    </span>
                    {session.commands > 0 ? (
                      <RouterLink
                        className="btn"
                        to={`/incidents/${incident.incident_id}/transcript/${session.session_id}`}
                      >
                        <Play size={13} /> Replay
                      </RouterLink>
                    ) : null}
                  </div>
                ))}
              <p className="incsec__note">
                Sessions with no commands never reached a shell, so there is nothing to replay.
              </p>
            </div>
          )}
        </section>
      </div>

      <section className="incsec">
        <h2 className="incsec__title">Score breakdown</h2>
        <div className="panel">
          <ScoreBreakdown rows={incident.score_breakdown} score={incident.score} />
        </div>
      </section>

      {openEvent ? (
        <RawEventDrawer event={openEvent} onClose={() => setOpenEvent(null)} />
      ) : null}

      {blocking ? (
        <BlockFlowModal
          incidentId={incident.incident_id}
          onClose={() => {
            setBlocking(false);
            void load();
          }}
          onChanged={() => void load()}
        />
      ) : null}

      {decidingLink ? (
        <LinkDecisionModal
          link={decidingLink}
          eventsById={eventsById}
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
