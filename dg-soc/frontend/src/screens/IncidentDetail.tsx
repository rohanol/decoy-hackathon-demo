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

import { ArrowLeft, Download, ShieldBan } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { ApiError, fetchActions, fetchAllEvents, fetchIncident, fetchIncidents, fetchProfile, fetchEligibility, incidentExportUrl } from '../api/client';
import { USE_FIXTURES } from '../api/config';
import { FindingCard } from '../components/FindingCard';
import { KillChainBar } from '../components/KillChainBar';
import { ActionCard } from '../components/ActionCard';
import { BlockFlowModal } from '../components/BlockFlowModal';
import { LinkDecisionModal } from '../components/LinkDecisionModal';
import { RawEventDrawer } from '../components/RawEventDrawer';
import { ArchivePanel, RoutingPanel, ScopeNote } from '../v12/components';
import { archiveEvidence, hasTranscript, responseScope } from '../v12/views';
import { ScoreBreakdown } from '../components/ScoreBreakdown';
import { EmptyState, ErrorCard, SkeletonRows } from '../components/primitives';
import { ModeBadge } from '../components/evidence/bits';
import { SessionCaseCard, SourceProfileCard } from '../components/evidence/CaseViews';
import { MappingList } from '../components/evidence/MappingViews';
import { ParentCard, RelationCard } from '../components/evidence/RelationViews';
import {
  EligibilityNotice,
  GatedActionButton,
  VerificationTimeline,
} from '../components/evidence/ResponseViews';
import {
  eligibilityFromV1,
  mappingsFromV1,
  parentsFromV1,
  relationsFromV1,
  sessionCasesFromV1,
  sourceProfileFromV1,
  verificationFromV1,
} from '../evidence/fromV1';
import { RULE_NAME, linkPhrase, stageLabel } from '../copy';
import { evidenceFromBackend, type BackendContext } from '../evidence/fromBackend';
import { fullUtc, number, timeUtcZ } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import {
  KILL_CHAIN_STAGES,
  type Incident,
  type Link,
  type ResponseAction,
  type SocEvent,
  type Stage,
} from '../types/api';

const ACTIONS_POLL_MS = 2000;

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

export function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const { subscribe, connectionEpoch } = useLiveStore();
  const refetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [incident, setIncident] = useState<Incident | null>(null);
  const [events, setEvents] = useState<SocEvent[]>([]);
  const [eventsById, setEventsById] = useState<Map<string, SocEvent>>(new Map());
  const [backendContext, setBackendContext] = useState<BackendContext | null>(null);
  /** Response actions targeting this source. [] when the router is not installed. */
  const [sourceActions, setSourceActions] = useState<ResponseAction[]>([]);
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
      // The incident drives the page; all of its events are fetched alongside
      // it (paged, not just the first 200) so every evidence id on screen can
      // open its raw event and every session case is complete.
      const [loadedIncident, loadedEvents] = await Promise.all([
        fetchIncident(incidentId),
        fetchAllEvents({ incident_id: incidentId }),
      ]);
      let context: BackendContext | null = null;
      if (loadedIncident.case_kind) {
        const [page, profile, eligibility, relatedEvents] = await Promise.all([
          fetchIncidents(), fetchProfile(loadedIncident.src_ip, loadedIncident.lab_run_id),
          fetchEligibility(loadedIncident.incident_id),
          fetchAllEvents({ lab_run_id: loadedIncident.lab_run_id, capture_mode: loadedIncident.capture_mode }),
        ]);
        context = { cases: page.items.filter(item => item.lab_run_id === loadedIncident.lab_run_id
          && item.capture_mode === loadedIncident.capture_mode), profile, eligibility, events: relatedEvents };
      }
      setIncident(loadedIncident);
      setEvents(loadedEvents);
      setBackendContext(context);
      setEventsById(new Map((context?.events ?? loadedEvents).map((event) => [event.event_id, event])));
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

  const srcIp = incident?.src_ip ?? null;
  const loadActions = useCallback(async () => {
    if (!srcIp) return;
    try {
      const page = await fetchActions();
      setSourceActions(page.items.filter((action) => action.target_ip === srcIp
        && (!action.lab_run_id || action.lab_run_id === incident?.lab_run_id)));
    } catch {
      // 503 response_unavailable or a network blip: the Response Center says
      // which. Here, no actions is the honest display.
      setSourceActions([]);
    }
  }, [srcIp, incident?.lab_run_id]);

  useEffect(() => {
    void loadActions();
  }, [loadActions]);

  // Block status is not pushed (API.md reserves `action`), so poll while live.
  const hasLiveAction = sourceActions.some((a) => a.status === 'applied' || a.status === 'verified');
  useEffect(() => {
    if (!hasLiveAction) return;
    const timer = setInterval(() => void loadActions(), ACTIONS_POLL_MS);
    return () => clearInterval(timer);
  }, [hasLiveAction, loadActions]);

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

  /*
   * The evidence structure, reshaped from v1.0 data (src/evidence/fromV1.ts):
   * regrouping only, nothing scored or inferred. Swap these inputs for the
   * agreed session/source/parent endpoints once the contract lands.
   */
  const evidence = useMemo(() => {
    if (!incident) return null;
    if (incident.case_kind && backendContext) return evidenceFromBackend(incident, backendContext);
    const cases = sessionCasesFromV1(events, incident.findings);
    const relations = relationsFromV1(incident.links, events);
    return {
      cases,
      relations,
      profile: sourceProfileFromV1(incident, events, cases),
      parents: parentsFromV1(relations),
      mappings: mappingsFromV1(incident.findings),
      eligibility: eligibilityFromV1(events),
    };
  }, [incident, events, backendContext]);

  const evidenceHandlers = useMemo(
    () => ({
      onOpenEvent: (id: string) => {
        const event = eventsById.get(id);
        if (event) setOpenEvent(event);
      },
      isKnown: (id: string) => eventsById.has(id),
    }),
    [eventsById],
  );

  /* Contract v1.2 views. Each degrades to "not served" on a v1.1 backend. */
  const archives = useMemo(
    () => (incident ? archiveEvidence(events, incident.links).map((item) => ({
      ...item,
      // The serving's own request may sit in another case of the run: look there too.
      claims: item.claims.map((claim) => (claim.claim === 'requested' && claim.state === 'not_observed' && backendContext
        ? archiveEvidence([...backendContext.events], incident.links)
          .find((other) => other.served_event_id === item.served_event_id)?.claims.find((c) => c.claim === 'requested') ?? claim
        : claim)),
    })) : []),
    [incident, events, backendContext],
  );
  const hasWebTraffic = events.some((event) => event.sensor_id === 'web-decoy-01');
  const scope = useMemo(() => responseScope(backendContext?.eligibility ?? null), [backendContext]);

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

  if (!incident || !evidence) return null;

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
        <GatedActionButton eligibility={evidence.eligibility} onClick={() => setBlocking(true)}>
          <ShieldBan size={15} /> Block source
        </GatedActionButton>
      </div>

      <header className={`inchero inchero--${incident.severity}`}>
        <div className="inchero__main">
          <div className="inchero__eyebrow">
            <span className={`badge badge--${incident.severity}`}>{incident.severity}</span>
            <span>
              {incident.incident_id} · {incident.lab_run_id}
            </span>
            {evidence.profile.capture_modes.map((mode) => (
              <ModeBadge key={mode} mode={mode} />
            ))}
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
          <span
            className="inchero__score-label"
            title={incident.case_kind ? 'Score supplied by the backend for this case or investigation.' : 'Legacy score for the source address in this run.'}
          >
            {incident.case_kind ? incident.case_kind === 'investigation' ? 'Investigation score' : 'Case score' : 'Source score · v1.0'}
          </span>
          <span className={`inchero__score-value inchero__score-value--${incident.severity}`}>
            {number(incident.score)}
          </span>
          <span className="inchero__score-hint">
            {incident.findings.length} findings across {evidence.cases.length} session case
            {evidence.cases.length === 1 ? '' : 's'}
          </span>
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
              <EligibilityNotice eligibility={evidence.eligibility} />
              <ScopeNote scope={scope} />
              {incident.active_block !== null ? (
                <ActionCard action={incident.active_block} onExpired={() => void load()} />
              ) : null}
              {sourceActions.length > 0 ? (
                <p className="decide__none">
                  Actions targeting {incident.src_ip} in this run. Older actions without run metadata are also shown.
                </p>
              ) : null}
              {sourceActions.map((action) => (
                <VerificationTimeline
                  key={action.action_id}
                  verification={verificationFromV1(action)}
                  {...evidenceHandlers}
                />
              ))}
              {incident.active_block === null && !hasLiveAction ? (
                <>
                  {sourceActions.length === 0 ? <p className="decide__none">No action applied.</p> : null}
                  <GatedActionButton
                    eligibility={evidence.eligibility}
                    className="btn btn--block"
                    onClick={() => setBlocking(true)}
                  >
                    Preview block
                  </GatedActionButton>
                </>
              ) : null}
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
              Clear {stageLabel(stageFilter)} filter
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

      <section className="incsec">
        <h2 className="incsec__title">
          Mapping rationale <span className="incsec__count">{evidence.mappings.length}</span>
        </h2>
        <p className="incsec__note">
          Each technique id with its reason and limitation. No technique is a valid answer.
        </p>
        <MappingList mappings={evidence.mappings} basis={incident.case_kind ? 'contract_v11' : 'contract_v1'} {...evidenceHandlers} />
      </section>

      <section className="incsec evsection" aria-label="Evidence structure">
        <h2 className="incsec__title">Evidence structure</h2>
        <p className="incsec__note">
          The source is an observed endpoint. Each decoy session is its own case. Only an
          analyst-approved relation joins cases across decoys.
        </p>
        <p className="incsec__note">
          {incident.case_kind ? 'Cases, investigations and their scores come from the backend. The source profile contains observations and has no combined score.'
            : <>These cases and the parent are <strong>display groupings</strong> built from legacy events.</>}
        </p>

        <SourceProfileCard profile={evidence.profile} {...evidenceHandlers} />

        {evidence.parents.map((parent) => (
          <ParentCard
            key={parent.parent_id}
            parent={parent}
            cases={evidence.cases}
            relations={evidence.relations}
          />
        ))}

        <div className="evsection__label">
          Cases <span className="incsec__count">{evidence.cases.length}</span>
        </div>
        {evidence.cases.length === 0 ? (
          <EmptyState title="No session cases." hint="Cases appear as the decoys record sessions." />
        ) : (
          <div className="casegrid">
            {evidence.cases.map((item) => (
              <SessionCaseCard
                key={item.case_id}
                item={item}
                transcriptHref={
                  hasTranscript(item.sensor_id) && item.session_id && item.commands > 0
                    ? `/incidents/${item.authority === 'backend_case' ? item.case_id : incident.incident_id}/transcript/${item.session_id}`
                    : null
                }
                {...evidenceHandlers}
              />
            ))}
          </div>
        )}

        <div className="evsection__label">
          Relations <span className="incsec__count">{evidence.relations.length}</span>
        </div>
        {evidence.relations.length === 0 ? (
          <EmptyState
            title="No cross-decoy relations."
            hint="A candidate appears when this source touches both decoys within 5 minutes."
          />
        ) : (
          <div className="rellist">
            {evidence.relations.map((relation) => {
              const link = incident.links.find((item) => item.link_id === relation.relation_id);
              return (
                <RelationCard
                  key={relation.relation_id}
                  relation={relation}
                  cases={evidence.cases}
                  onDecide={link ? () => setDecidingLink(link) : undefined}
                  {...evidenceHandlers}
                />
              );
            })}
          </div>
        )}
      </section>

      {archives.length > 0 ? (
        <section className="incsec" aria-label="Archive bait">
          <h2 className="incsec__title">
            Archive bait <span className="incsec__count">{archives.length}</span>
          </h2>
          <ArchivePanel items={archives} {...evidenceHandlers} />
        </section>
      ) : null}

      {hasWebTraffic ? (
        <section className="incsec" aria-label="Gateway routing">
          <h2 className="incsec__title">Gateway routing</h2>
          <RoutingPanel incidentId={incident.incident_id} onOpenEvent={evidenceHandlers.onOpenEvent} />
        </section>
      ) : null}

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
            void loadActions();
          }}
          onChanged={() => {
            void load();
            void loadActions();
          }}
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
