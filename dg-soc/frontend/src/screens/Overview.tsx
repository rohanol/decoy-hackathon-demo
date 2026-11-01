/**
 * Screen 1 — Overview. DESIGN_SPEC.md section 6.
 *
 * The screen on display before the demo starts and after it ends. It has one
 * job: make the noise-reduction argument visible in a single glance, because
 * that is the argument the whole project rests on. A deception decoy has no
 * legitimate users, so "900 raw records became 2 cases" is not a filtering
 * trick — it is the point.
 *
 * Built for the ten-foot view as well as the desk: big white numbers, colour
 * only where it carries severity, and every number straight from
 * GET /api/stats/overview. Nothing is derived in the browser except bar
 * widths, which are proportional decoration beside the numbers they show.
 */

import { ArrowRight } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useCallback, useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { ApiError, fetchIncidents, fetchOverview } from '../api/client';
import { CountUp } from '../components/CountUp';
import { KillChainStrip } from '../components/KillChainBar';
import { EmptyState, ErrorCard, SkeletonRows } from '../components/primitives';
import { COPY, RULE_NAME, eventTypeLabel } from '../copy';
import { styleOf } from '../lib/eventStyle';
import { number, relativeFromNow, seconds, timeUtc } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { RULE_IDS, type IncidentSummary, type StatsOverview } from '../types/api';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 } as const;
const whole = (value: number) => number(Math.round(value));

function Kpi({
  label,
  value,
  format,
  hint,
  tone,
}: {
  label: string;
  value: number | null;
  format: (value: number) => string;
  hint: string;
  tone?: 'muted';
}) {
  return (
    <section className="kpi">
      <span className="kpi__label">{label}</span>
      <span className={tone === 'muted' ? 'kpi__value kpi__value--muted' : 'kpi__value'}>
        {value === null ? '—' : <CountUp value={value} format={format} />}
      </span>
      <span className="kpi__hint">{hint}</span>
    </section>
  );
}

function NoiseFunnel({ stats }: { stats: StatsOverview }) {
  const raw = Math.max(stats.raw_events, 1);
  const rows = [
    { label: 'Raw events', value: stats.raw_events, tone: 'raw' },
    { label: 'Incidents to review', value: stats.incidents, tone: 'cases' },
    { label: 'Low priority', value: stats.low_priority_incidents, tone: 'low' },
  ];

  return (
    <div className="funnel">
      <p className="funnel__headline">
        <strong>{number(stats.raw_events)}</strong> raw event{stats.raw_events === 1 ? '' : 's'}{' '}
        became <strong>{number(stats.incidents)}</strong> incident
        {stats.incidents === 1 ? '' : 's'} to review.
      </p>
      <div className="funnel__rows">
        {rows.map((row) => (
          <div key={row.label} className="funnel__row" title={`${row.label}: ${number(row.value)}`}>
            <span className="funnel__label">{row.label}</span>
            <span className="funnel__track">
              <motion.span
                className={`funnel__fill funnel__fill--${row.tone}`}
                initial={{ width: 0 }}
                animate={{ width: `${Math.max(row.value > 0 ? 1.5 : 0, (row.value / raw) * 100)}%` }}
                transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
              />
            </span>
            <span className="funnel__value">{number(row.value)}</span>
          </div>
        ))}
      </div>
      <p className="funnel__note">{COPY.noiseCounterNote}</p>
    </div>
  );
}

function FindingsByRule({ stats }: { stats: StatsOverview }) {
  const counts = RULE_IDS.map((ruleId) => ({
    ruleId,
    count: stats.findings_by_rule[ruleId] ?? 0,
  }));
  const max = Math.max(1, ...counts.map((row) => row.count));

  return (
    <div className="rules">
      {counts.map(({ ruleId, count }, index) => (
        <div
          key={ruleId}
          className={count > 0 ? 'rule' : 'rule rule--zero'}
          title={`${ruleId} · ${RULE_NAME[ruleId] ?? ''}: ${count} finding${count === 1 ? '' : 's'}`}
        >
          <span className="rule__id">{ruleId}</span>
          <span className="rule__name">{RULE_NAME[ruleId]}</span>
          <span className="rule__track">
            <motion.span
              className="rule__fill"
              initial={{ width: 0 }}
              animate={{ width: `${(count / max) * 100}%` }}
              transition={{ duration: 0.7, delay: index * 0.04, ease: [0.22, 1, 0.36, 1] }}
            />
          </span>
          <span className="rule__count">{count}</span>
        </div>
      ))}
      {/* Every rule that can fire stays visible at zero, so the set of things
          being looked for is legible even before anything happens. There is
          deliberately no R06. */}
      <p className="rules__note">Rules at zero have not fired in this run.</p>
    </div>
  );
}

function LatestActivity() {
  const { events, snapshotMaxSeq } = useLiveStore();
  const latest = events.slice(0, 7);

  if (latest.length === 0) {
    return <EmptyState title={COPY.emptyFeedTitle} hint={COPY.emptyFeedHint} />;
  }

  return (
    <ol className="activity">
      <AnimatePresence initial={false}>
        {latest.map((event) => {
          const style = styleOf(event.event_type);
          return (
            <motion.li
              key={event.event_id}
              layout
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              className={event.seq > snapshotMaxSeq ? 'activity__row activity__row--new' : 'activity__row'}
            >
              <span className={`activity__glyph evtype--${style.tone}`}>{style.glyph}</span>
              <span className="activity__what">{eventTypeLabel(event.event_type)}</span>
              <span className="activity__ip">{event.src_ip}</span>
              <span className="activity__time">{timeUtc(event.occurred_at)}</span>
            </motion.li>
          );
        })}
      </AnimatePresence>
    </ol>
  );
}

function IncidentRow({ incident }: { incident: IncidentSummary }) {
  return (
    <RouterLink to={`/incidents/${incident.incident_id}`} className={`ovinc ovinc--${incident.severity}`}>
      <span className={`ovinc__score ovinc__score--${incident.severity}`}>{number(incident.score)}</span>
      <span className="ovinc__main">
        <span className="ovinc__ip">{incident.src_ip}</span>
        <span className="ovinc__meta">
          <span className={`badge badge--${incident.severity}`}>{incident.severity}</span>
          {number(incident.event_count)} events · last {relativeFromNow(incident.last_seen)}
        </span>
      </span>
      <span className="ovinc__chain">
        <KillChainStrip stagesObserved={incident.stages_observed} severity={incident.severity} />
      </span>
      <ArrowRight className="ovinc__go" size={18} />
    </RouterLink>
  );
}

export function Overview() {
  const { connectionEpoch, subscribe } = useLiveStore();

  const [stats, setStats] = useState<StatsOverview | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [loadedStats, incidentsPage] = await Promise.all([fetchOverview(), fetchIncidents()]);
      setStats(loadedStats);
      setIncidents(incidentsPage.items);
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('overview_load_failed', 'Could not load the overview.', 0),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // API.md: reload the snapshot on every reconnect.
  useEffect(() => {
    if (connectionEpoch > 0) void load();
  }, [connectionEpoch, load]);

  /**
   * These counters move on almost every commit, so rather than re-fetch per
   * message we re-fetch on a trailing debounce. /api/stats/overview has no
   * push of its own.
   */
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const unsubscribe = subscribe(() => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => void load(), 600);
    });
    return () => {
      unsubscribe();
      if (timer) clearTimeout(timer);
    };
  }, [subscribe, load]);

  if (loading && stats === null) {
    return (
      <div className="page">
        <section className="card">
          <SkeletonRows rows={6} />
        </section>
      </div>
    );
  }

  if (error && stats === null) {
    return (
      <div className="page">
        <div className="page__head">
          <h1 className="page__title">Overview</h1>
        </div>
        <ErrorCard error={error} onRetry={() => void load()} />
      </div>
    );
  }

  // Most severe first, then most recent: the order an analyst should read them.
  const sorted = [...incidents].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.last_seen.localeCompare(a.last_seen),
  );

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Overview</h1>
      </div>

      <div className="kpis">
        <Kpi
          label="Raw events"
          value={stats?.raw_events ?? null}
          format={whole}
          hint="deduplicated sensor records"
        />
        <Kpi
          label="Incidents"
          value={stats?.incidents ?? null}
          format={whole}
          hint="grouped by source IP"
        />
        <Kpi
          label="Low priority"
          value={stats?.low_priority_incidents ?? null}
          format={whole}
          hint={COPY.lowPriorityTooltip}
          tone="muted"
        />
        <Kpi
          label="Time to first alert"
          value={stats?.first_alert_seconds ?? null}
          format={(value) => seconds(value)}
          hint={
            stats?.first_alert_seconds == null
              ? 'no findings yet'
              : 'backend arrival → first finding, one incident; not end-to-end latency'
          }
        />
      </div>

      <div className="ovgrid2">
        <section className="panel">
          <header className="panel__head">
            <h2 className="panel__title" title="Grouping compression, not detection accuracy">
              Event grouping
            </h2>
          </header>
          {stats ? <NoiseFunnel stats={stats} /> : null}
        </section>

        <section className="panel">
          <header className="panel__head">
            <h2 className="panel__title">Findings by rule</h2>
          </header>
          {stats ? <FindingsByRule stats={stats} /> : null}
        </section>
      </div>

      <div className="ovgrid2 ovgrid2--wide">
        <section className="panel">
          <header className="panel__head">
            <h2 className="panel__title">Active incidents</h2>
            <span className="panel__count">{sorted.length}</span>
            <RouterLink to="/incidents" className="linkbtn panel__link">
              All incidents <ArrowRight size={14} />
            </RouterLink>
          </header>
          {sorted.length === 0 ? (
            <EmptyState title={COPY.emptyIncidentsTitle} hint={COPY.emptyIncidentsHint} />
          ) : (
            <div className="ovincs">
              {sorted.map((incident) => (
                <IncidentRow key={incident.incident_id} incident={incident} />
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <header className="panel__head">
            <h2 className="panel__title">Latest activity</h2>
            <span className="livedot" aria-hidden="true" />
            <RouterLink to="/events" className="linkbtn panel__link">
              Live feed <ArrowRight size={14} />
            </RouterLink>
          </header>
          <LatestActivity />
        </section>
      </div>
    </div>
  );
}
