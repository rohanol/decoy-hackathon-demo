/**
 * Screen 1 — Overview. DESIGN_SPEC.md section 6.
 *
 * The screen on display before the demo starts and after it ends. It has one
 * job: make the noise-reduction argument visible in a single glance, because
 * that is the argument the whole project rests on. A deception decoy has no
 * legitimate users, so "900 raw records became 2 cases" is not a filtering
 * trick — it is the point.
 *
 * Every number comes from GET /api/stats/overview. Nothing here is derived in
 * the browser except the bar widths, which are proportional decoration beneath
 * the numbers they illustrate.
 */

import { useCallback, useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { ApiError, fetchIncidents, fetchOverview } from '../api/client';
import { KillChainStrip } from '../components/KillChainBar';
import { Card, EmptyState, ErrorCard, SkeletonRows } from '../components/primitives';
import { COPY } from '../copy';
import { number, seconds } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { RULE_IDS, type IncidentSummary, type StatsOverview } from '../types/api';

function NoiseCounter({ stats }: { stats: StatsOverview }) {
  const raw = Math.max(stats.raw_events, 1);
  const incidentPct = Math.min(100, (stats.incidents / raw) * 100);
  const lowPct = Math.min(100, (stats.low_priority_incidents / raw) * 100);

  return (
    <div className="card__body">
      <div className="metrics">
        <div className="metric">
          <div className="metric__value">{number(stats.raw_events)}</div>
          <div className="metric__label">raw events</div>
        </div>
        <div className="metric__arrow" aria-hidden="true">
          →
        </div>
        <div className="metric">
          <div className="metric__value">{number(stats.incidents)}</div>
          <div className="metric__label">incidents</div>
        </div>
        <div className="metric">
          <div
            className="metric__value metric__value--muted"
            title={COPY.lowPriorityTooltip}
          >
            {number(stats.low_priority_incidents)}
          </div>
          <div className="metric__label" title={COPY.lowPriorityTooltip}>
            low priority
          </div>
        </div>
      </div>

      {/* Decoration beneath the numbers, never instead of them. */}
      <div className="noisebar" aria-hidden="true">
        <span className="noisebar__raw" />
        <span className="noisebar__incidents" style={{ width: `${Math.max(incidentPct, 1)}%` }} />
        <span className="noisebar__low" style={{ width: `${lowPct}%` }} />
      </div>

      <p className="noisebar__sentence">
        {number(stats.raw_events)} raw event{stats.raw_events === 1 ? '' : 's'} →{' '}
        {number(stats.incidents)} incident{stats.incidents === 1 ? '' : 's'},{' '}
        {number(stats.low_priority_incidents)} low priority
      </p>
      <p className="state__hint" style={{ textAlign: 'left' }}>
        {COPY.noiseCounterNote}
      </p>
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
    <div className="card__body">
      <div className="rulebars">
        {counts.map(({ ruleId, count }) => (
          <div key={ruleId} className={count > 0 ? 'rulebar' : 'rulebar rulebar--zero'}>
            <span className="rulebar__id mono">{ruleId}</span>
            <span className="rulebar__track">
              <span className="rulebar__fill" style={{ width: `${(count / max) * 100}%` }} />
            </span>
            <span className="rulebar__count mono">{count}</span>
          </div>
        ))}
      </div>
      {/* Every rule that can fire stays visible at zero, so the set of things
          being looked for is legible even before anything happens. There is
          deliberately no R06. */}
      <p className="state__hint" style={{ textAlign: 'left', marginTop: 'var(--s3)' }}>
        Rules at zero have not fired in this run.
      </p>
    </div>
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

  const sorted = [...incidents].sort((a, b) => b.last_seen.localeCompare(a.last_seen));

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Overview</h1>
      </div>

      <div className="ovgrid">
        <Card title="Noise reduction">
          {stats ? <NoiseCounter stats={stats} /> : null}
        </Card>

        <Card title="Time to first alert">
          <div className="card__body">
            <div className="metric metric--solo">
              <div className="metric__value">
                {stats?.first_alert_seconds == null ? '—' : seconds(stats.first_alert_seconds)}
              </div>
              <div className="metric__label">first event → first finding</div>
            </div>
            {stats?.first_alert_seconds == null ? (
              <p className="state__hint" style={{ textAlign: 'left' }}>
                No findings yet.
              </p>
            ) : null}
          </div>
        </Card>
      </div>

      <div style={{ marginTop: 'var(--s4)' }}>
        <Card title="Findings by rule">
          {stats ? <FindingsByRule stats={stats} /> : null}
        </Card>
      </div>

      <div style={{ marginTop: 'var(--s4)' }}>
        <Card title={`Active incidents (${sorted.length})`}>
          <div className="card__body">
            {sorted.length === 0 ? (
              <EmptyState title={COPY.emptyIncidentsTitle} hint={COPY.emptyIncidentsHint} />
            ) : (
              <div className="ovlist">
                {sorted.map((incident) => (
                  <RouterLink
                    key={incident.incident_id}
                    to={`/incidents/${incident.incident_id}`}
                    className="ovrow"
                  >
                    <span className="ovrow__ip mono">{incident.src_ip}</span>
                    <span className={`badge badge--${incident.severity}`}>
                      {incident.severity}
                    </span>
                    <span className={`ovrow__score ovrow__score--${incident.severity}`}>
                      {number(incident.score)}
                    </span>
                    <span className="ovrow__chain">
                      <KillChainStrip
                        stagesObserved={incident.stages_observed}
                        severity={incident.severity}
                      />
                    </span>
                  </RouterLink>
                ))}
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
