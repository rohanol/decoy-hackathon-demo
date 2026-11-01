import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchEvents, fetchHealth, fetchIncident, fetchTripRuns } from '../api/client';
import { USE_FIXTURES } from '../api/config';
import { matchesTrip, tripCommand, tripVerdict, type Trip } from '../lib/controlledTrip';
import { useLiveStore } from '../state/LiveStore';
import type { Finding, Health, SocEvent } from '../types/api';
import '../styles/trip.css';

interface Observation {
  event: SocEvent | null;
  findings: Finding[];
  health: Health | null;
  checkedAt: number;
  completedAt: number | null;
}
const EMPTY: Observation = { event: null, findings: [], health: null, checkedAt: 0, completedAt: null };

export function ControlledTrip() {
  const { events } = useLiveStore();
  const [trip, setTrip] = useState<Trip | null>(null);
  const [observation, setObservation] = useState<Observation>(EMPTY);
  const [now, setNow] = useState(Date.now);
  const [preparing, setPreparing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  async function start() {
    setPreparing(true);
    setError(null);
    try {
      const runs = await fetchTripRuns();
      const active = runs.items.filter(r => r.active && r.capture_mode === 'live' && !r.legacy_mixed);
      const activeRun = active[0];
      if (active.length !== 1 || !activeRun) throw new Error('No single active live run. Make one normal request from attacker Kali, then retry.');
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      const nonce = 'trip_' + [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
      setObservation(EMPTY);
      setCopied(false);
      setTrip({ nonce, runId: activeRun.lab_run_id, minSeq: Math.max(0, ...events.map(e => e.seq)), startedAt: Date.now() });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Unable to prepare check.');
    } finally {
      setPreparing(false);
    }
  }

  useEffect(() => {
    if (!trip) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cursor = trip.minSeq;
    let matched: SocEvent | null = null;
    async function poll() {
      try {
        const [page, health] = await Promise.all([
          fetchEvents({ lab_run_id: trip!.runId, capture_mode: 'live', sensor_id: 'web-decoy-01', since_seq: cursor, limit: 1000 }),
          fetchHealth(),
        ]);
        if (!alive) return;
        cursor = Math.max(cursor, page.next_seq);
        matched ??= page.items.find(e => matchesTrip(e, trip!)) ?? null;
        const findings = matched?.incident_id ? (await fetchIncident(matched.incident_id)).findings : [];
        if (!alive) return;
        const checkedAt = Date.now();
        const result = tripVerdict(trip!, matched, findings, health, checkedAt, checkedAt);
        setError(null);
        setObservation({ event: matched, findings, health, checkedAt, completedAt: result.status === 'passed' ? checkedAt : null });
        if (result.status !== 'waiting') return;
      } catch {
        if (!alive) return;
        setError('Evidence read unavailable. No successful trip is claimed; check the backend and collector.');
      }
      if (alive && Date.now() - trip!.startedAt <= 90_000) timer = setTimeout(poll, 2000);
    }
    void poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [trip]);

  const verdict = trip ? tripVerdict(trip, observation.event, observation.findings, observation.health,
    observation.checkedAt, now, observation.completedAt) : null;
  const label = error && trip ? 'Read unavailable' : verdict?.status === 'passed' ? 'Last web trip passed'
    : verdict?.status === 'expired' ? 'Last result expired' : verdict?.status === 'incomplete' ? 'Incomplete'
    : verdict?.status === 'waiting' ? 'Waiting for evidence' : 'Not checked';
  const command = trip ? tripCommand(trip.nonce) : '';
  return (
    <section className="panel trip" aria-label="Controlled trip test">
      <div className="trip__head">
        <div><h2>Chain health · controlled web trip</h2><p>Prove one request travelled through the decoy, collector, backend rule and this dashboard.</p></div>
        <span className={`pill trip__status trip__status--${error ? 'error' : verdict?.status ?? 'idle'}`} role="status">{label}</span>
      </div>
      <p className="trip__scope">Scope: web-decoy-01 only. Uses observed live evidence; other honeypots and continuous health are not certified by this check.</p>
      <button className="btn" type="button" onClick={() => void start()} disabled={preparing || USE_FIXTURES}>
        {preparing ? 'Preparing…' : trip ? 'Start a new web trip' : 'Start web trip'}
      </button>
      {USE_FIXTURES ? <p>Unavailable in fixture mode.</p> : null}
      {error ? <p className="trip__error" role="alert">{error}</p> : null}
      {trip ? <>
        <p className="trip__instruction">Run this one command on attacker Kali <strong>192.168.77.10</strong> within 90 seconds. HTTP 500 is the expected canned result.</p>
        <label className="trip__command-label">Attacker command<textarea aria-label="Attacker trip command" readOnly value={command} rows={6} spellCheck={false} /></label>
        <button className="btn" type="button" onClick={() => {
          if (navigator.clipboard) void navigator.clipboard.writeText(command).then(() => setCopied(true)).catch(() => setCopied(false));
        }}>{copied ? 'Copied' : 'Copy command'}</button>
        <ol className="trip__steps">
          <li data-passed={verdict?.request}>Request stored from .10 in live run <code>{trip.runId}</code> · {verdict?.request ? 'observed' : 'waiting'}</li>
          <li data-passed={Boolean(verdict?.finding)}>R07 SQLi alert cites this exact event · {verdict?.finding ? 'observed' : 'waiting'}</li>
          <li data-passed={verdict?.collector}>Collector heartbeat, read and ingest current at check · {verdict?.collector ? 'observed' : 'waiting'}</li>
        </ol>
        {observation.event ? <p className="trip__evidence">Event <code>{observation.event.event_id}</code>
          {verdict?.finding ? <> · Finding <code>{verdict.finding.finding_id}</code></> : null}
          {observation.event.incident_id ? <> · <Link to={`/incidents/${observation.event.incident_id}`}>Open incident evidence</Link></> : null}
        </p> : null}
        {observation.completedAt ? <p>Passed at {new Date(observation.completedAt).toISOString()}. This result expires after five minutes.</p> : null}
        {verdict?.status === 'incomplete' ? <p>One or more stages were not verified within 90 seconds. Check the command result, active run, policy and collector before retrying.</p> : null}
      </> : null}
    </section>
  );
}
