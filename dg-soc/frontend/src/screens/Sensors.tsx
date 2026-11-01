/**
 * Sensors. The decoys the backend hears from and what each one has sent.
 * Sensor management is still being built (M2), so this page only reads.
 *
 * Health and activity are separate (review section 13, F9). GET /api/health
 * in v1.0 reports only each sensor's last event time, which is attacker
 * activity: it says nothing about whether a collector is alive. So the health
 * panel shows service liveness, says collection health is not reported, and
 * lists activity on its own.
 */

import { ArrowRight } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { sensorActivity, sensorHealth } from '../components/Shell';
import { HealthDimensions } from '../components/evidence/HealthDimensions';
import { healthFromV1 } from '../evidence/fromV1';
import { Dot } from '../components/primitives';
import { eventTypeLabel } from '../copy';
import { number, timeUtc } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { SENSOR_IDS, type EventType } from '../types/api';
import { fetchSources, isNotServed } from '../api/client';
import { SourcesPanel } from '../v12/components';
import type { SourcesRegistry } from '../v12/types';
import { sourceRows } from '../v12/views';

interface SensorDef {
  id: string;
  name: string;
  decoy: string;
  port: string;
  what: string;
  planned?: boolean;
  /** v1.2 decoy: shown as not on this backend until the backend reports it. */
  v12?: boolean;
}

const SENSORS: SensorDef[] = [
  {
    id: 'ssh-decoy-01',
    name: 'SSH decoy',
    decoy: 'D1 · Cowrie, emulated mode',
    port: '2222',
    what: 'Login prompt and an emulated shell. Commands are recorded, never executed.',
  },
  {
    id: 'web-decoy-01',
    name: 'Web decoy',
    decoy: 'D2 · Flask bait portal',
    port: '8080',
    what: 'Staff portal, hidden paths, a fake .env and a synthetic customer export.',
  },
  {
    id: 'db-decoy-01',
    name: 'MySQL decoy',
    decoy: 'D3 · authentication deception (contract v1.2)',
    port: '3306',
    what: 'Records the login handshake and command packets. Never sees a password, never executes a query.',
    v12: true,
  },
  {
    id: 'file-decoy-01',
    name: 'SMB file decoy',
    decoy: 'D4 · file-service honeypot (contract v1.2)',
    port: '445',
    what: 'Records logins and file operations. Uploads are stored inert or discarded; never executed or given a verdict.',
    v12: true,
  },
];

export function Sensors() {
  const { events, health, healthCheckedAt, status } = useLiveStore();
  const [registry, setRegistry] = useState<SourcesRegistry | null>(null);
  const [registryState, setRegistryState] = useState<'loading' | 'served' | 'not_served' | 'error'>('loading');
  useEffect(() => {
    let alive = true;
    fetchSources()
      .then((value) => { if (alive) { setRegistry(value); setRegistryState('served'); } })
      .catch((error) => { if (alive) setRegistryState(isNotServed(error) ? 'not_served' : 'error'); });
    return () => { alive = false; };
  }, []);
  const rows = useMemo(() => sourceRows(registry, health), [registry, health]);
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 5000);
    return () => clearInterval(timer);
  }, []);

  const bySensor = useMemo(() => {
    const out = new Map<string, { total: number; types: Map<EventType, number>; last: (typeof events)[number] | null }>();
    for (const event of events) {
      const entry = out.get(event.sensor_id) ?? { total: 0, types: new Map(), last: null };
      entry.total += 1;
      entry.types.set(event.event_type, (entry.types.get(event.event_type) ?? 0) + 1);
      if (!entry.last || event.seq > entry.last.seq) entry.last = event;
      out.set(event.sensor_id, entry);
    }
    return out;
  }, [events]);

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Sensors</h1>
        <span className="page__head-spacer" />
        <span className="pill">Read-only · management in progress</span>
      </div>

      <section className="panel" style={{ marginBottom: 'var(--s4)', padding: 'var(--s4)' }}>
        <HealthDimensions
          view={healthFromV1(health, healthCheckedAt, SENSOR_IDS)}
          stream={status.state}
          now={now}
        />
      </section>

      <section className="panel" style={{ marginBottom: 'var(--s4)', padding: 'var(--s4)' }} aria-label="Sources">
        {registryState === 'loading' ? (
          <p className="v12note">Loading source registry…</p>
        ) : (
          <SourcesPanel
            honeypots={rows.honeypots}
            telemetry={rows.telemetry}
            honeypotCount={rows.honeypot_count}
            registryServed={registryState === 'served'}
            now={now}
          />
        )}
      </section>

      <div className="sensorgrid">
        {SENSORS.map((sensor) => {
          // A v1.2 decoy is only "on this backend" once the backend reports it.
          const absent = sensor.planned || (sensor.v12 && !(health && sensor.id in health.sensors));
          const state = absent
            ? { tone: 'neutral' as const, text: sensor.planned ? 'not deployed' : 'not on this backend' }
            : sensorHealth(health, sensor.id);
          const activity = absent ? null : sensorActivity(health, sensor.id, now);
          const stats = bySensor.get(sensor.id);
          const types = stats ? [...stats.types.entries()].sort((a, b) => b[1] - a[1]) : [];
          const max = Math.max(1, ...types.map(([, count]) => count));

          return (
            <section
              key={sensor.id}
              className={absent ? 'sensorcard sensorcard--planned' : 'sensorcard'}
            >
              <header className="sensorcard__head">
                <Dot tone={state.tone} />
                <div>
                  <h2 className="sensorcard__name">{sensor.name}</h2>
                  <div className="sensorcard__id">
                    {sensor.id} · :{sensor.port}
                  </div>
                </div>
                <span className="sensorcard__status" title="Service and collection health">
                  {state.text}
                </span>
              </header>

              <p className="sensorcard__what">
                <strong>{sensor.decoy}.</strong> {sensor.what}
              </p>

              {absent ? null : (
                <>
                  {activity ? (
                    <p className="sensorcard__activity" title="Attacker activity, not health">
                      <span className="activity__mark" aria-hidden="true" /> Activity: {activity.text}
                    </p>
                  ) : null}
                  <div className="sensorcard__stat">
                    <span className="sensorcard__num">{number(stats?.total ?? 0)}</span>
                    <span className="sensorcard__unit">events in this window</span>
                  </div>

                  {types.length > 0 ? (
                    <ul className="sensorcard__types">
                      {types.map(([type, count]) => (
                        <li key={type}>
                          <span className="sensorcard__type">{eventTypeLabel(type)}</span>
                          <span className="sensorcard__bar">
                            <span style={{ width: `${(count / max) * 100}%` }} />
                          </span>
                          <span className="sensorcard__count">{count}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="state__hint">Nothing received from this sensor yet.</p>
                  )}

                  <footer className="sensorcard__foot">
                    {stats?.last ? (
                      <span>
                        Last: {eventTypeLabel(stats.last.event_type)} at{' '}
                        {timeUtc(stats.last.occurred_at)} UTC
                      </span>
                    ) : (
                      <span>No events yet</span>
                    )}
                    <Link to={`/events?sensor=${encodeURIComponent(sensor.id)}`} className="linkbtn">
                      Live feed <ArrowRight size={14} />
                    </Link>
                  </footer>
                </>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}
