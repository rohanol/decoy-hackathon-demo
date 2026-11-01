/**
 * Sensors. The decoys the backend hears from, what each one has sent, and how
 * fresh it is. Sensor management is still being built (M2), so this page only
 * reads: GET /api/health for freshness, the live store for counts.
 */

import { ArrowRight } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { sensorState } from '../components/Shell';
import { Dot } from '../components/primitives';
import { EVENT_TYPE_LABEL } from '../copy';
import { number, timeUtc } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import type { EventType } from '../types/api';

interface SensorDef {
  id: string;
  name: string;
  decoy: string;
  port: string;
  what: string;
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
];

export function Sensors() {
  const { events, health } = useLiveStore();
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

      <div className="sensorgrid">
        {SENSORS.map((sensor) => {
          const state = sensorState(health, sensor.id, now);
          const stats = bySensor.get(sensor.id);
          const types = stats ? [...stats.types.entries()].sort((a, b) => b[1] - a[1]) : [];
          const max = Math.max(1, ...types.map(([, count]) => count));

          return (
            <section key={sensor.id} className="sensorcard">
              <header className="sensorcard__head">
                <Dot tone={state.tone} animate={state.tone === 'ok' ? 'pulse' : undefined} />
                <div>
                  <h2 className="sensorcard__name">{sensor.name}</h2>
                  <div className="sensorcard__id">
                    {sensor.id} · :{sensor.port}
                  </div>
                </div>
                <span className="sensorcard__status">{state.text}</span>
              </header>

              <p className="sensorcard__what">
                <strong>{sensor.decoy}.</strong> {sensor.what}
              </p>

              <>
                  <div className="sensorcard__stat">
                    <span className="sensorcard__num">{number(stats?.total ?? 0)}</span>
                    <span className="sensorcard__unit">events in this window</span>
                  </div>

                  {types.length > 0 ? (
                    <ul className="sensorcard__types">
                      {types.map(([type, count]) => (
                        <li key={type}>
                          <span className="sensorcard__type">{EVENT_TYPE_LABEL[type]}</span>
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
                        Last: {EVENT_TYPE_LABEL[stats.last.event_type]} at{' '}
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
            </section>
          );
        })}
      </div>
    </div>
  );
}
