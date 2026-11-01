/**
 * Health in three separate dimensions (review section 13, finding F9):
 *
 *   Service     is the backend answering, is the event stream connected
 *   Collection  is each collector running and keeping up, as it reports
 *   Activity    when attacker traffic last arrived
 *
 * Activity is never health. A quiet decoy can be perfectly healthy, and a
 * collector can be dead while its last event is a minute old. When the
 * backend does not report collection health, this says "not reported"
 * instead of guessing it from traffic.
 */

import { HEALTH_COPY, SENSOR_LABEL } from '../../copy';
import type { CollectorHealth, HealthView } from '../../evidence/model';
import { number, relativeFromNow } from '../../lib/format';
import type { ConnectionState } from '../../api/socket';
import { Dot } from '../primitives';
import { BasisTag } from './bits';

/** A heartbeat older than this is shown as stale, whatever the process says. */
const HEARTBEAT_STALE_S = 30;

type Tone = 'ok' | 'warn' | 'danger' | 'neutral';

function collectorTone(collector: CollectorHealth, now: Date): { tone: Tone; text: string } {
  if (collector.process_state === 'stopped') return { tone: 'danger', text: 'stopped' };
  if (collector.process_state === 'unknown') return { tone: 'neutral', text: 'state unknown' };
  if (!collector.heartbeat_at) return { tone: 'warn', text: 'running · no heartbeat' };
  const age = (now.getTime() - Date.parse(collector.heartbeat_at)) / 1000;
  if (age > HEARTBEAT_STALE_S) return { tone: 'warn', text: `heartbeat stale · ${relativeFromNow(collector.heartbeat_at, now)}` };
  return { tone: 'ok', text: 'running' };
}

const STREAM_TEXT: Record<ConnectionState, { tone: Tone; text: string }> = {
  live: { tone: 'ok', text: 'connected' },
  connecting: { tone: 'warn', text: 'connecting' },
  reconnecting: { tone: 'warn', text: 'reconnecting' },
  offline: { tone: 'danger', text: 'offline' },
};

export function HealthDimensions({
  view,
  stream,
  now,
}: {
  view: HealthView;
  stream: ConnectionState;
  now: Date;
}) {
  const backendTone: Tone = view.service.backend === 'up' ? 'ok' : view.service.backend === 'down' ? 'danger' : 'neutral';
  const streamState = STREAM_TEXT[stream];

  return (
    <div className="healthdims" data-basis={view.basis}>
      <section className="healthdim" aria-label={HEALTH_COPY.service}>
        <header className="healthdim__head">
          <h3 className="healthdim__title">{HEALTH_COPY.service}</h3>
          <BasisTag basis={view.basis} />
        </header>
        <p className="healthdim__hint">{HEALTH_COPY.serviceHint}</p>
        <ul className="healthdim__rows">
          <li>
            <Dot tone={backendTone} />
            <span>Backend API</span>
            <span className="healthdim__val">{view.service.backend === 'up' ? 'answering' : view.service.backend}</span>
          </li>
          <li>
            <Dot tone={streamState.tone} />
            <span>Event stream</span>
            <span className="healthdim__val">{streamState.text}</span>
          </li>
        </ul>
      </section>

      <section className="healthdim" aria-label={HEALTH_COPY.collection}>
        <header className="healthdim__head">
          <h3 className="healthdim__title">{HEALTH_COPY.collection}</h3>
        </header>
        <p className="healthdim__hint">{HEALTH_COPY.collectionHint}</p>
        {view.collectors === null ? (
          <p className="healthdim__unknown">
            <Dot tone="neutral" /> {HEALTH_COPY.collectionNotReported}
          </p>
        ) : (
          <ul className="healthdim__rows healthdim__rows--collectors">
            {view.collectors.map((collector) => {
              const state = collectorTone(collector, now);
              return (
                <li key={collector.sensor_id} className="collector">
                  <div className="collector__line">
                    <Dot tone={state.tone} />
                    <span>{SENSOR_LABEL[collector.sensor_id] ?? collector.sensor_id} collector</span>
                    <span className="healthdim__val">{state.text}</span>
                  </div>
                  <dl className="collector__facts">
                    <div>
                      <dt>last read</dt>
                      <dd>{collector.last_read_at ? relativeFromNow(collector.last_read_at, now) : '—'}</dd>
                    </div>
                    <div>
                      <dt>backlog</dt>
                      <dd>
                        {collector.backlog_records === null ? '—' : number(collector.backlog_records)}
                        {collector.oldest_backlog_age_s ? ` · oldest ${collector.oldest_backlog_age_s}s` : ''}
                      </dd>
                    </div>
                    <div>
                      <dt>errors</dt>
                      <dd>{collector.error_count === null ? '—' : number(collector.error_count)}</dd>
                    </div>
                    {collector.ingest ? (
                      <div className="collector__ingest">
                        <dt>ingest</dt>
                        <dd>
                          {number(collector.ingest.accepted)} accepted · {number(collector.ingest.duplicate)} dup ·{' '}
                          {number(collector.ingest.rejected)} rejected · {number(collector.ingest.quarantined)}{' '}
                          quarantined · {collector.ingest.retry === null ? '—' : number(collector.ingest.retry)} retry
                        </dd>
                      </div>
                    ) : null}
                  </dl>
                  {collector.clock_skew_s !== null && Math.abs(collector.clock_skew_s) >= 5 ? (
                    <p className="collector__skew" title={HEALTH_COPY.skew}>
                      Clock skew {collector.clock_skew_s > 0 ? '+' : ''}
                      {collector.clock_skew_s}s. {HEALTH_COPY.skew}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="healthdim healthdim--activity" aria-label={HEALTH_COPY.activity}>
        <header className="healthdim__head">
          <h3 className="healthdim__title">{HEALTH_COPY.activity}</h3>
        </header>
        <p className="healthdim__hint">{HEALTH_COPY.activityHint}</p>
        <ul className="healthdim__rows">
          {view.activity.map((row) => (
            <li key={row.sensor_id}>
              <span className="activity__mark" aria-hidden="true" />
              <span>{SENSOR_LABEL[row.sensor_id] ?? row.sensor_id}</span>
              <span className="healthdim__val">
                {row.last_event_at ? `last event ${relativeFromNow(row.last_event_at, now)}` : 'no events yet'}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
