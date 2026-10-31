/**
 * Raw event view. DESIGN_SPEC.md section 7.4, shown as a centred dialog.
 *
 * Every field of the event, exactly as the API returned it. This is what makes
 * "evidence-linked" a real claim rather than a slogan: any ID on any screen can
 * be opened here and checked. It opens instantly, with no transition: an
 * analyst opening evidence wants it now.
 */

import { X } from 'lucide-react';
import { useEffect, useRef, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { AttackerText, CopyableValue } from './primitives';
import { EVENT_TYPE_DESCRIPTION, EVENT_TYPE_LABEL, SENSOR_LABEL } from '../copy';
import { EVENT_STYLE } from '../lib/eventStyle';
import { bytes, fullUtc, shortHash } from '../lib/format';
import type { SocEvent } from '../types/api';

/** Attacker-controlled attributes get the bounded well treatment. */
const HOSTILE_KEYS = new Set(['command', 'path', 'query_redacted', 'user_agent', 'username']);

/** Hashes are shown truncated with a copy button, never raw in a table. */
const HASH_KEYS = new Set(['password_sha256', 'sha256']);

function AttributeValue({ attrKey, value }: { attrKey: string; value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="kv__v kv__v--muted">null</span>;
  }
  if (HASH_KEYS.has(attrKey) && typeof value === 'string') {
    return (
      <span className="kv__v">
        <CopyableValue value={value} display={shortHash(value)} />
      </span>
    );
  }
  if (HOSTILE_KEYS.has(attrKey) && typeof value === 'string') {
    return (
      <span className="kv__v">
        <AttackerText value={value} well />
      </span>
    );
  }
  if (attrKey === 'size_bytes' && typeof value === 'number') {
    return <span className="kv__v">{bytes(value)}</span>;
  }
  if (typeof value === 'object') {
    return <span className="kv__v">{JSON.stringify(value)}</span>;
  }
  return <span className="kv__v">{String(value)}</span>;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="evfact">
      <span className="evfact__label">{label}</span>
      <span className="evfact__value">{children}</span>
    </div>
  );
}

export function RawEventDrawer({ event, onClose }: { event: SocEvent; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKeyDown = (keyEvent: KeyboardEvent) => {
      if (keyEvent.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const style = EVENT_STYLE[event.event_type];
  const attributes = Object.entries(event.attributes ?? {});

  return (
    <div className="evmodal-backdrop" onMouseDown={onClose}>
      <section
        className="evmodal"
        role="dialog"
        aria-label="Raw event"
        aria-modal="true"
        onMouseDown={(mouseEvent) => mouseEvent.stopPropagation()}
      >
        <header className="evmodal__head">
          <span className={`evmodal__glyph evtype--${style.tone}`}>{style.glyph}</span>
          <div className="evmodal__titles">
            <h2 className="evmodal__title">{EVENT_TYPE_LABEL[event.event_type]}</h2>
            <p className="evmodal__desc">{EVENT_TYPE_DESCRIPTION[event.event_type]}</p>
          </div>
          <button
            ref={closeRef}
            type="button"
            className="iconbtn evmodal__close"
            aria-label="Close"
            title="Close (Esc)"
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </header>

        <div className="evmodal__facts">
          <Fact label="Source">
            <span className="evmodal__ip">{event.src_ip}</span>
          </Fact>
          <Fact label="Sensor">
            {SENSOR_LABEL[event.sensor_id] ?? event.sensor_id}
            <span className="evmodal__sub">{event.sensor_id}</span>
          </Fact>
          <Fact label="Occurred (UTC)">{fullUtc(event.occurred_at)}</Fact>
          <Fact label="Incident">
            {event.incident_id ? (
              <Link to={`/incidents/${event.incident_id}`} onClick={onClose}>
                {event.incident_id}
              </Link>
            ) : (
              <span className="kv__v--muted">none</span>
            )}
          </Fact>
        </div>

        <div className="evmodal__body">
          <section>
            <h3 className="evmodal__section">What was sent</h3>
            {attributes.length === 0 ? (
              <p className="evmodal__note">No attributes on this event.</p>
            ) : (
              <div className="kv">
                {attributes.map(([key, value]) => (
                  <span key={key} style={{ display: 'contents' }}>
                    <span className="kv__k">{key}</span>
                    <AttributeValue attrKey={key} value={value} />
                  </span>
                ))}
              </div>
            )}
          </section>

          <section>
            <h3 className="evmodal__section">Evidence record</h3>
            <div className="kv">
              <span className="kv__k">event_id</span>
              <span className="kv__v">
                <CopyableValue value={event.event_id} />
              </span>
              <span className="kv__k">seq</span>
              <span className="kv__v">{event.seq}</span>
              <span className="kv__k">event_type</span>
              <span className="kv__v">{event.event_type}</span>
              <span className="kv__k">ingested_at</span>
              <span className="kv__v">{fullUtc(event.ingested_at)}</span>
              <span className="kv__k">src_port</span>
              <span className={event.src_port == null ? 'kv__v kv__v--muted' : 'kv__v'}>
                {event.src_port ?? 'null'}
              </span>
              <span className="kv__k">session_id</span>
              <span className={event.session_id == null ? 'kv__v kv__v--muted' : 'kv__v'}>
                {event.session_id ?? 'null'}
              </span>
              <span className="kv__k">lab_run_id</span>
              <span className="kv__v">{event.lab_run_id}</span>
              <span className="kv__k">capture_mode</span>
              <span className="kv__v">{event.capture_mode}</span>
              <span className="kv__k">schema_version</span>
              <span className="kv__v">{event.schema_version}</span>
              <span className="kv__k">source_record_id</span>
              <span className="kv__v">
                <CopyableValue
                  value={event.source_record_id}
                  display={shortHash(event.source_record_id)}
                />
              </span>
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}
