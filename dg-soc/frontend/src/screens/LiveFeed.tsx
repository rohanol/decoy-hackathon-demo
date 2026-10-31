/**
 * Screen 2 — Live Feed. DESIGN_SPEC.md section 7.
 *
 * This is the H4 gate: a real SSH event from Kali, visible here, with its event
 * ID (AGENTS.md section 5, M1_frontend.md task 1).
 *
 * Arrivals are meant to be noticed without taking the screen away from the
 * analyst: the newest event takes the spotlight at the top, a new row glows in
 * and fades over a few seconds, and if you have scrolled down a pill counts
 * what arrived above you instead of moving the rows under your cursor.
 */

import { ArrowUp, Pause, Play } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { EmptyState, ErrorCard, SkeletonRows, AttackerText } from '../components/primitives';
import { RawEventDrawer } from '../components/RawEventDrawer';
import { EventFacets, ModeBadge } from '../components/evidence/bits';
import {
  filtersActive as anyFilterActive,
  matchesFeedFilters,
  requestIdsAvailable,
  type FeedFilters,
} from '../state/feedFilters';
import { COPY, SENSOR_LABEL, eventTypeDescription, eventTypeLabel } from '../copy';
import { FEED_MAX_ROWS } from '../api/config';
import { styleOf } from '../lib/eventStyle';
import { bytes, clamp, number, relativeFromNow, timeUtc } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { EVENT_TYPES, SENSOR_IDS, type EventType, type SocEvent } from '../types/api';

const DETAIL_MAX = 60;

/** One or two lines derived from attributes. DESIGN_SPEC.md section 7.3. */
function DetailCell({ event, max = DETAIL_MAX }: { event: SocEvent; max?: number }) {
  const attributes = event.attributes ?? {};

  switch (event.event_type) {
    case 'auth_failure':
    case 'auth_success':
      return attributes.username ? (
        <AttackerText value={`username=${clamp(attributes.username, max)}`} />
      ) : null;

    case 'command_input':
      return attributes.command ? <AttackerText value={clamp(attributes.command, max)} /> : null;

    case 'http_request':
    case 'blocked_request': {
      const line = `${attributes.method ?? ''} ${attributes.path ?? ''}`.trim();
      return (
        <>
          {line ? <AttackerText value={clamp(line, max)} /> : null}
          {attributes.query_redacted ? (
            <AttackerText value={clamp(attributes.query_redacted, max)} />
          ) : null}
          {event.event_type === 'blocked_request' && attributes.block_action_id ? (
            <span className="mono">{attributes.block_action_id}</span>
          ) : null}
        </>
      );
    }

    case 'synthetic_file_access':
      return (
        <>
          {attributes.asset_id ? <AttackerText value={clamp(attributes.asset_id, max)} /> : null}
          {typeof attributes.size_bytes === 'number' ? (
            <span className="mono">{bytes(attributes.size_bytes)}</span>
          ) : null}
        </>
      );

    case 'connection_open':
      return attributes.client_version ? (
        <AttackerText value={clamp(attributes.client_version, max)} />
      ) : null;

    default:
      return null;
  }
}

/** Status / outcome line under the event type. */
function eventSubLabel(event: SocEvent): string | null {
  const attributes = event.attributes ?? {};
  const parts: string[] = [];
  if (typeof attributes.status_code === 'number') parts.push(String(attributes.status_code));
  if (attributes.response_class) parts.push(attributes.response_class);
  if (attributes.outcome) parts.push(attributes.outcome);
  return parts.length > 0 ? parts.join(' ') : null;
}

/** The newest event, large, at the top. Swaps in with a short slide. */
function Spotlight({ event, onOpen }: { event: SocEvent; onOpen: () => void }) {
  const style = styleOf(event.event_type);
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="spotlight-wrap">
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.button
          key={event.event_id}
          type="button"
          className={`spotlight spotlight--${style.tone}`}
          onClick={onOpen}
          initial={{ opacity: 0, y: -18, scale: 0.985 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 14 }}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
        >
          <span className="spotlight__sweep" aria-hidden="true" />
          <span className="spotlight__kicker">
            <span className="livedot" aria-hidden="true" /> Latest event ·{' '}
            {relativeFromNow(event.occurred_at, now)}
          </span>
          <span className="spotlight__row">
            <span className={`spotlight__glyph evtype--${style.tone}`}>{style.glyph}</span>
            <span className="spotlight__type">{eventTypeLabel(event.event_type)}</span>
            <span className="spotlight__ip">{event.src_ip}</span>
            <span className="spotlight__sensor">{SENSOR_LABEL[event.sensor_id] ?? event.sensor_id}</span>
          </span>
          <span className="spotlight__detail">
            <DetailCell event={event} max={120} />
          </span>
          <span className="spotlight__desc">{eventTypeDescription(event.event_type)}</span>
          <span className="spotlight__id">{event.event_id}</span>
        </motion.button>
      </AnimatePresence>
    </div>
  );
}

function EventRow({
  event,
  isLive,
  isSelected,
  onSelect,
}: {
  event: SocEvent;
  isLive: boolean;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const style = styleOf(event.event_type);
  const sub = eventSubLabel(event);

  const classes = [`row--${style.tone}`, isLive ? 'row--new' : '', isSelected ? 'is-selected' : '']
    .filter(Boolean)
    .join(' ');

  return (
    <tr
      className={classes}
      data-event-id={event.event_id}
      onClick={onSelect}
      tabIndex={0}
      onKeyDown={(keyEvent) => {
        if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
          keyEvent.preventDefault();
          onSelect();
        }
      }}
    >
      <td className="cell-time">
        {timeUtc(event.occurred_at)}
        {isLive ? <span className="newtag">new</span> : null}
      </td>
      <td className="cell-sensor">{event.sensor_id}</td>
      <td>
        <div className={`evtype evtype--${style.tone}`}>
          <span className="evtype__glyph">{style.glyph}</span>
          <span className="evtype__label">{eventTypeLabel(event.event_type)}</span>
        </div>
        {sub ? <div className="evtype__sub">{sub}</div> : null}
      </td>
      <td className="mono cell-ip">{event.src_ip}</td>
      <td>
        <div className="cell-detail">
          <DetailCell event={event} />
          {event.capture_mode === 'replay' ? <ModeBadge mode="replay" /> : null}
          <EventFacets event={event} />
          <div className="cell-detail__ids">
            <span>{event.event_id}</span>
            {event.incident_id ? (
              <Link
                to={`/incidents/${event.incident_id}`}
                onClick={(clickEvent) => clickEvent.stopPropagation()}
              >
                {event.incident_id}
              </Link>
            ) : null}
          </div>
        </div>
      </td>
    </tr>
  );
}

/**
 * Counts events that arrive while the feed is scrolled away from the top, so
 * new rows never push the one you are reading out from under you unnoticed.
 */
function useArrivedAbove(newestSeq: number) {
  const [arrived, setArrived] = useState(0);
  const scrolledRef = useRef(false);
  const lastSeqRef = useRef(newestSeq);

  useEffect(() => {
    const main = document.querySelector('.main');
    if (!main) return;
    const onScroll = () => {
      scrolledRef.current = main.scrollTop > 240;
      if (!scrolledRef.current) setArrived(0);
    };
    main.addEventListener('scroll', onScroll, { passive: true });
    return () => main.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    if (newestSeq > lastSeqRef.current && scrolledRef.current) {
      setArrived((count) => count + 1);
    }
    lastSeqRef.current = newestSeq;
  }, [newestSeq]);

  const jumpToTop = () => {
    document.querySelector('.main')?.scrollTo({ top: 0, behavior: 'smooth' });
    setArrived(0);
  };

  return { arrived, jumpToTop };
}

export function LiveFeed() {
  const {
    events,
    receivedCount,
    snapshotMaxSeq,
    paused,
    bufferedCount,
    loading,
    error,
    setPaused,
    reload,
  } = useLiveStore();

  // The attack graph's sensor nodes deep-link here with ?sensor=<id>.
  const [searchParams, setSearchParams] = useSearchParams();
  const [sensorFilter, setSensorFilter] = useState<string>(
    () => searchParams.get('sensor') ?? '',
  );
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [ipFilter, setIpFilter] = useState<string>('');
  // Review section 15: filters by run, mode, session and request. Deep-linkable,
  // so a session case can open the feed already narrowed to itself.
  const [runFilter, setRunFilter] = useState<string>(() => searchParams.get('run') ?? '');
  const [modeFilter, setModeFilter] = useState<string>(() => searchParams.get('mode') ?? '');
  const [sessionFilter, setSessionFilter] = useState<string>(() => searchParams.get('session') ?? '');
  const [requestFilter, setRequestFilter] = useState<string>(() => searchParams.get('request') ?? '');
  const [selected, setSelected] = useState<SocEvent | null>(null);

  /** Runs present in the loaded window, newest first. Offered, never assumed. */
  const runs = useMemo(() => [...new Set(events.map((event) => event.lab_run_id))], [events]);
  /** request_id: the filter is offered once events carry it (M4 web records, v1.1). */
  const requestAvailable = useMemo(() => requestIdsAvailable(events), [events]);
  const filters = useMemo<FeedFilters>(
    () => ({
      sensor: sensorFilter,
      type: typeFilter,
      ip: ipFilter,
      run: runFilter,
      mode: modeFilter,
      session: sessionFilter,
      request: requestFilter,
    }),
    [sensorFilter, typeFilter, ipFilter, runFilter, modeFilter, sessionFilter, requestFilter],
  );
  const filtered = useMemo(() => events.filter((event) => matchesFeedFilters(event, filters)), [events, filters]);
  const filtersActive = anyFilterActive(filters);
  const trimmed = receivedCount > FEED_MAX_ROWS;
  const newest = events[0] ?? null;
  const { arrived, jumpToTop } = useArrivedAbove(newest?.seq ?? 0);

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Live Feed</h1>
        {paused ? (
          <span className="pill pill--warn">paused · {bufferedCount} waiting</span>
        ) : (
          <span className="feedstate">
            <span className="livedot" aria-hidden="true" /> streaming
          </span>
        )}
        <span className="page__head-spacer" />
        <span className="feedstate">{number(receivedCount)} received this session</span>
        <button type="button" className="btn" onClick={() => setPaused(!paused)}>
          {paused ? <Play size={15} /> : <Pause size={15} />}
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {newest ? <Spotlight event={newest} onOpen={() => setSelected(newest)} /> : null}

      <div className="toolbar">
        <select
          className="select"
          aria-label="Filter by sensor"
          value={sensorFilter}
          onChange={(changeEvent) => {
            setSensorFilter(changeEvent.target.value);
            setSearchParams({}, { replace: true });
          }}
        >
          <option value="">All sensors</option>
          {SENSOR_IDS.map((sensorId) => (
            <option key={sensorId} value={sensorId}>
              {sensorId}
            </option>
          ))}
        </select>

        <select
          className="select"
          aria-label="Filter by event type"
          value={typeFilter}
          onChange={(changeEvent) => setTypeFilter(changeEvent.target.value)}
        >
          <option value="">All event types</option>
          {EVENT_TYPES.map((eventType: EventType) => (
            <option key={eventType} value={eventType}>
              {eventTypeLabel(eventType)}
            </option>
          ))}
        </select>

        <input
          className="input"
          aria-label="Filter by source IP"
          placeholder="Source IP"
          value={ipFilter}
          onChange={(changeEvent) => setIpFilter(changeEvent.target.value)}
        />

        <select
          className="select"
          aria-label="Filter by lab run"
          value={runFilter}
          onChange={(changeEvent) => setRunFilter(changeEvent.target.value)}
        >
          <option value="">All runs</option>
          {runs.map((run) => (
            <option key={run} value={run}>
              {run}
            </option>
          ))}
        </select>

        <select
          className="select"
          aria-label="Filter by capture mode"
          value={modeFilter}
          onChange={(changeEvent) => setModeFilter(changeEvent.target.value)}
        >
          <option value="">Live and replay</option>
          <option value="live">Live only</option>
          <option value="replay">Replay only</option>
        </select>

        <input
          className="input"
          aria-label="Filter by session id"
          placeholder="Session id"
          value={sessionFilter}
          onChange={(changeEvent) => setSessionFilter(changeEvent.target.value)}
        />

        <input
          className="input"
          aria-label="Filter by request id"
          placeholder={requestAvailable ? 'Request id' : 'Request id · not in v1.0'}
          title={
            requestAvailable
              ? undefined
              : 'request_id is a proposed field. Contract v1.0 events do not carry it yet.'
          }
          disabled={!requestAvailable && requestFilter === ''}
          value={requestFilter}
          onChange={(changeEvent) => setRequestFilter(changeEvent.target.value)}
        />

        <span className="toolbar__spacer" />
        <span className="toolbar__count">
          {number(filtered.length)}
          {filtersActive ? ` of ${number(events.length)}` : ''} events
        </span>
      </div>

      {/* Never let a filtered view be mistaken for the whole truth. */}
      {filtersActive ? (
        <div className="filternote">
          Filtered view — {number(events.length - filtered.length)} loaded events hidden.{' '}
          <button
            type="button"
            className="btn btn--ghost"
            onClick={() => {
              setSensorFilter('');
              setTypeFilter('');
              setIpFilter('');
              setRunFilter('');
              setModeFilter('');
              setSessionFilter('');
              setRequestFilter('');
              setSearchParams({}, { replace: true });
            }}
          >
            Clear filters
          </button>
        </div>
      ) : null}

      <section className="card feedcard">
        {error ? (
          <div style={{ padding: 'var(--s4)' }}>
            <ErrorCard error={error} onRetry={reload} />
          </div>
        ) : loading && events.length === 0 ? (
          <SkeletonRows rows={8} />
        ) : filtered.length === 0 ? (
          <EmptyState
            title={filtersActive ? 'No events match these filters.' : COPY.emptyFeedTitle}
            hint={
              filtersActive
                ? 'Clear the filters to see everything that has arrived.'
                : COPY.emptyFeedHint
            }
          />
        ) : (
          <>
            <table className="feed">
              <thead>
                <tr>
                  <th className="feed__col-time" scope="col">
                    Time UTC
                  </th>
                  <th className="feed__col-sensor" scope="col">
                    Sensor
                  </th>
                  <th className="feed__col-event" scope="col">
                    Event
                  </th>
                  <th className="feed__col-source" scope="col">
                    Source
                  </th>
                  <th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <EventRow
                    key={event.event_id}
                    event={event}
                    isLive={event.seq > snapshotMaxSeq}
                    isSelected={selected?.event_id === event.event_id}
                    onSelect={() => setSelected(event)}
                  />
                ))}
              </tbody>
            </table>
            {trimmed ? (
              <div className="feed__footer">
                showing newest {number(events.length)} of {number(receivedCount)} received
              </div>
            ) : null}
          </>
        )}
      </section>

      <AnimatePresence>
        {arrived > 0 ? (
          <motion.button
            type="button"
            className="newpill"
            onClick={jumpToTop}
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
          >
            <ArrowUp size={15} /> {arrived} new event{arrived === 1 ? '' : 's'}
          </motion.button>
        ) : null}
      </AnimatePresence>

      {selected ? (
        <RawEventDrawer event={selected} onClose={() => setSelected(null)} />
      ) : null}
    </div>
  );
}
