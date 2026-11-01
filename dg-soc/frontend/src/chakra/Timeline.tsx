/**
 * The fourth dimension: a cursor over the incident's own event times. Moving
 * it rebuilds the wheel from the events that had occurred by then, so the
 * scene replays how deep the source went and in what order. "Live" is the
 * cursor parked at the end, following new events as they arrive.
 */

import { Pause, Play, Radio, RotateCcw } from 'lucide-react';
import { useEffect, useMemo, useRef } from 'react';
import { eventTypeLabel } from '../copy';
import { styleOf } from '../lib/eventStyle';
import { timeUtc } from '../lib/format';
import type { SocEvent } from '../types/api';

/** A whole replay takes about this long, whatever the incident's real span. */
const REPLAY_MS = 14_000;

export function useTimeline(events: SocEvent[]) {
  return useMemo(() => {
    const times = events.map((event) => Date.parse(event.occurred_at)).filter(Number.isFinite);
    const start = times.length > 0 ? Math.min(...times) : 0;
    const end = times.length > 0 ? Math.max(...times) : 0;
    return { start, end, span: Math.max(0, end - start) };
  }, [events]);
}

export function Timeline({
  events,
  cursor,
  playing,
  onCursor,
  onPlaying,
}: {
  events: SocEvent[];
  /** null = live. */
  cursor: number | null;
  playing: boolean;
  onCursor: (cursor: number | null) => void;
  onPlaying: (playing: boolean) => void;
}) {
  const { start, end, span } = useTimeline(events);
  const cursorRef = useRef(cursor);
  cursorRef.current = cursor;

  // Playback: advance the cursor on animation frames, then return to live.
  useEffect(() => {
    if (!playing || span === 0) return;
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const from = cursorRef.current ?? start;
      const next = from + ((now - last) / REPLAY_MS) * span;
      last = now;
      if (next >= end) {
        onCursor(null);
        onPlaying(false);
        return;
      }
      onCursor(next);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, span, start, end, onCursor, onPlaying]);

  const ticks = useMemo(
    () =>
      events.map((event) => ({
        id: event.event_id,
        at: span === 0 ? 1 : (Date.parse(event.occurred_at) - start) / span,
        tone: styleOf(event.event_type).tone,
        label: `${timeUtc(event.occurred_at)} · ${eventTypeLabel(event.event_type)}`,
      })),
    [events, span, start],
  );

  if (events.length === 0 || span === 0) return null;

  const live = cursor === null;
  const fraction = live ? 1 : (cursor - start) / span;
  const reachedCount = live
    ? events.length
    : events.filter((event) => Date.parse(event.occurred_at) <= cursor).length;

  return (
    <div className="timeline">
      <button
        type="button"
        className="timeline__play"
        aria-label={playing ? 'Pause replay' : 'Replay from the first event'}
        title={playing ? 'Pause' : 'Replay how this source moved in'}
        onClick={() => {
          if (playing) {
            onPlaying(false);
            return;
          }
          if (live) onCursor(start);
          onPlaying(true);
        }}
      >
        {playing ? <Pause size={16} /> : live ? <RotateCcw size={16} /> : <Play size={16} />}
      </button>

      <div className="timeline__track">
        <div className="timeline__ticks" aria-hidden="true">
          {ticks.map((tick) => (
            <span
              key={tick.id}
              className={`timeline__tick timeline__tick--${tick.tone}${
                tick.at <= fraction + 1e-9 ? ' timeline__tick--past' : ''
              }`}
              style={{ left: `${tick.at * 100}%` }}
              title={tick.label}
            />
          ))}
        </div>
        <div className="timeline__fill" style={{ width: `${fraction * 100}%` }} />
        <input
          className="timeline__range"
          type="range"
          min={0}
          max={1000}
          step={1}
          value={Math.round(fraction * 1000)}
          aria-label="Replay time"
          onChange={(changeEvent) => {
            onPlaying(false);
            const value = Number(changeEvent.target.value) / 1000;
            onCursor(value >= 1 ? null : start + value * span);
          }}
        />
      </div>

      <div className="timeline__readout">
        <span className={live ? 'timeline__mode timeline__mode--live' : 'timeline__mode'}>
          {live ? 'Live' : 'Replay'}
        </span>
        <span className="timeline__time">{timeUtc(new Date(live ? end : cursor).toISOString())} UTC</span>
        <span className="timeline__count">
          {reachedCount} of {events.length} events
        </span>
      </div>

      {!live ? (
        <button
          type="button"
          className="btn timeline__live"
          onClick={() => {
            onPlaying(false);
            onCursor(null);
          }}
        >
          <Radio size={14} /> Back to live
        </button>
      ) : null}
    </div>
  );
}
