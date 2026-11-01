/**
 * The live event store: REST snapshot plus /ws/events, shared by the shell and
 * the live feed.
 *
 * Rules it enforces (API.md, DESIGN_SPEC.md sections 4.3 and 7.1):
 *  - apply a WebSocket message only when its seq exceeds the highest seq seen
 *  - on every (re)connection, reload the REST snapshot and discard the list
 *    rather than trying to patch the gap
 *  - pausing freezes rendering only; the buffer keeps filling
 *  - the rendered list is capped, and the footer says so
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { ApiError, fetchEvents, fetchHealth } from '../api/client';
import { createEventStream, type ConnectionStatus, type EventStream } from '../api/socket';
import { EVENTS_PAGE_LIMIT, FEED_MAX_ROWS, MAX_SNAPSHOT_PAGES } from '../api/config';
import type { CaptureMode, Health, SocEvent, WsMessage } from '../types/api';
import { FeedReconciler, mergeById } from './reconcile';

interface LiveStoreValue {
  /** Newest first, capped at FEED_MAX_ROWS. */
  events: SocEvent[];
  /** Total events this session has applied, including ones trimmed from the list. */
  receivedCount: number;
  /** Highest seq in the initial snapshot; rows above it arrived live and flash. */
  snapshotMaxSeq: number;
  status: ConnectionStatus;
  paused: boolean;
  bufferedCount: number;
  loading: boolean;
  error: ApiError | null;
  health: Health | null;
  /** When GET /api/health last answered or failed. Service liveness, not activity. */
  healthCheckedAt: string | null;
  /** 'replay' if anything in view came from a replayed capture. */
  captureMode: CaptureMode | null;
  labRunId: string | null;
  /** When data last arrived, for the offline pill and stale banners. */
  lastDataAt: Date | null;
  /**
   * Increments on every RE-connection (not the first). API.md requires the
   * whole snapshot to be reloaded on reconnect, including incidents and links
   * — so screens that hold their own data depend on this to resync.
   */
  connectionEpoch: number;
  setPaused: (paused: boolean) => void;
  retryNow: () => void;
  reload: () => void;
  /**
   * Listen to every /ws/events message, not just events. Screens that own
   * findings, incidents, links or actions subscribe here rather than opening a
   * second socket. Returns an unsubscribe function.
   */
  subscribe: (handler: (message: WsMessage) => void) => () => void;
}

const LiveStoreContext = createContext<LiveStoreValue | null>(null);

export function LiveStoreProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<SocEvent[]>([]);
  const [receivedCount, setReceivedCount] = useState(0);
  const [snapshotMaxSeq, setSnapshotMaxSeq] = useState(0);
  const [status, setStatus] = useState<ConnectionStatus>({ state: 'connecting', attempt: 0 });
  const [paused, setPausedState] = useState(false);
  const [bufferedCount, setBufferedCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [healthCheckedAt, setHealthCheckedAt] = useState<string | null>(null);
  const [lastDataAt, setLastDataAt] = useState<Date | null>(null);
  const [connectionEpoch, setConnectionEpoch] = useState(0);

  /**
   * Snapshot/live reconciliation (./reconcile.ts): the seq gate, dedupe by
   * event_id, and the buffer that keeps live events arriving during a
   * snapshot load from being lost when the snapshot lands.
   */
  const reconcilerRef = useRef<FeedReconciler>(new FeedReconciler(FEED_MAX_ROWS));
  /** What is on screen, readable from callbacks without a stale closure. */
  const eventsRef = useRef<SocEvent[]>([]);
  const pausedRef = useRef(false);
  const bufferRef = useRef<SocEvent[]>([]);
  const streamRef = useRef<EventStream | null>(null);
  /** Guards against a late snapshot response overwriting a newer one. */
  const loadTokenRef = useRef(0);
  /** Screens listening for finding/incident/link/action messages. */
  const subscribersRef = useRef(new Set<(message: WsMessage) => void>());
  /** The first connection is the initial load, not a resync. */
  const hasConnectedRef = useRef(false);

  const subscribe = useCallback((handler: (message: WsMessage) => void) => {
    subscribersRef.current.add(handler);
    return () => {
      subscribersRef.current.delete(handler);
    };
  }, []);

  const showEvents = useCallback((next: SocEvent[]) => {
    eventsRef.current = next;
    setEvents(next);
  }, []);

  const appendEvents = useCallback((incoming: SocEvent[]) => {
    if (incoming.length === 0) return;
    setEvents((current) => {
      // By event_id, never by concatenation: an id can only ever appear once.
      const merged = mergeById([current, incoming], FEED_MAX_ROWS);
      eventsRef.current = merged;
      return merged;
    });
    setReceivedCount((count) => count + incoming.length);
    setLastDataAt(new Date());
  }, []);

  const loadSnapshot = useCallback(async () => {
    const token = ++loadTokenRef.current;
    const reconciler = reconcilerRef.current;
    // From here until this load settles, live events are buffered for the merge.
    reconciler.beginSnapshot();
    let settled = false;
    setLoading(true);
    try {
      // GET /api/events returns events ASCENDING from since_seq, and next_seq is
      // a forward cursor, not the global maximum. A single call therefore
      // returns the OLDEST page — so for a run longer than one page the feed
      // would show the oldest events and the socket would then append new ones
      // on top, leaving a silent hole in the middle. Page forward to the end.
      const collected: SocEvent[] = [];
      let cursor = 0;
      for (let guard = 0; guard < MAX_SNAPSHOT_PAGES; guard += 1) {
        const page = await fetchEvents({ since_seq: cursor, limit: EVENTS_PAGE_LIMIT });
        if (token !== loadTokenRef.current) {
          // A newer load superseded this one; it owns the merge now.
          reconciler.abandonSnapshot();
          settled = true;
          return;
        }
        collected.push(...page.items);
        // Stop at a short page, or if the cursor stops advancing.
        if (page.items.length < EVENTS_PAGE_LIMIT) break;
        if (page.next_seq === undefined || page.next_seq <= cursor) break;
        cursor = page.next_seq;
      }

      // Merge, never replace: the snapshot plus every live event that arrived
      // while it loaded, by event_id (review T14).
      const result = reconciler.completeSnapshot(collected);
      settled = true;
      bufferRef.current = [];
      setBufferedCount(0);
      showEvents(result.events);
      setReceivedCount(result.total);
      // Rows above the snapshot's own maximum arrived live, so they flash.
      setSnapshotMaxSeq(collected.reduce((max, event) => Math.max(max, event.seq), 0));
      setError(null);
      setLastDataAt(new Date());
    } catch (cause) {
      if (!settled) {
        if (token !== loadTokenRef.current) reconciler.abandonSnapshot();
        else showEvents(reconciler.failSnapshot(eventsRef.current));
        settled = true;
      }
      if (token !== loadTokenRef.current) return;
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('unknown_error', 'Failed to load events.', 0),
      );
    } finally {
      if (token === loadTokenRef.current) setLoading(false);
    }
  }, [showEvents]);

  const setPaused = useCallback(
    (next: boolean) => {
      pausedRef.current = next;
      setPausedState(next);
      if (!next && bufferRef.current.length > 0) {
        const flushed = bufferRef.current;
        bufferRef.current = [];
        setBufferedCount(0);
        appendEvents(flushed);
      }
    },
    [appendEvents],
  );

  // Load the snapshot on mount, independent of the socket. Without this, a
  // backend that is down leaves the feed on its skeleton forever, because
  // onConnected never fires and the REST failure is never surfaced.
  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    const stream = createEventStream({
      onStatus: setStatus,
      onConnected: () => {
        if (hasConnectedRef.current) setConnectionEpoch((value) => value + 1);
        else hasConnectedRef.current = true;
        void loadSnapshot();
      },
      onMessage: (message) => {
        // Hand every message to the screens listening for their own type,
        // BEFORE the seq gate below. API.md: a finding, link or incident
        // message often reuses the previous event's seq, and an analyst
        // decision sends messages with no new event at all — so those three
        // types must never be dropped by seq.
        for (const handler of subscribersRef.current) handler(message);

        // The seq gate applies to events only, and lives in the reconciler,
        // which also buffers for an in-flight snapshot and dedupes by id.
        if (message.type !== 'event') return;
        const event = message.data as SocEvent;
        if (reconcilerRef.current.acceptLive(event) === 'duplicate') return;

        if (pausedRef.current) {
          bufferRef.current = mergeById([bufferRef.current, [event]], FEED_MAX_ROWS);
          setBufferedCount(bufferRef.current.length);
          return;
        }
        appendEvents([event]);
      },
    });
    streamRef.current = stream;
    return () => {
      stream.close();
      streamRef.current = null;
    };
  }, [appendEvents, loadSnapshot]);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const next = await fetchHealth();
        if (!cancelled) {
          setHealth(next);
          setHealthCheckedAt(new Date().toISOString());
        }
      } catch {
        if (!cancelled) {
          setHealth(null);
          setHealthCheckedAt(new Date().toISOString());
        }
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), 15_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const captureMode = useMemo<CaptureMode | null>(() => {
    if (events.length === 0) return null;
    return events.some((event) => event.capture_mode === 'replay') ? 'replay' : 'live';
  }, [events]);

  const labRunId = events[0]?.lab_run_id ?? null;

  const value = useMemo<LiveStoreValue>(
    () => ({
      events,
      receivedCount,
      snapshotMaxSeq,
      status,
      paused,
      bufferedCount,
      loading,
      error,
      health,
      healthCheckedAt,
      captureMode,
      labRunId,
      lastDataAt,
      connectionEpoch,
      setPaused,
      retryNow: () => streamRef.current?.retryNow(),
      reload: () => void loadSnapshot(),
      subscribe,
    }),
    [
      events,
      receivedCount,
      snapshotMaxSeq,
      status,
      paused,
      bufferedCount,
      loading,
      error,
      health,
      healthCheckedAt,
      captureMode,
      labRunId,
      lastDataAt,
      connectionEpoch,
      setPaused,
      loadSnapshot,
      subscribe,
    ],
  );

  return <LiveStoreContext.Provider value={value}>{children}</LiveStoreContext.Provider>;
}

export function useLiveStore(): LiveStoreValue {
  const value = useContext(LiveStoreContext);
  if (!value) throw new Error('useLiveStore must be used inside LiveStoreProvider');
  return value;
}
