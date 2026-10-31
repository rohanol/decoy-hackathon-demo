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
import { EVENTS_PAGE_LIMIT, FEED_MAX_ROWS } from '../api/config';
import type { CaptureMode, Health, SocEvent, WsMessage } from '../types/api';

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
  const [lastDataAt, setLastDataAt] = useState<Date | null>(null);
  const [connectionEpoch, setConnectionEpoch] = useState(0);

  /** Highest seq applied. The gate for every incoming message. */
  const lastSeqRef = useRef(0);
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

  const appendEvents = useCallback((incoming: SocEvent[]) => {
    if (incoming.length === 0) return;
    setEvents((current) => {
      const merged = [...incoming, ...current];
      merged.sort((a, b) => b.seq - a.seq);
      return merged.slice(0, FEED_MAX_ROWS);
    });
    setReceivedCount((count) => count + incoming.length);
    setLastDataAt(new Date());
  }, []);

  const loadSnapshot = useCallback(async () => {
    const token = ++loadTokenRef.current;
    setLoading(true);
    try {
      const page = await fetchEvents({ limit: EVENTS_PAGE_LIMIT });
      if (token !== loadTokenRef.current) return;

      const ordered = [...page.items].sort((a, b) => b.seq - a.seq);
      // API.md: next_seq IS your last event seq. Use it rather than deriving a
      // max from the page, which would be wrong if the page were truncated.
      const maxSeq = page.next_seq ?? ordered.reduce((max, event) => Math.max(max, event.seq), 0);

      // Reconnect discards the list rather than patching the gap (API.md).
      lastSeqRef.current = maxSeq;
      bufferRef.current = [];
      setBufferedCount(0);
      setEvents(ordered.slice(0, FEED_MAX_ROWS));
      setReceivedCount(ordered.length);
      setSnapshotMaxSeq(maxSeq);
      setError(null);
      setLastDataAt(new Date());
    } catch (cause) {
      if (token !== loadTokenRef.current) return;
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('unknown_error', 'Failed to load events.', 0),
      );
    } finally {
      if (token === loadTokenRef.current) setLoading(false);
    }
  }, []);

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

        // The seq gate applies to events only.
        if (message.type !== 'event') return;
        if (message.seq <= lastSeqRef.current) return;
        lastSeqRef.current = message.seq;

        const event = message.data as SocEvent;
        if (pausedRef.current) {
          bufferRef.current = [event, ...bufferRef.current].slice(0, FEED_MAX_ROWS);
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
        if (!cancelled) setHealth(next);
      } catch {
        if (!cancelled) setHealth(null);
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
