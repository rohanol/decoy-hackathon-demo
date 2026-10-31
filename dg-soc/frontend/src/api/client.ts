/**
 * REST client. Thin on purpose: it fetches, it validates the error envelope,
 * it returns typed data. It never derives, aggregates or decides anything
 * (DESIGN_SPEC.md law 1).
 */

import { API_BASE, EVENTS_PAGE_LIMIT, USE_FIXTURES } from './config';
import * as fixtures from './fixtures';
import type {
  ApiErrorBody,
  EventsPage,
  Health,
  Incident,
  IncidentSummary,
  Link,
  StatsOverview,
  Transcript,
} from '../types/api';

/** Carries the backend's error envelope so the UI can show code and message. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

function isErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== 'object' || value === null) return false;
  const err = (value as { error?: unknown }).error;
  if (typeof err !== 'object' || err === null) return false;
  return typeof (err as { code?: unknown }).code === 'string';
}

async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      headers: { Accept: 'application/json' },
    });
  } catch (cause) {
    throw new ApiError(
      'network_unreachable',
      `Cannot reach the backend at ${API_BASE}. Is it running?`,
      0,
    );
  }

  const text = await res.text();
  let body: unknown = null;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      throw new ApiError('invalid_json', `${path} did not return JSON.`, res.status);
    }
  }

  if (!res.ok) {
    if (isErrorBody(body)) {
      throw new ApiError(body.error.code, body.error.message, res.status);
    }
    throw new ApiError('http_error', `${res.status} ${res.statusText} for ${path}`, res.status);
  }

  return body as T;
}

export interface EventsQuery {
  incident_id?: string;
  sensor_id?: string;
  since_seq?: number;
  limit?: number;
}

export function fetchEvents(query: EventsQuery = {}): Promise<EventsPage> {
  if (USE_FIXTURES) return fixtures.fetchEvents(query);
  const params = new URLSearchParams();
  if (query.incident_id) params.set('incident_id', query.incident_id);
  if (query.sensor_id) params.set('sensor_id', query.sensor_id);
  if (query.since_seq !== undefined) params.set('since_seq', String(query.since_seq));
  params.set('limit', String(query.limit ?? EVENTS_PAGE_LIMIT));
  return get<EventsPage>(`/api/events?${params.toString()}`);
}

export function fetchHealth(): Promise<Health> {
  if (USE_FIXTURES) return fixtures.fetchHealth();
  return get<Health>('/api/health');
}

export function fetchIncidents(): Promise<{ items: IncidentSummary[] }> {
  if (USE_FIXTURES) return fixtures.fetchIncidents();
  return get<{ items: IncidentSummary[] }>('/api/incidents');
}

export function fetchIncident(incidentId: string): Promise<Incident> {
  return get<Incident>(`/api/incidents/${encodeURIComponent(incidentId)}`);
}

export function fetchTranscript(incidentId: string, sessionId: string): Promise<Transcript> {
  const params = new URLSearchParams({ session_id: sessionId });
  return get<Transcript>(
    `/api/incidents/${encodeURIComponent(incidentId)}/transcript?${params.toString()}`,
  );
}

export function fetchLinks(): Promise<{ items: Link[] }> {
  return get<{ items: Link[] }>('/api/links');
}

export function fetchOverview(): Promise<StatsOverview> {
  return get<StatsOverview>('/api/stats/overview');
}
