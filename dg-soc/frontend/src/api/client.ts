/**
 * REST client. Thin on purpose: it fetches, it validates the error envelope,
 * it returns typed data. It never derives, aggregates or decides anything
 * (DESIGN_SPEC.md law 1).
 */

import { API_BASE, EVENTS_PAGE_LIMIT, MAX_SNAPSHOT_PAGES } from './config';
import { ApiError } from './error';
import type { GatewayRequestDetail, IncidentRouting, SourcesRegistry } from '../v12/types';

/**
 * The mock backend is loaded only in a fixture build. The flag is read from
 * import.meta.env right here so the bundler can see it is false in a normal
 * build and drop the mock and its demo events from the release bundle.
 */
const MOCK = import.meta.env.VITE_USE_FIXTURES === '1';
const fixtures = () => import('./fixtures');
import type {
  ApiErrorBody,
  EventsPage,
  Health,
  BlockPreview,
  Incident,
  IncidentSummary,
  Link,
  ResponseAction,
  StatsOverview,
  Transcript,
  BackendProfile,
  BackendEligibility,
} from '../types/api';

// Defined in ./error so the fixture backend can throw the same type without a
// circular import. Re-exported here because every screen imports it from the
// client alongside the fetchers.
export { ApiError };

function isErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== 'object' || value === null) return false;
  const err = (value as { error?: unknown }).error;
  if (typeof err !== 'object' || err === null) return false;
  return typeof (err as { code?: unknown }).code === 'string';
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        ...init?.headers,
      },
    });
  } catch {
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

function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: 'POST', body: JSON.stringify(body) });
}

export interface EventsQuery {
  incident_id?: string;
  sensor_id?: string;
  since_seq?: number;
  limit?: number;
  lab_run_id?: string;
  capture_mode?: 'live' | 'replay';
}

export function fetchEvents(query: EventsQuery = {}): Promise<EventsPage> {
  if (MOCK) return fixtures().then((mock) => mock.fetchEvents(query));
  const params = new URLSearchParams();
  if (query.incident_id) params.set('incident_id', query.incident_id);
  if (query.sensor_id) params.set('sensor_id', query.sensor_id);
  if (query.lab_run_id) params.set('lab_run_id', query.lab_run_id);
  if (query.capture_mode) params.set('capture_mode', query.capture_mode);
  if (query.since_seq !== undefined) params.set('since_seq', String(query.since_seq));
  params.set('limit', String(query.limit ?? EVENTS_PAGE_LIMIT));
  return get<EventsPage>(`/api/events?${params.toString()}`);
}

/**
 * Every event matching a query, paging forward with since_seq. GET /api/events
 * returns ascending pages and next_seq is a forward cursor, so one call only
 * returns the oldest page. Bounded by MAX_SNAPSHOT_PAGES.
 */
export async function fetchAllEvents(query: Omit<EventsQuery, 'since_seq' | 'limit'> = {}) {
  const collected: EventsPage['items'] = [];
  let cursor = 0;
  for (let guard = 0; guard < MAX_SNAPSHOT_PAGES; guard += 1) {
    const page = await fetchEvents({ ...query, since_seq: cursor, limit: EVENTS_PAGE_LIMIT });
    collected.push(...page.items);
    if (page.items.length < EVENTS_PAGE_LIMIT) break;
    if (page.next_seq === undefined || page.next_seq <= cursor) break;
    cursor = page.next_seq;
  }
  return collected;
}

export function fetchHealth(): Promise<Health> {
  if (MOCK) return fixtures().then((mock) => mock.fetchHealth());
  return get<Health>('/api/health');
}

export function fetchTripRuns(): Promise<{ items: Array<{ lab_run_id: string; capture_mode: string; active: boolean; legacy_mixed: boolean }> }> {
  if (MOCK) return Promise.resolve({ items: [] });
  return get('/api/runs');
}

export function fetchIncidents(): Promise<{ items: IncidentSummary[] }> {
  if (MOCK) return fixtures().then((mock) => mock.fetchIncidents());
  return get<{ items: IncidentSummary[] }>('/api/incidents');
}

export function fetchIncident(incidentId: string): Promise<Incident> {
  if (MOCK) return fixtures().then((mock) => mock.fetchIncident(incidentId));
  return get<Incident>(`/api/incidents/${encodeURIComponent(incidentId)}`);
}

export function fetchProfile(srcIp: string, runId: string): Promise<BackendProfile> {
  return get<BackendProfile>(`/api/profiles/${encodeURIComponent(srcIp)}?lab_run_id=${encodeURIComponent(runId)}`);
}

export function fetchEligibility(incidentId: string): Promise<BackendEligibility> {
  return get<BackendEligibility>(`/api/incidents/${encodeURIComponent(incidentId)}/response-eligibility`);
}

/* ---------- contract v1.2 reads (PR #19). A v1.1 backend answers 404. ---------- */

/** True when the backend does not serve a v1.2 route yet (404/405, or fixture mode). */
export function isNotServed(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 405 || error.code === 'not_served');
}

function v12Get<T>(path: string): Promise<T> {
  // The fixture backend has no v1.2 routes; provisional v1.2 data is shown on
  // the dev Evidence lab instead, labelled as such.
  if (MOCK) return Promise.reject(new ApiError('not_served', `${path} is not in the fixture backend.`, 404));
  return get<T>(path);
}

export function fetchSources(): Promise<SourcesRegistry> {
  return v12Get<SourcesRegistry>('/api/sources');
}

export function fetchIncidentRouting(incidentId: string): Promise<IncidentRouting> {
  return v12Get<IncidentRouting>(`/api/incidents/${encodeURIComponent(incidentId)}/routing`);
}

export function fetchGatewayRequest(gatewayRequestId: string): Promise<GatewayRequestDetail> {
  return v12Get<GatewayRequestDetail>(`/api/gateway/requests/${encodeURIComponent(gatewayRequestId)}`);
}

/**
 * The analyst's decision on a cross-decoy link. Confirm makes R05 count, and
 * R09 too when the link is a strong candidate (AGENTS.md section 4).
 * Reversible: another decision overwrites it.
 */
export function postLinkDecision(
  linkId: string,
  decision: 'confirm' | 'reject',
  rationale: string,
): Promise<Link> {
  if (MOCK) return fixtures().then((mock) => mock.postLinkDecision(linkId, decision, rationale));
  return post<Link>(`/api/links/${encodeURIComponent(linkId)}/decision`, { decision, rationale });
}

/** Download URL for the incident export. No password hashes (API.md). */
export function incidentExportUrl(incidentId: string): string {
  return `${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/export`;
}

export function fetchTranscript(incidentId: string, sessionId: string): Promise<Transcript> {
  if (MOCK) return fixtures().then((mock) => mock.fetchTranscript(sessionId));
  const params = new URLSearchParams({ session_id: sessionId });
  return get<Transcript>(
    `/api/incidents/${encodeURIComponent(incidentId)}/transcript?${params.toString()}`,
  );
}

export function fetchLinks(): Promise<{ items: Link[] }> {
  if (MOCK) return fixtures().then((mock) => mock.fetchLinks());
  return get<{ items: Link[] }>('/api/links');
}

export function fetchOverview(): Promise<StatsOverview> {
  if (MOCK) return fixtures().then((mock) => mock.fetchOverview());
  return get<StatsOverview>('/api/stats/overview');
}

/* ---------- response (M2's router, mounted by the backend at /api/response) ----------
 *
 * Until response/router.py exists the backend answers 503 with
 * {"error":{"code":"response_unavailable", ...}}, which the UI surfaces as-is.
 */

export function fetchActions(): Promise<{ items: ResponseAction[] }> {
  if (MOCK) return fixtures().then((mock) => mock.fetchActions());
  return get<{ items: ResponseAction[] }>('/api/response/actions');
}

/** Preview expires after 60s. Read every value back from the RESPONSE. */
export function postBlockPreview(incidentId: string, ttlSeconds = 120): Promise<BlockPreview> {
  if (MOCK) return fixtures().then((mock) => mock.postBlockPreview(incidentId, ttlSeconds));
  return post<BlockPreview>('/api/response/preview', {
    incident_id: incidentId,
    ttl_seconds: ttlSeconds,
  });
}

export function postBlockApply(previewId: string, reason: string): Promise<ResponseAction> {
  if (MOCK) return fixtures().then((mock) => mock.postBlockApply(previewId, reason));
  return post<ResponseAction>('/api/response/apply', {
    preview_id: previewId,
    reason,
    confirm: true,
  });
}

export function postBlockRevoke(actionId: string): Promise<ResponseAction> {
  if (MOCK) return fixtures().then((mock) => mock.postBlockRevoke(actionId));
  return post<ResponseAction>(`/api/response/${encodeURIComponent(actionId)}/revoke`, {});
}
