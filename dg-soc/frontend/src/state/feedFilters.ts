/**
 * Live Feed filters (review section 15: run, mode, session, request), pure so
 * the exact predicate the feed uses is unit-tested against producers' records.
 * Only type imports: runs under `node --test`.
 */

import type { SocEvent } from '../types/api';
import { facetOf } from '../evidence/model.ts';

export interface FeedFilters {
  sensor: string;
  type: string;
  /** Substring of src_ip. */
  ip: string;
  /** Exact lab_run_id. */
  run: string;
  /** 'live' | 'replay' | '' for both. */
  mode: string;
  /** Substring of session_id. Web events carry one once M4 emits session cookies. */
  session: string;
  /** Substring of attributes.request_id (or an envelope request_id). */
  request: string;
}

export const NO_FILTERS: FeedFilters = { sensor: '', type: '', ip: '', run: '', mode: '', session: '', request: '' };

export function filtersActive(filters: FeedFilters): boolean {
  return Object.values(filters).some((value) => value.trim() !== '');
}

export function matchesFeedFilters(event: SocEvent, filters: FeedFilters): boolean {
  const ip = filters.ip.trim();
  const session = filters.session.trim();
  const request = filters.request.trim();
  if (filters.sensor && event.sensor_id !== filters.sensor) return false;
  if (filters.type && event.event_type !== filters.type) return false;
  if (ip && !event.src_ip.includes(ip)) return false;
  if (filters.run && event.lab_run_id !== filters.run) return false;
  if (filters.mode && event.capture_mode !== filters.mode) return false;
  if (session && !(event.session_id ?? '').includes(session)) return false;
  if (request && !(facetOf(event).request_id ?? '').includes(request)) return false;
  return true;
}

/** True once any loaded event carries a request id; the request filter is offered from then on. */
export function requestIdsAvailable(events: SocEvent[]): boolean {
  return events.some((event) => facetOf(event).request_id !== null);
}
