import type { Finding, Health, SocEvent } from '../types/api';

export const TRIP_WAIT_MS = 90_000;
export const TRIP_VALID_MS = 300_000;
export interface Trip {
  nonce: string;
  runId: string;
  minSeq: number;
  startedAt: number;
}

export function tripCommand(nonce: string): string {
  if (!/^trip_[a-f0-9]{32}$/.test(nonce)) throw new Error('Invalid trip reference');
  return [
    "curl --noproxy '*' --connect-timeout 3 --max-time 5 --get",
    `--data-urlencode "q=1' OR 1=1--"`,
    `--data-urlencode 'dg_trip=${nonce}'`,
    "-sS -o /dev/null -w 'Trip HTTP status: %{http_code}\\n'",
    'http://192.168.77.20:8080/search',
  ].join(' ');
}

export function matchesTrip(event: SocEvent, trip: Trip): boolean {
  const at = Date.parse(event.occurred_at);
  const received = Date.parse(event.ingested_at);
  const a = event.attributes;
  return event.sensor_id === 'web-decoy-01' && event.event_type === 'http_request'
    && event.capture_mode === 'live' && event.lab_run_id === trip.runId
    && event.src_ip === '192.168.77.10' && event.seq > trip.minSeq
    && at >= trip.startedAt - 10_000 && at <= trip.startedAt + TRIP_WAIT_MS
    && received >= trip.startedAt - 2_000 && received <= trip.startedAt + TRIP_WAIT_MS
    && a?.method === 'GET' && a.path === '/search' && a.status_code === 500
    && new URLSearchParams(a.query_redacted ?? '').getAll('dg_trip').length === 1
    && new URLSearchParams(a.query_redacted ?? '').get('dg_trip') === trip.nonce;
}

export function tripVerdict(trip: Trip, event: SocEvent | null, findings: Finding[], health: Health | null,
                            checkedAt: number, observedAt: number, completedAt: number | null = null) {
  const request = Boolean(event && matchesTrip(event, trip));
  const finding = request ? findings.find(f => f.rule_id === 'R07'
    && f.incident_id === event?.incident_id && f.evidence_event_ids.includes(event?.event_id ?? '')
    && f.web_attack_class?.includes('sqli')) : undefined;
  const row = health?.sensor_health?.['web-decoy-01'];
  const heartbeat = Date.parse(row?.heartbeat_at ?? '');
  const read = Date.parse(row?.last_read_at ?? '');
  const ingest = Date.parse(row?.last_ingest_at ?? '');
  const at = completedAt ?? observedAt;
  const fresh = (stamp: number, allowance: number) => Number.isFinite(stamp) && at - stamp >= -5000 && at - stamp <= allowance;
  const collector = Boolean(health?.ok && row?.collection === 'ok' && row.process_state === 'running'
    && fresh(checkedAt, 15_000) && fresh(heartbeat, 30_000) && fresh(read, 30_000)
    && Number.isFinite(ingest) && ingest >= trip.startedAt - 2000 && row.backlog_records === 0);
  const passed = request && Boolean(finding) && collector;
  const status = completedAt && observedAt - completedAt > TRIP_VALID_MS ? 'expired'
    : passed ? 'passed' : observedAt - trip.startedAt > TRIP_WAIT_MS ? 'incomplete' : 'waiting';
  return { status, request, finding, collector };
}
