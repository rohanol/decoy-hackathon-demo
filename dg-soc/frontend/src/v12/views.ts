/**
 * Pure v1.2 view functions: API data in, display rows out. Type imports only,
 * so they run under `node --test`. Nothing here infers a diversion, an
 * identity or a health state: every row says where its value came from, and a
 * value the backend did not send stays null.
 */

import type { BackendEligibility, Health, SensorId, SocEvent } from '../types/api';
import type {
  ArchiveAttributes,
  CredentialEvidence,
  DbAttributes,
  FileAttributes,
  IngressAttributes,
  RegistryHoneypot,
  RegistryTelemetrySource,
  SourcesRegistry,
  TransferAttributes,
} from './types.ts';

/* ---------- sources and health ---------- */

/**
 * Identities frozen by contract v1.2. Used ONLY when GET /api/sources is not
 * served (backend still on v1.1); the row then says `registry: 'fallback'`
 * and carries no binding or capability claims.
 */
export const KNOWN_HONEYPOTS: readonly SensorId[] = ['ssh-decoy-01', 'web-decoy-01', 'db-decoy-01', 'file-decoy-01'];
export const KNOWN_TELEMETRY_SOURCES = ['gateway-01', 'demo-app-01'] as const;

export interface HoneypotRow {
  source_id: string;
  registry: 'served' | 'fallback';
  entry: RegistryHoneypot | null;
  /** From sensor_health; null = the backend sent no health row for it. */
  health: NonNullable<Health['sensor_health']>[SensorId] | null;
  /** v1.0 last event time, attacker activity only. */
  last_event_at: string | null;
}

export interface TelemetryRow {
  source_id: string;
  registry: 'served' | 'fallback';
  entry: RegistryTelemetrySource | null;
  health: NonNullable<Health['telemetry_health']>[string] | null;
}

export function sourceRows(registry: SourcesRegistry | null, health: Health | null) {
  const honeypotIds = registry ? registry.honeypots.map((item) => item.source_id) : [...KNOWN_HONEYPOTS];
  const telemetryIds = registry ? registry.telemetry_sources.map((item) => item.source_id) : [...KNOWN_TELEMETRY_SOURCES];
  const honeypots: HoneypotRow[] = honeypotIds.map((id) => ({
    source_id: id,
    registry: registry ? 'served' : 'fallback',
    entry: registry?.honeypots.find((item) => item.source_id === id) ?? null,
    health: (health?.sensor_health as Record<string, HoneypotRow['health']> | undefined)?.[id] ?? null,
    last_event_at: health?.sensors?.[id] ?? null,
  }));
  const telemetry: TelemetryRow[] = telemetryIds.map((id) => ({
    source_id: id,
    registry: registry ? 'served' : 'fallback',
    entry: registry?.telemetry_sources.find((item) => item.source_id === id) ?? null,
    health: health?.telemetry_health?.[id] ?? null,
  }));
  return { honeypots, telemetry, honeypot_count: registry?.honeypot_count ?? null };
}

/* ---------- per-event protocol facts ---------- */

function objectAttr<T>(event: SocEvent, key: string): T | null {
  const value = event.attributes?.[key];
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as T) : null;
}

export const credentialOf = (event: SocEvent) => objectAttr<CredentialEvidence>(event, 'credential');
export const dbOf = (event: SocEvent) => objectAttr<DbAttributes>(event, 'db');
export const fileOf = (event: SocEvent) => objectAttr<FileAttributes>(event, 'file');
export const ingressOf = (event: SocEvent) => objectAttr<IngressAttributes>(event, 'ingress');
export const archiveOf = (event: SocEvent) => objectAttr<ArchiveAttributes>(event, 'archive');
export const transferOf = (event: SocEvent) => objectAttr<TransferAttributes>(event, 'transfer');

/** Only an SSH session has an emulated-shell transcript. */
export function hasTranscript(sensorId: string): boolean {
  return sensorId === 'ssh-decoy-01';
}

/* ---------- archive bait: the claims ladder (API.md, Archive bait) ---------- */

export type ClaimState = 'observed' | 'not_observed' | 'never_observable';

export interface ArchiveClaim {
  claim: 'requested' | 'served' | 'client_completed_download' | 'extracted_or_opened' | 'planted_credential_used';
  state: ClaimState;
  event_ids: string[];
  detail: string | null;
}

export interface ArchiveEvidence {
  asset_id: string;
  served_event_id: string;
  entries: ArchiveAttributes['entries'];
  contains_executable: boolean | null;
  auto_run: boolean | null;
  honeytoken_ids: string[];
  issuance_id: string | null;
  transfer: TransferAttributes | null;
  claims: ArchiveClaim[];
}

interface LinkLike {
  link_id: string;
  from_event_id: string;
  to_event_id: string;
  to_sensor: string;
  kind: string;
  basis: string;
  status: string;
  attribution?: string | null;
}

const ARCHIVE_PATH = /\/backup\/backup\.zip$/;

/**
 * One entry per archive served. "Requested" and "served" cite the decoy's own
 * events; client completion and extraction are never observable and are
 * always reported as such; credential use cites the backend's token links,
 * keeping ambiguous attribution visible.
 */
export function archiveEvidence(events: SocEvent[], links: LinkLike[]): ArchiveEvidence[] {
  const servings = events.filter((event) => event.event_type === 'bait_served'
    && (archiveOf(event) !== null || ARCHIVE_PATH.test(String(event.attributes?.asset_id ?? ''))));
  return servings.map((served) => {
    const attrs = served.attributes ?? {};
    const requestId = typeof attrs.request_id === 'string' ? attrs.request_id : null;
    // The serving's own request: same request_id when the decoy reports one;
    // otherwise only the same source, run and mode. Never another client's
    // request for the same path.
    const requests = events.filter((event) => event.event_type === 'http_request'
      && ARCHIVE_PATH.test(String(event.attributes?.path ?? ''))
      && event.sensor_id === served.sensor_id && event.lab_run_id === served.lab_run_id
      && event.capture_mode === served.capture_mode
      && (requestId !== null ? event.attributes?.request_id === requestId : event.src_ip === served.src_ip));
    const archive = archiveOf(served);
    const tokens = Array.isArray(attrs.honeytoken_ids) ? (attrs.honeytoken_ids as string[]) : [];
    const uses = links.filter((link) => link.from_event_id === served.event_id && link.kind === 'strong_candidate');
    return {
      asset_id: String(attrs.asset_id ?? 'web:/backup/backup.zip'),
      served_event_id: served.event_id,
      entries: archive?.entries ?? [],
      contains_executable: archive ? archive.contains_executable : null,
      auto_run: archive ? archive.auto_run : null,
      honeytoken_ids: tokens,
      issuance_id: typeof attrs.issuance_id === 'string' ? attrs.issuance_id : null,
      transfer: transferOf(served),
      claims: [
        { claim: 'requested', state: requests.length ? 'observed' : 'not_observed', event_ids: requests.map((e) => e.event_id),
          detail: requests.length ? null : 'No matching request record in this case.' },
        { claim: 'served', state: 'observed', event_ids: [served.event_id],
          detail: `evidence_basis ${String(attrs.evidence_basis ?? 'not reported')}` },
        { claim: 'client_completed_download', state: 'never_observable', event_ids: [],
          detail: 'The decoy can only see that it finished writing the body; client receipt is not recorded.' },
        { claim: 'extracted_or_opened', state: 'never_observable', event_ids: [],
          detail: 'Nothing on the client side is observed.' },
        { claim: 'planted_credential_used', state: uses.length ? 'observed' : 'not_observed',
          event_ids: uses.map((link) => link.to_event_id),
          detail: uses.length
            ? uses.map((link) => `${link.to_sensor}: ${link.attribution ?? 'attribution not reported'} (${link.status})`).join('; ')
            : 'No later presentation of a credential from this serving.' },
      ],
    };
  });
}

/* ---------- response scope ---------- */

export interface ScopeView {
  enforced_on: string[];
  not_enforced_on: string[];
  /** True when the backend itself stated the scope (v1.2). */
  stated_by_backend: boolean;
  unsupported_sensor: boolean;
}

/**
 * Where the only response (the web block) is enforced. When the backend
 * does not state it (v1.1), the registry-independent fact still holds: the
 * block lives on web-decoy-01 only. Never a universal "blocked".
 */
export function responseScope(eligibility: BackendEligibility | null): ScopeView {
  const scope = eligibility?.response_scope;
  return {
    enforced_on: scope?.enforced_on ?? ['web-decoy-01'],
    not_enforced_on: scope?.not_enforced_on ?? [],
    stated_by_backend: Boolean(scope),
    unsupported_sensor: Boolean(eligibility?.reasons.some((reason) => reason.code === 'response_unsupported_sensor')),
  };
}
