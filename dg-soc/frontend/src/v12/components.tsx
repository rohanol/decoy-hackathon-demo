/**
 * Contract v1.2 views. Each one reads what the backend reported and shows
 * "not served" or "not reported" instead of filling a gap. No view infers a
 * diversion, an identity or a health state from a shared IP or timing.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { ApiError, fetchGatewayRequest, fetchIncidentRouting, isNotServed } from '../api/client';
import { EvidenceId } from '../components/evidence/bits';
import { AttackerText, Dot } from '../components/primitives';
import {
  ARCHIVE_CLAIM_LABEL,
  ARCHIVE_COPY,
  CORRELATION_LABEL,
  DB_COPY,
  FILE_COPY,
  INGRESS_LABEL,
  PROOF_CHECK_LABEL,
  PROOF_CHECK_MEANING,
  ROUTING_COPY,
  ROUTING_REASON_LABEL,
  SCOPE_COPY,
  SENSOR_LABEL,
} from '../copy';
import { relativeFromNow, timeUtcZ } from '../lib/format';
import type { SocEvent } from '../types/api';
import type { GatewayRequestDetail, IncidentRouting } from './types';
import {
  credentialOf,
  dbOf,
  fileOf,
  ingressOf,
  type ArchiveEvidence,
  type HoneypotRow,
  type ScopeView,
  type TelemetryRow,
} from './views';

const label = (id: string) => SENSOR_LABEL[id] ?? id;
const reasonLabel = (reason: string) => ROUTING_REASON_LABEL[reason] ?? reason.replace(/_/g, ' ');

/* ---------- per-event protocol facts (feed rows, drawers) ---------- */

export function ProtocolFacts({ event }: { event: SocEvent }) {
  const credential = credentialOf(event);
  const db = dbOf(event);
  const file = fileOf(event);
  const ingress = ingressOf(event);
  if (!credential && !db && !file && !ingress) return null;
  return (
    <span className="v12facts">
      {credential ? (
        <span className={`v12fact v12fact--proof-${credential.proof_check}`} title={PROOF_CHECK_MEANING}>
          {credential.scheme} · {PROOF_CHECK_LABEL[credential.proof_check] ?? credential.proof_check}
        </span>
      ) : null}
      {db ? (
        <span className="v12fact" title={DB_COPY.noStatementText}>
          {db.command}
          {db.statement_verb ? ` · ${db.statement_verb}` : ''}
          {typeof db.length_bytes === 'number' ? ` · ${db.length_bytes} B` : ''} · {DB_COPY.notExecuted}
          {db.error_code ? ` · error ${db.error_code}` : ''}
        </span>
      ) : null}
      {file ? (
        <span className="v12fact">
          {file.operation}
          {file.share ? (
            <>
              {' '}
              <AttackerText value={`\\\\${file.share}${file.path ?? ''}`} />
            </>
          ) : null}
          {typeof file.bytes === 'number' && file.bytes > 0 ? ` · ${file.bytes} B` : ''}
          {file.storage === 'quarantined_inert' ? ` · ${FILE_COPY.inert}` : file.storage === 'discarded' ? ` · ${FILE_COPY.discarded}` : ''}
          {file.magic_type_hint ? (
            <span title={FILE_COPY.hintNotVerdict}> · hint {file.magic_type_hint} (not a verdict)</span>
          ) : null}
        </span>
      ) : null}
      {ingress ? (
        <span className={`v12fact v12fact--ingress-${ingress.gateway_context}`}>
          {INGRESS_LABEL[ingress.gateway_context] ?? ingress.gateway_context}
          {ingress.gateway_request_id ? <span className="mono"> · {ingress.gateway_request_id}</span> : null}
          {ingress.invalid_reason ? ` · ${ingress.invalid_reason}` : ''}
        </span>
      ) : null}
    </span>
  );
}

/* ---------- sources and telemetry health (Sensors page) ---------- */

type Tone = 'ok' | 'warn' | 'danger' | 'neutral';
const COLLECTION_TONE: Record<string, Tone> = { ok: 'ok', stale: 'warn', never: 'neutral' };

function HealthLine({ collection, service, heartbeat, now }: { collection?: string; service?: string; heartbeat?: string | null; now: Date }) {
  if (!collection) {
    return (
      <span className="v12health">
        <Dot tone="neutral" /> health not reported by this backend
      </span>
    );
  }
  return (
    <span className="v12health">
      <Dot tone={COLLECTION_TONE[collection] ?? 'neutral'} /> collection {collection} · service {service ?? 'not reported'}
      {heartbeat ? ` · heartbeat ${relativeFromNow(heartbeat, now)}` : ' · no heartbeat'}
    </span>
  );
}

export function SourcesPanel({
  honeypots,
  telemetry,
  honeypotCount,
  registryServed,
  now,
}: {
  honeypots: HoneypotRow[];
  telemetry: TelemetryRow[];
  honeypotCount: number | null;
  registryServed: boolean;
  now: Date;
}) {
  return (
    <div className="v12sources">
      {!registryServed ? (
        <p className="v12note">
          <strong>Source registry not served.</strong> This backend does not answer <span className="mono">GET /api/sources</span>{' '}
          (contract v1.2, PR #19), so these rows list the frozen v1.2 identities with no binding or capability claims.
        </p>
      ) : null}
      <section aria-label="Honeypots">
        <h3 className="v12sources__title">
          Honeypots{honeypotCount !== null ? ` · ${honeypotCount}` : ''}
        </h3>
        <ul className="v12sources__list">
          {honeypots.map((row) => (
            <li key={row.source_id} className="v12source" data-source-id={row.source_id}>
              <div className="v12source__head">
                <strong>{row.entry?.label ?? label(row.source_id)}</strong>
                <span className="mono v12source__id">{row.source_id}</span>
                {row.entry ? (
                  <span className={`v12tag v12tag--${row.entry.binding.status}`}>
                    {row.entry.protocol} · {row.entry.binding.host}:{row.entry.binding.port ?? '—'} · {row.entry.binding.status}
                  </span>
                ) : null}
                {row.entry ? (
                  <span className="v12tag">
                    response {row.entry.response.block === 'supported' ? `supported (${row.entry.response.scope ?? 'scoped'})` : row.entry.response.block}
                  </span>
                ) : null}
              </div>
              <HealthLine collection={row.health?.collection} service={row.health?.service} heartbeat={row.health?.heartbeat_at} now={now} />
              <span className="v12activity">
                Activity: {row.last_event_at ? `last event ${relativeFromNow(row.last_event_at, now)}` : row.health ? 'no events yet' : 'not reported'}
              </span>
            </li>
          ))}
        </ul>
      </section>
      {telemetry.length > 0 ? <section aria-label="Telemetry sources">
        <h3 className="v12sources__title">Telemetry sources · not honeypots</h3>
        <p className="v12note">{ROUTING_COPY.telemetryNotHoneypot}</p>
        <ul className="v12sources__list">
          {telemetry.map((row) => (
            <li key={row.source_id} className="v12source v12source--telemetry" data-source-id={row.source_id}>
              <div className="v12source__head">
                <strong>{row.entry?.label ?? label(row.source_id)}</strong>
                <span className="mono v12source__id">{row.source_id}</span>
                {row.entry ? <span className={`v12tag v12tag--${row.entry.binding.status}`}>{row.entry.binding.status}</span> : null}
              </div>
              <HealthLine collection={row.health?.collection} service={row.health?.service} heartbeat={row.health?.heartbeat_at} now={now} />
              <span className="v12activity">
                Records: {row.health?.last_record_at ? `last record ${relativeFromNow(row.health.last_record_at, now)}` : row.health ? 'none yet' : 'not reported'}
              </span>
            </li>
          ))}
        </ul>
      </section> : null}
    </div>
  );
}

/* ---------- routing (Incident Detail) ---------- */

type Load<T> = { state: 'loading' } | { state: 'not_served' } | { state: 'error'; error: ApiError } | { state: 'ok'; data: T };

function useLoad<T>(loader: () => Promise<T>, key: string): [Load<T>, () => void] {
  const [value, setValue] = useState<Load<T>>({ state: 'loading' });
  const run = useCallback(() => {
    let alive = true;
    setValue({ state: 'loading' });
    loader()
      .then((data) => alive && setValue({ state: 'ok', data }))
      .catch((error) => {
        if (!alive) return;
        if (isNotServed(error)) setValue({ state: 'not_served' });
        else setValue({ state: 'error', error: error instanceof ApiError ? error : new ApiError('load_failed', String(error), 0) });
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  useEffect(() => run(), [run]);
  return [value, run];
}

export function GatewayRequestPanel({ gatewayRequestId, onOpenEvent }: { gatewayRequestId: string; onOpenEvent?: (id: string) => void }) {
  const [load] = useLoad<GatewayRequestDetail>(() => fetchGatewayRequest(gatewayRequestId), gatewayRequestId);
  if (load.state === 'loading') return <p className="v12note">Loading {gatewayRequestId}…</p>;
  if (load.state === 'not_served') return <p className="v12note">{ROUTING_COPY.unavailable}</p>;
  if (load.state === 'error') return <p className="v12note">Could not load {gatewayRequestId}: {load.error.message}</p>;
  return <GatewayRequestView detail={load.data} onOpenEvent={onOpenEvent} />;
}

/** Requested, gateway-observed and upstream-observed, kept apart. */
export function GatewayRequestView({ detail, onOpenEvent }: { detail: GatewayRequestDetail; onOpenEvent?: (id: string) => void }) {
  const decision = detail.decision;
  return (
    <div className="v12gwreq" data-correlation={detail.correlation.status}>
      <ol className="v12claims">
        <li>
          <span className="v12claims__label">{ROUTING_COPY.requested}</span>
          {decision ? (
            <span>
              <strong>{decision.decision === 'decoy' ? 'to web decoy' : 'to normal app'}</strong> ({decision.upstream_id}) ·{' '}
              {decision.reasons.map(reasonLabel).join(', ')}
              {decision.indicator_classes?.length ? ` · ${decision.indicator_classes.join(', ')}` : ''} · policy{' '}
              <span className="mono">
                {decision.routing_policy_id} rev {decision.routing_policy_revision}
              </span>{' '}
              · pin {decision.pin_scope} · client <span className="mono">{decision.client_ip}</span> ·{' '}
              <span className="mono">{timeUtcZ(decision.occurred_at)}</span>
            </span>
          ) : (
            <span className="v12missing">no decision record received</span>
          )}
        </li>
        <li>
          <span className="v12claims__label">{ROUTING_COPY.gatewayObserved}</span>
          {detail.gateway_observed_upstream ? (
            <span>
              {detail.gateway_observed_upstream.outcome.replace(/_/g, ' ')}
              {detail.gateway_observed_upstream.status_code ? ` · HTTP ${detail.gateway_observed_upstream.status_code}` : ''} from{' '}
              {detail.gateway_observed_upstream.upstream_id}
            </span>
          ) : (
            <span className="v12missing">no upstream result received</span>
          )}
        </li>
        <li>
          <span className="v12claims__label">{ROUTING_COPY.upstreamObserved}</span>
          {detail.upstream_handling.length ? (
            <span className="v12list">
              {detail.upstream_handling.map((item, index) => (
                <span key={item.event_id ?? item.record_id ?? index}>
                  {item.event_id ? <EvidenceId eventId={item.event_id} onOpen={onOpenEvent} /> : <span className="mono">{item.record_id}</span>}{' '}
                  {label(item.sensor_id ?? item.source_id ?? '')} {item.event_type ? `· ${item.event_type.replace(/_/g, ' ')}` : ''}
                </span>
              ))}
            </span>
          ) : (
            <span className="v12missing">no upstream record carries this id</span>
          )}
        </li>
      </ol>
      <p className={`v12corr v12corr--${detail.correlation.status}`}>
        {CORRELATION_LABEL[detail.correlation.status] ?? detail.correlation.status}
        {detail.correlation.reasons.length ? ` · ${detail.correlation.reasons.join(', ')}` : ''}
      </p>
    </div>
  );
}

export function RoutingPanel({ incidentId, onOpenEvent }: { incidentId: string; onOpenEvent?: (id: string) => void }) {
  const [load] = useLoad<IncidentRouting>(() => fetchIncidentRouting(incidentId), incidentId);
  if (load.state === 'loading') return <p className="v12note">Loading routing…</p>;
  if (load.state === 'not_served') return <p className="v12note v12note--unavailable">{ROUTING_COPY.unavailable}</p>;
  if (load.state === 'error') return <p className="v12note">Could not load routing: {load.error.message}</p>;
  return (
    <RoutingView
      routing={load.data}
      detail={(id) => <GatewayRequestPanel gatewayRequestId={id} onOpenEvent={onOpenEvent} />}
    />
  );
}

export function RoutingView({ routing, detail }: { routing: IncidentRouting; detail: (gatewayRequestId: string) => ReactNode }) {
  const [open, setOpen] = useState<string | null>(null);
  const contact = routing.normal_app_contact;
  return (
    <div className="v12routing">
      <p className="v12note">{ROUTING_COPY.joinRule}</p>
      <div className="v12routing__ingress">
        Ingress for this case: <strong>{routing.ingress.verified}</strong> via gateway (verified) · <strong>{routing.ingress.absent}</strong> direct ·{' '}
        <strong>{routing.ingress.invalid}</strong> invalid context
        {routing.gateway_session_refs.length ? (
          <>
            {' '}
            · sessions <span className="mono">{routing.gateway_session_refs.join(', ')}</span>
          </>
        ) : null}
      </div>
      {routing.gateway_requests.length === 0 ? (
        <p className="v12note">{ROUTING_COPY.noRouting}</p>
      ) : (
        <ul className="v12routing__list">
          {routing.gateway_requests.map((item) => (
            <li key={item.gateway_request_id}>
              <button
                type="button"
                className="v12routing__row"
                aria-expanded={open === item.gateway_request_id}
                onClick={() => setOpen(open === item.gateway_request_id ? null : item.gateway_request_id)}
              >
                <span className="mono">{item.gateway_request_id}</span>
                <span className={`v12tag v12tag--${item.decision}`}>{item.decision === 'decoy' ? 'to decoy' : 'to normal app'}</span>
                <span>{item.reasons.map(reasonLabel).join(', ')}</span>
                <span className={`v12corr v12corr--${item.correlation_status}`}>{item.correlation_status.replace(/_/g, ' ')}</span>
              </button>
              {open === item.gateway_request_id ? detail(item.gateway_request_id) : null}
            </li>
          ))}
        </ul>
      )}
      <div className="v12contact">
        <strong>Normal-app contact:</strong> {contact.records.length} record{contact.records.length === 1 ? '' : 's'} · demo-app collection{' '}
        {contact.coverage.collection} · {contact.coverage.records_in_run} records in run
        <p className="v12note">{contact.statement}</p>
      </div>
    </div>
  );
}

/* ---------- archive bait ---------- */

export function ArchivePanel({ items, onOpenEvent, isKnown }: { items: ArchiveEvidence[]; onOpenEvent?: (id: string) => void; isKnown?: (id: string) => boolean }) {
  if (items.length === 0) return null;
  return (
    <div className="v12archives">
      {items.map((item) => (
        <article key={item.served_event_id} className="v12archive">
          <header className="v12archive__head">
            <strong>{ARCHIVE_COPY.title}</strong> <span className="mono">{item.asset_id}</span>
            {item.issuance_id ? <span className="mono"> · {item.issuance_id}</span> : null}
            {item.honeytoken_ids.length ? <span> · tokens {item.honeytoken_ids.join(', ')}</span> : null}
          </header>
          {item.entries.length ? (
            <p className="v12note">
              {ARCHIVE_COPY.contents} Entries: {item.entries.map((entry) => entry.name).join(', ')} · executable{' '}
              {String(item.contains_executable)} · auto-run {String(item.auto_run)}
            </p>
          ) : null}
          {item.transfer ? (
            <p className="v12note">
              Server side: HTTP {item.transfer.response_status ?? '—'} · {item.transfer.bytes_written ?? '—'} bytes written ·{' '}
              {item.transfer.completion ?? 'completion not reported'} (the decoy's view; not client receipt)
            </p>
          ) : null}
          <ol className="v12claims">
            {item.claims.map((claim) => (
              <li key={claim.claim} className={`v12claim v12claim--${claim.state}`}>
                <span className="v12claims__label">{ARCHIVE_CLAIM_LABEL[claim.claim] ?? claim.claim}</span>
                <span>
                  {claim.state === 'observed' ? ARCHIVE_COPY.observed : claim.state === 'never_observable' ? ARCHIVE_COPY.neverObservable : ARCHIVE_COPY.notObserved}
                  {claim.event_ids.map((id) => (
                    <span key={id}>
                      {' '}
                      <EvidenceId eventId={id} onOpen={onOpenEvent} known={isKnown ? isKnown(id) : true} />
                    </span>
                  ))}
                  {claim.detail ? <span className="v12claim__detail"> · {claim.detail}</span> : null}
                </span>
              </li>
            ))}
          </ol>
        </article>
      ))}
    </div>
  );
}

/* ---------- response scope ---------- */

export function ScopeNote({ scope }: { scope: ScopeView }) {
  return (
    <div className="v12scope" data-unsupported={scope.unsupported_sensor ? 'true' : 'false'}>
      {scope.unsupported_sensor ? <p className="v12scope__warn">{SCOPE_COPY.unsupported}</p> : null}
      {scope.stated_by_backend ? (
        <p>
          {SCOPE_COPY.enforced}: {scope.enforced_on.map(label).join(', ')}.{' '}
          {scope.not_enforced_on.length ? `${SCOPE_COPY.notEnforced}: ${scope.not_enforced_on.map(label).join(', ')}.` : ''}
        </p>
      ) : (
        <p>{SCOPE_COPY.v11}</p>
      )}
    </div>
  );
}
