/**
 * Contract v1.2 views rendered from M3's PROVISIONAL fixtures
 * (provisional/m3_telemetry_v1_2.json, PR #19 @ eb2a94e). Fixture build only:
 * imported solely by the dev Evidence lab, which a release build drops.
 * No gateway, demo-app, MySQL or SMB producer existed when these were written.
 */

import { useMemo } from 'react';
import { EvidenceId } from '../components/evidence/bits';
import { eventTypeLabel } from '../copy';
import { timeUtcZ } from '../lib/format';
import type { BackendEligibility, Health, SocEvent } from '../types/api';
import fixture from './provisional/m3_telemetry_v1_2.json';
import { ArchivePanel, GatewayRequestView, ProtocolFacts, RoutingView, ScopeNote, SourcesPanel } from './components';
import type { GatewayRequestDetail, IncidentRouting, SourcesRegistry } from './types';
import { archiveEvidence, responseScope, sourceRows } from './views';

type Fixture = typeof fixture;
const F = fixture as unknown as Fixture & { expected_reads: Record<string, any> }; // eslint-disable-line @typescript-eslint/no-explicit-any

export function ProvisionalV12Lab({ onOpen }: { onOpen: (event: SocEvent) => void }) {
  const events = useMemo<SocEvent[]>(
    () => (F.events_valid as unknown as SocEvent[]).map((event, index) => ({
      ...event, event_id: `prov_evt_${index}`, seq: 9000 + index, ingested_at: event.occurred_at, incident_id: 'inc_provisional',
    })),
    [],
  );
  const byId = useMemo(() => new Map(events.map((event) => [event.event_id, event])), [events]);
  const handlers = { onOpenEvent: (id: string) => { const e = byId.get(id); if (e) onOpen(e); }, isKnown: (id: string) => byId.has(id) };
  const reads = F.expected_reads;
  const registry: SourcesRegistry = {
    registry_version: '1.2',
    honeypots: reads.sources_excerpt.honeypots.map((id: string) => ({
      source_id: id, source_kind: 'honeypot', protocol: id.startsWith('ssh') ? 'ssh' : id.startsWith('web') ? 'http' : id.startsWith('db') ? 'mysql' : 'smb',
      label: id, event_schema_versions: ['1.2'], event_types: [],
      binding: { host: '192.168.77.20', port: null, status: id.startsWith('ssh') || id.startsWith('web') ? 'deployed' : 'proposed' },
      response: id.startsWith('web') ? { block: 'supported', scope: 'web-decoy-01 only' } : { block: 'unsupported' },
    })),
    telemetry_sources: reads.sources_excerpt.telemetry_sources.map((id: string) => ({
      source_id: id, source_kind: id === 'gateway-01' ? 'gateway' : 'application', protocol: 'http', label: id,
      telemetry_versions: ['1.0'], record_types: [], binding: { host: 'internal', port: null, status: 'proposed' }, response: { block: 'not_applicable' },
    })),
    honeypot_count: reads.sources_excerpt.honeypot_count,
  };
  const health: Health = { ok: true, sensors: {}, sensor_health: {}, telemetry_health: { 'gateway-01': reads.health_excerpt.telemetry_health_row as NonNullable<Health['telemetry_health']>[string] } };
  const rows = sourceRows(registry, health);
  const served = events.find((event) => event.event_type === 'bait_served');
  const dbUse = events.find((event) => event.sensor_id === 'db-decoy-01' && event.event_type === 'auth_success');
  const links = served && dbUse ? [{ link_id: 'prov_link_db', from_event_id: served.event_id, to_event_id: dbUse.event_id,
    to_sensor: 'db-decoy-01', kind: reads.token_link_db.kind, basis: reads.token_link_db.basis, status: 'open', attribution: reads.token_link_db.attribution }] : [];
  const routing = reads.incident_routing_web_case as IncidentRouting;
  const gw = reads.gateway_request as GatewayRequestDetail;
  const dbEligibility = reads.eligibility_db_case;
  const eligibility: BackendEligibility = { eligible: dbEligibility.eligible, reasons: dbEligibility.reasons_include, capture_mode: 'live',
    lab_run_id: dbEligibility.lab_run_id, target_ip: dbEligibility.target_ip, checked_at: '', last_web_observation_at: null, response_scope: dbEligibility.response_scope };

  return (
    <section className="devlab__scenario" id="v12-provisional" aria-label="Contract v1.2 provisional">
      <header className="devlab__head">
        <h2 className="devlab__title">Contract v1.2 · four honeypots, gateway and telemetry</h2>
        <span className="pill pill--warn">PROVISIONAL · M3 fixture eb2a94e</span>
      </header>
      <p className="devlab__expect">
        <strong>Must show:</strong> four honeypots and two telemetry sources kept apart; gateway decision, gateway-observed
        result and upstream record as three claims; archive served but never "downloaded" or "extracted"; a database case
        offered no web block. Every record here is M3's synthetic fixture, not a producer record.
      </p>

      <div className="evsection__label">Sources and telemetry health</div>
      <SourcesPanel honeypots={rows.honeypots} telemetry={rows.telemetry} honeypotCount={rows.honeypot_count} registryServed now={new Date('2026-11-02T05:01:00Z')} />

      <div className="evsection__label">Events from all four honeypots</div>
      <table className="devlab__events">
        <tbody>
          {events.map((event) => (
            <tr key={event.event_id} data-sensor={event.sensor_id}>
              <td><EvidenceId eventId={event.event_id} onOpen={handlers.onOpenEvent} /></td>
              <td className="mono">{event.sensor_id}</td>
              <td className="mono">{timeUtcZ(event.occurred_at)}</td>
              <td>{eventTypeLabel(event.event_type)}</td>
              <td><ProtocolFacts event={event} /></td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="evsection__label">Gateway routing for a web case</div>
      <RoutingView routing={routing} detail={(id) => (id === gw.gateway_request_id
        ? <GatewayRequestView detail={gw} onOpenEvent={handlers.onOpenEvent} />
        : <p className="v12note">No fixture detail for {id}.</p>)} />

      <div className="evsection__label">Archive bait and later credential use</div>
      <ArchivePanel items={archiveEvidence(events, links)} {...handlers} />

      <div className="evsection__label">Response scope for a database case</div>
      <ScopeNote scope={responseScope(eligibility)} />
    </section>
  );
}
