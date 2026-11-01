/** Adapt authoritative case/profile APIs; the browser never computes a score. */
import type { BackendEligibility, BackendProfile, Incident, IncidentSummary, SocEvent } from '../types/api';
import type { CandidateRelation, ParentInvestigation, SessionCase, SourceProfile } from './model.ts';
import { mappingsFromV1, relationsFromV1, sessionCasesFromV1 } from './fromV1.ts';

export interface BackendContext {
  events: SocEvent[];
  cases: IncidentSummary[];
  profile: BackendProfile;
  eligibility: BackendEligibility;
}

export function evidenceFromBackend(incident: Incident, context: BackendContext) {
  const events = context.events;
  const eventById = new Map(events.map(event => [event.event_id, event]));
  const includedIds = new Set([...context.profile.case_ids, ...(incident.children ?? []), incident.incident_id]);
  for (const link of incident.links) {
    for (const id of [link.from_event_id, link.to_event_id]) {
      const owner = eventById.get(id)?.incident_id;
      if (owner) includedIds.add(owner);
    }
  }
  const summaries = context.cases.filter(item => includedIds.has(item.incident_id)
    && item.case_kind !== 'investigation' && item.status !== 'superseded');
  const cases: SessionCase[] = summaries.map(item => {
    const list = events.filter(event => event.incident_id === item.incident_id);
    const display = sessionCasesFromV1(list, incident.findings)[0];
    return {
      case_id: item.incident_id, basis: 'contract_v11', authority: 'backend_case',
      sensor_id: item.sensor_id ?? display?.sensor_id ?? 'ssh-decoy-01',
      session_id: item.session_id ?? null,
      boundary: item.grouping_basis === 'sensor_session' ? 'sensor_session' : 'bounded_fallback',
      lab_run_id: item.lab_run_id, capture_mode: item.capture_mode ?? 'live', src_ip: item.src_ip,
      first_at: item.first_seen, last_at: item.last_seen,
      event_ids: list.map(event => event.event_id), event_count: item.event_count,
      grouping_basis: item.grouping_basis ?? null,
      outcomes: display?.outcomes ?? {}, request_ids: [...new Set(list.map(event => event.attributes?.request_id)
        .filter((id): id is string => typeof id === 'string'))],
      accounts: [...new Set(list.map(event => event.attributes?.username).filter((id): id is string => Boolean(id)))],
      commands: list.filter(event => event.event_type === 'command_input').length,
      rule_ids: display?.rule_ids ?? [], score: item.score, severity: item.severity,
    };
  });
  const relations: CandidateRelation[] = relationsFromV1(incident.links, events).map(relation => {
    const link = incident.links.find(item => item.link_id === relation.relation_id)!;
    const from = eventById.get(link.from_event_id), to = eventById.get(link.to_event_id);
    const bait = relation.bait;
    const served = from?.event_type === 'bait_served' ? from : null;
    return {
      ...relation, basis: 'contract_v11', attribution: link.attribution ?? null,
      candidate_issuance_ids: link.candidate_issuance_ids ?? [],
      from: { ...relation.from, case_id: from?.incident_id ?? null },
      to: { ...relation.to, case_id: to?.incident_id ?? null },
      bait: bait ? {
        ...bait, v1_planted_side_event_id: null,
        asset_id: typeof served?.attributes?.asset_id === 'string' ? served.attributes.asset_id : null,
        fixture_version: typeof served?.attributes?.fixture_version === 'string' ? served.attributes.fixture_version : null,
        issuance_id: typeof served?.attributes?.issuance_id === 'string' ? served.attributes.issuance_id : null,
        issued: served ? { session_id: served.session_id ?? null, sensor_id: served.sensor_id, at: served.occurred_at } : null,
        served: served ? { event_id: served.event_id, at: served.occurred_at,
          digest_scope: typeof served.attributes?.digest_scope === 'string' ? served.attributes.digest_scope : null } : null,
        status: served ? 'served_then_presented' : 'presented_without_served_evidence',
      } : null,
    };
  });
  const parents: ParentInvestigation[] = context.cases.filter(item => item.case_kind === 'investigation'
    && item.status === 'open' && (item.incident_id === incident.incident_id
      || (item.children ?? []).some(id => includedIds.has(id)))).map(item => ({
        parent_id: item.incident_id, basis: 'contract_v11', authority: 'backend_case',
        relation_ids: relations.filter(relation => relation.status === 'confirmed').map(relation => relation.relation_id),
        case_ids: item.children ?? [], approved_at: null, approved_by: null, rationale: null,
        score: item.score, severity: item.severity, incident_revision: null, summary_stale: false,
      }));
  const profile: SourceProfile = {
    profile_id: `${context.profile.src_ip}/${context.profile.lab_run_id}/${context.profile.capture_mode}`,
    basis: 'contract_v11', src_ip: context.profile.src_ip, lab_run_id: context.profile.lab_run_id,
    capture_modes: [context.profile.capture_mode], first_at: context.profile.first_seen,
    last_at: context.profile.last_seen,
    sensors: Object.entries(context.profile.sensors).map(([sensor, counts]) => ({
      sensor_id: sensor as SessionCase['sensor_id'], cases: counts!.cases, events: counts!.events,
    })), attempted_accounts: context.profile.attempted_usernames, client_claims: [],
    case_ids: context.profile.case_ids, source_score: null,
  };
  for (const claim of context.profile.client_claims) {
    const kind = claim.client_version ? 'ssh_client_version' as const : 'http_user_agent' as const;
    const value = claim.client_version ?? claim.user_agent;
    if (!value) continue;
    const event = events.find(item => item.sensor_id === claim.sensor_id && item.src_ip === profile.src_ip
      && String(item.attributes?.[claim.client_version ? 'client_version' : 'user_agent'] ?? '').startsWith(value));
    if (event) profile.client_claims.push({ kind, value, event_id: event.event_id });
  }
  return {
    cases, relations, parents, profile,
    mappings: mappingsFromV1(incident.findings).map(item => {
      const finding = incident.findings.find(f => f.finding_id === item.finding_id)!;
      return { ...item, mapping_version: finding.mapping_version ?? null,
        rationale: finding.mapping?.map(mapping => mapping.rationale).join(' ') || null };
    }),
    eligibility: { eligible: context.eligibility.eligible, source: 'backend' as const, reasons: context.eligibility.reasons },
  };
}
