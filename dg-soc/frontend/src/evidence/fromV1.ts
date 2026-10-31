/**
 * Today's API (contracts/API.md v1.0) reshaped into the evidence display
 * model. This is regrouping only: no score, no detection, no guess. Where
 * v1.0 does not carry a value the result is null and the UI says so.
 *
 * Replace each function's input with the agreed contract endpoint once Rohan's
 * session/source/parent model lands; the components stay as they are.
 *
 * Only type imports: pure, and tested under `node --test`.
 */

import type {
  CaptureMode,
  Finding,
  Health,
  Incident,
  Link,
  ResponseAction,
  RuleId,
  SensorId,
  SocEvent,
} from '../types/api';
import {
  facetOf,
  type BaitChain,
  type CandidateRelation,
  type ClientClaim,
  type HealthView,
  type MappingView,
  type Outcome,
  type ParentInvestigation,
  type ResponseEligibility,
  type ResponseVerification,
  type SessionCase,
  type SourceProfile,
} from './model.ts';

const byTime = (a: SocEvent, b: SocEvent) =>
  a.occurred_at === b.occurred_at ? a.seq - b.seq : a.occurred_at < b.occurred_at ? -1 : 1;

/** The case an event belongs to: its decoy session, or the bounded fallback. */
export function caseIdOf(event: SocEvent): string {
  return event.session_id
    ? `${event.sensor_id}/${event.session_id}`
    : `${event.sensor_id}/no-session/${event.src_ip}/${event.lab_run_id}`;
}

function modeOf(events: SocEvent[]): CaptureMode | 'mixed' {
  const modes = new Set(events.map((event) => event.capture_mode));
  if (modes.size > 1) return 'mixed';
  return [...modes][0] ?? 'live';
}

function unique(values: Array<string | null | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && value !== ''))];
}

/**
 * Session cases. One per decoy session; events without a session (the v1.0
 * web decoy) form one bounded fallback case per sensor, source and run. Never
 * merged across sessions: that is exactly the pooling the review flags (F1).
 */
export function sessionCasesFromV1(events: SocEvent[], findings: Finding[]): SessionCase[] {
  const groups = new Map<string, SocEvent[]>();
  for (const event of [...events].sort(byTime)) {
    const id = caseIdOf(event);
    const list = groups.get(id) ?? [];
    list.push(event);
    groups.set(id, list);
  }

  const rulesByEvent = new Map<string, Set<RuleId>>();
  for (const finding of findings) {
    for (const id of finding.evidence_event_ids) {
      const set = rulesByEvent.get(id) ?? new Set<RuleId>();
      set.add(finding.rule_id);
      rulesByEvent.set(id, set);
    }
  }

  const cases: SessionCase[] = [];
  for (const [caseId, list] of groups) {
    const first = list[0];
    const last = list[list.length - 1];
    if (!first || !last) continue;
    const outcomes: Partial<Record<Outcome, number>> = {};
    for (const event of list) {
      const outcome = facetOf(event).outcome;
      if (outcome) outcomes[outcome] = (outcomes[outcome] ?? 0) + 1;
    }
    const rules = new Set<RuleId>();
    for (const event of list) for (const rule of rulesByEvent.get(event.event_id) ?? []) rules.add(rule);
    cases.push({
      case_id: caseId,
      basis: 'contract_v1',
      sensor_id: first.sensor_id,
      session_id: first.session_id ?? null,
      boundary: first.session_id ? 'sensor_session' : 'bounded_fallback',
      lab_run_id: first.lab_run_id,
      capture_mode: modeOf(list),
      src_ip: first.src_ip,
      first_at: first.occurred_at,
      last_at: last.occurred_at,
      event_ids: list.map((event) => event.event_id),
      outcomes,
      request_ids: unique(list.map((event) => facetOf(event).request_id)),
      accounts: unique(list.map((event) => event.attributes?.username)),
      commands: list.filter((event) => event.event_type === 'command_input').length,
      rule_ids: [...rules].sort(),
      score: null,
      severity: null,
    });
  }
  return cases.sort((a, b) => (a.first_at < b.first_at ? -1 : a.first_at > b.first_at ? 1 : 0));
}

/** The source profile: an observed endpoint in one run. Counts only. */
export function sourceProfileFromV1(incident: Incident, events: SocEvent[], cases: SessionCase[]): SourceProfile {
  const sensors = new Map<SensorId, { cases: Set<string>; events: number }>();
  for (const event of events) {
    const entry = sensors.get(event.sensor_id) ?? { cases: new Set<string>(), events: 0 };
    entry.cases.add(caseIdOf(event));
    entry.events += 1;
    sensors.set(event.sensor_id, entry);
  }
  const claims: ClientClaim[] = [];
  const seen = new Set<string>();
  for (const event of [...events].sort(byTime)) {
    const attributes = event.attributes ?? {};
    const pairs: Array<[ClientClaim['kind'], unknown]> = [
      ['ssh_client_version', attributes.client_version],
      ['http_user_agent', attributes.user_agent],
    ];
    for (const [kind, value] of pairs) {
      if (typeof value !== 'string' || !value) continue;
      const key = `${kind}\u0000${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      claims.push({ kind, value, event_id: event.event_id });
    }
  }
  return {
    profile_id: `${incident.src_ip}/${incident.lab_run_id}`,
    basis: 'contract_v1',
    src_ip: incident.src_ip,
    lab_run_id: incident.lab_run_id,
    capture_modes: unique(events.map((event) => event.capture_mode)) as CaptureMode[],
    first_at: incident.first_seen,
    last_at: incident.last_seen,
    sensors: [...sensors.entries()].map(([sensor_id, entry]) => ({
      sensor_id,
      cases: entry.cases.size,
      events: entry.events,
    })),
    attempted_accounts: unique(events.map((event) => event.attributes?.username)),
    client_claims: claims,
    case_ids: cases.map((item) => item.case_id),
    source_score: { incident_id: incident.incident_id, score: incident.score, severity: incident.severity },
  };
}

const TOKEN_IN_BASIS = /honeytoken\s+(\S+)/i;

/** Relations from v1.0 links. Strong links get the bait chain v1.0 can support: presented only. */
export function relationsFromV1(links: Link[], events: SocEvent[]): CandidateRelation[] {
  const byId = new Map(events.map((event) => [event.event_id, event]));
  return links.map((link) => {
    const from = byId.get(link.from_event_id);
    const to = byId.get(link.to_event_id);
    const token = TOKEN_IN_BASIS.exec(link.basis)?.[1] ?? null;
    const bait: BaitChain | null = token
      ? {
          token_id: token,
          asset_id: null,
          issuance_id: null,
          fixture_version: null,
          issued: null,
          // v1.0 has no bait_served event: nothing records the bait being served.
          served: null,
          presented: { event_id: link.to_event_id, sensor_id: link.to_sensor, at: to?.occurred_at ?? null },
          status: 'presented_without_served_evidence',
          v1_planted_side_event_id: link.from_event_id,
        }
      : null;
    return {
      relation_id: link.link_id,
      basis: 'contract_v1',
      kind: link.kind,
      status: link.status,
      reason: link.basis,
      from: {
        case_id: from ? caseIdOf(from) : null,
        event_id: link.from_event_id,
        sensor_id: link.from_sensor,
        at: from?.occurred_at ?? null,
      },
      to: {
        case_id: to ? caseIdOf(to) : null,
        event_id: link.to_event_id,
        sensor_id: link.to_sensor,
        at: to?.occurred_at ?? null,
      },
      gap_seconds:
        from && to ? Math.round((Date.parse(to.occurred_at) - Date.parse(from.occurred_at)) / 1000) : null,
      bait,
      decided_at: link.decided_at,
      rationale: link.rationale,
      actor_id: null,
    };
  });
}

/**
 * An approved cross-decoy parent: one per confirmed relation. v1.0 has no
 * parent object and no parent score, so the score stays null; the source
 * score is shown separately for what it is.
 */
export function parentsFromV1(relations: CandidateRelation[]): ParentInvestigation[] {
  return relations
    .filter((relation) => relation.status === 'confirmed')
    .map((relation) => ({
      parent_id: `parent/${relation.relation_id}`,
      basis: 'contract_v1',
      relation_ids: [relation.relation_id],
      case_ids: unique([relation.from.case_id, relation.to.case_id]),
      approved_at: relation.decided_at,
      approved_by: relation.actor_id,
      rationale: relation.rationale,
      score: null,
      severity: null,
      incident_revision: null,
      summary_stale: false,
    }));
}

export function mappingsFromV1(findings: Finding[]): MappingView[] {
  return findings.map((finding) => ({
    finding_id: finding.finding_id,
    rule_id: finding.rule_id,
    rule_version: finding.rule_version,
    mapping_version: null,
    technique_ids: finding.technique_ids,
    technique_status: finding.technique_ids.length > 0 ? 'mapped' : 'no_technique',
    rationale: null,
    limitation: finding.limitation,
    observation: null,
    evidence_event_ids: finding.evidence_event_ids,
  }));
}

/** v1.0 action status, split into the stages the review asks to show. */
export function verificationFromV1(action: ResponseAction): ResponseVerification {
  return {
    action_id: action.action_id,
    basis: 'contract_v1',
    target_ip: action.target_ip,
    reason: action.reason,
    until: action.until,
    committed: { at: action.created_at, policy_revision: null, by: null },
    verified: action.verified_by_event_id ? { event_id: action.verified_by_event_id, at: null } : null,
    ended:
      action.status === 'expired'
        ? { kind: 'expired', at: action.until, by: null }
        : action.status === 'revoked'
          ? { kind: 'revoked', at: null, by: null }
          : null,
    rejected_attempts: [],
  };
}

/**
 * The UI guard for response actions, from fields the backend reported. It can
 * only withhold an offer; the backend still decides on every preview and
 * apply (review T03).
 */
export function eligibilityFromV1(events: SocEvent[]): ResponseEligibility {
  const modes = new Set(events.map((event) => event.capture_mode));
  const reasons: ResponseEligibility['reasons'] = [];
  if (events.length === 0) {
    reasons.push({ code: 'no_live_run', message: 'No observations from this source yet.' });
  } else if (modes.has('replay') && modes.has('live')) {
    reasons.push({
      code: 'mixed_modes',
      message: 'This source mixes live and replayed observations. Response needs live evidence only.',
    });
  } else if (modes.has('replay')) {
    reasons.push({
      code: 'replay_data',
      message: 'Every observation here is replayed. A replay cannot change the live web policy.',
    });
  }
  return { eligible: reasons.length === 0, source: 'ui_guard', reasons };
}

export function healthFromV1(health: Health | null, checkedAt: string | null, sensorIds: readonly SensorId[]): HealthView {
  return {
    basis: 'contract_v1',
    service: { backend: health === null ? 'down' : health.ok ? 'up' : 'unknown', checked_at: checkedAt },
    // v1.0 /api/health has no collector heartbeat: do not invent one.
    collectors: null,
    activity: sensorIds.map((sensor_id) => ({ sensor_id, last_event_at: health?.sensors[sensor_id] ?? null })),
  };
}
