/**
 * Candidate relations, bait provenance and approved parents (review sections
 * 4 and 11).
 *
 * A relation connects two observed sessions and says why. It keeps its
 * uncertainty on screen: a candidate is a reason to look, a strong candidate
 * shows a planted credential travelled, and neither identifies a person. Only
 * an analyst's confirmation makes a parent; a rejected relation keeps both
 * children and their evidence.
 */

import {
  BAIT_STATUS_LABEL,
  BAIT_STATUS_MEANING,
  RELATION_COPY,
  SENSOR_LABEL,
  linkPhrase,
} from '../../copy';
import type { BaitChain, CandidateRelation, ParentInvestigation, SessionCase } from '../../evidence/model';
import { number, timeUtcZ } from '../../lib/format';
import { AttackerText } from '../primitives';
import { AuthorityTag, BasisTag, EvidenceId } from './bits';
import type { EvidenceHandlers } from './CaseViews';

function caseName(caseId: string | null, cases: SessionCase[]): string {
  if (!caseId) return 'case not loaded';
  const found = cases.find((item) => item.case_id === caseId);
  if (!found) return caseId;
  const sensor = SENSOR_LABEL[found.sensor_id] ?? found.sensor_id;
  return `${sensor} · ${found.session_id ?? 'no session id'}`;
}

export function BaitProvenance({ bait, onOpenEvent, isKnown }: { bait: BaitChain } & EvidenceHandlers) {
  const steps: Array<{ key: string; label: string; present: boolean; body: JSX.Element | string }> = [
    {
      key: 'issued',
      label: 'Issued',
      present: bait.issued !== null,
      body: bait.issued ? (
        <>
          to <span className="mono">{bait.issued.session_id ?? 'run'}</span> on{' '}
          {SENSOR_LABEL[bait.issued.sensor_id] ?? bait.issued.sensor_id}
          {bait.issuance_id ? (
            <>
              {' '}
              · issuance <span className="mono">{bait.issuance_id}</span>
            </>
          ) : null}
        </>
      ) : (
        'no issuance on record'
      ),
    },
    {
      key: 'served',
      label: 'Served',
      present: bait.served !== null,
      body: bait.served ? (
        <>
          <EvidenceId eventId={bait.served.event_id} onOpen={onOpenEvent} known={isKnown?.(bait.served.event_id) ?? true} />
          {bait.asset_id ? (
            <>
              {' '}
              · asset <span className="mono">{bait.asset_id}</span>
            </>
          ) : null}
          {bait.served.digest_scope ? (
            <span className="bait__meta"> · digest {bait.served.digest_scope.replace(/_/g, ' ')}</span>
          ) : null}
        </>
      ) : bait.v1_planted_side_event_id ? (
        <>
          not recorded · v1.0 linked the nearest earlier event{' '}
          <EvidenceId
            eventId={bait.v1_planted_side_event_id}
            onOpen={onOpenEvent}
            known={isKnown?.(bait.v1_planted_side_event_id) ?? true}
          />
          , not proof of a read
        </>
      ) : (
        'not recorded'
      ),
    },
    {
      key: 'presented',
      label: 'Presented',
      present: true,
      body: (
        <>
          on {SENSOR_LABEL[bait.presented.sensor_id] ?? bait.presented.sensor_id}{' '}
          <EvidenceId
            eventId={bait.presented.event_id}
            onOpen={onOpenEvent}
            known={isKnown?.(bait.presented.event_id) ?? true}
          />
          {bait.presented.at ? <span className="bait__meta"> · {timeUtcZ(bait.presented.at)}</span> : null}
        </>
      ),
    },
  ];

  return (
    <div className={`bait bait--${bait.status}`}>
      <div className="bait__head">
        <span className="mono bait__token">{bait.token_id}</span>
        <span className="bait__status" title={BAIT_STATUS_MEANING[bait.status]}>
          {BAIT_STATUS_LABEL[bait.status]}
        </span>
      </div>
      <ol className="bait__chain">
        {steps.map((step) => (
          <li key={step.key} className={step.present ? 'bait__step' : 'bait__step bait__step--missing'}>
            <span className="bait__label">{step.label}</span>
            <span className="bait__body">{step.body}</span>
          </li>
        ))}
      </ol>
      <p className="bait__meaning">{BAIT_STATUS_MEANING[bait.status]}</p>
    </div>
  );
}

export function RelationCard({
  relation,
  cases,
  onDecide,
  ...handlers
}: {
  relation: CandidateRelation;
  cases: SessionCase[];
  /** Present when the analyst may decide here (a live v1.0 link). */
  onDecide?: () => void;
} & EvidenceHandlers) {
  const caveat =
    relation.status === 'rejected'
      ? RELATION_COPY.rejected
      : relation.kind === 'strong_candidate'
        ? RELATION_COPY.strong
        : RELATION_COPY.candidate;
  return (
    <article
      className={`relcard relcard--${relation.status} relcard--${relation.kind}`}
      aria-label={linkPhrase(relation.kind, relation.status)}
      data-relation-id={relation.relation_id}
    >
      <header className="relcard__head">
        <span className={`relcard__line relcard__line--${relation.status}`} aria-hidden="true" />
        <span className="relcard__phrase">{linkPhrase(relation.kind, relation.status)}</span>
        <span className="relcard__spacer" />
        <BasisTag basis={relation.basis} />
      </header>

      <div className="relcard__ends">
        <div className="relcard__end">
          <span className="relcard__endlabel">{caseName(relation.from.case_id, cases)}</span>
          <EvidenceId
            eventId={relation.from.event_id}
            onOpen={handlers.onOpenEvent}
            known={handlers.isKnown?.(relation.from.event_id) ?? true}
          />
        </div>
        <span className="relcard__arrow" aria-hidden="true">
          ⇢
        </span>
        <div className="relcard__end">
          <span className="relcard__endlabel">{caseName(relation.to.case_id, cases)}</span>
          <EvidenceId
            eventId={relation.to.event_id}
            onOpen={handlers.onOpenEvent}
            known={handlers.isKnown?.(relation.to.event_id) ?? true}
          />
        </div>
      </div>

      <p className="relcard__reason">
        Proposed because: <span className="mono">{relation.reason}</span>
        {relation.gap_seconds !== null ? <> · {number(relation.gap_seconds)} s apart</> : null}
      </p>

      {relation.bait ? <BaitProvenance bait={relation.bait} {...handlers} /> : null}

      <p className="relcard__caveat">{caveat}</p>

      {relation.rationale ? (
        <p className="relcard__rationale">
          Analyst rationale: <AttackerText value={relation.rationale} />
          {relation.actor_id ? <span className="relcard__actor"> · {relation.actor_id}</span> : null}
          {relation.decided_at ? <span className="relcard__actor"> · {timeUtcZ(relation.decided_at)}</span> : null}
        </p>
      ) : null}

      {onDecide ? (
        <div className="relcard__actions">
          <button type="button" className="btn" onClick={onDecide}>
            {relation.status === 'open' ? 'Confirm or reject…' : 'Change decision…'}
          </button>
        </div>
      ) : null}
    </article>
  );
}

export function OrphanUseCard({ bait, ...handlers }: { bait: BaitChain } & EvidenceHandlers) {
  return (
    <article className="relcard relcard--orphan" aria-label="Orphan token use">
      <header className="relcard__head">
        <span className="relcard__phrase">Token use with no relation</span>
      </header>
      <BaitProvenance bait={bait} {...handlers} />
    </article>
  );
}

export function ParentCard({
  parent,
  cases,
  relations,
}: {
  parent: ParentInvestigation;
  cases: SessionCase[];
  relations: CandidateRelation[];
}) {
  const included = relations.filter((relation) => parent.relation_ids.includes(relation.relation_id));
  return (
    <section className="evcard evcard--parent" aria-label="Approved cross-decoy parent">
      <header className="evcard__head">
        <span className="evcard__kind">
          {parent.authority === 'backend_case' ? 'Investigation' : 'Approved cross-decoy parent'}
        </span>
        <AuthorityTag authority={parent.authority} />
        <span className="mono evcard__sub">{parent.parent_id}</span>
        <span className="evcard__spacer" />
        {parent.score !== null && parent.severity !== null ? (
          <span className={`badge badge--${parent.severity}`}>
            {number(parent.score)} {parent.severity}
          </span>
        ) : (
          <span className="casescore casescore--none" title={RELATION_COPY.parentScoreV1}>
            no parent score in v1.0
          </span>
        )}
        <BasisTag basis={parent.basis} />
      </header>
      <p className="evcard__note">{RELATION_COPY.parent}</p>
      <ul className="parent__cases">
        {parent.case_ids.map((caseId) => (
          <li key={caseId}>{caseName(caseId, cases)}</li>
        ))}
      </ul>
      <p className="evcard__meta">
        via {included.map((relation) => linkPhrase(relation.kind, relation.status)).join(', ') || 'relation'}
        {parent.approved_by ? <> · approved by {parent.approved_by}</> : null}
        {parent.approved_at ? <> · {timeUtcZ(parent.approved_at)}</> : null}
        {parent.incident_revision !== null ? <> · revision {parent.incident_revision}</> : null}
      </p>
      {parent.summary_stale ? (
        <p className="evcard__stale">The summary predates the latest decision and is stale.</p>
      ) : null}
      <p className="relcard__caveat">{RELATION_COPY.identity}</p>
    </section>
  );
}
