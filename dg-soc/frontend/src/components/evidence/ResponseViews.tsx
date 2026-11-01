/**
 * Response verification and eligibility (review section 14).
 *
 * The stages are kept apart on purpose:
 *   policy committed      the blocklist entry was written
 *   pending verification  nothing matching has been refused yet
 *   verified denial       a request matching the full tuple was refused
 *   expired / revoked     the action ended
 * Observations the backend rejected as verification are listed with their
 * reasons; they never move the state.
 *
 * Eligibility: the UI can withhold an action it cannot honestly offer
 * (replay or mixed data), but the backend still checks every request.
 */

import type { ReactNode } from 'react';
import {
  ELIGIBILITY_COPY,
  mismatchReasonLabel,
  SENSOR_LABEL,
  VERIFICATION_COPY,
} from '../../copy';
import type { ResponseEligibility, ResponseVerification } from '../../evidence/model';
import { timeUtcZ } from '../../lib/format';
import { BasisTag, EvidenceId, ModeBadge } from './bits';
import type { EvidenceHandlers } from './CaseViews';

type StageState = 'done' | 'current' | 'waiting' | 'skipped';

function Stage({
  kind,
  state,
  title,
  hint,
  children,
}: {
  kind: 'committed' | 'pending' | 'verified' | 'ended';
  state: StageState;
  title: string;
  hint: string;
  children?: ReactNode;
}) {
  return (
    <li className={`vstage vstage--${state} vstage--k-${kind}`}>
      <span className="vstage__dot" aria-hidden="true" />
      <div className="vstage__body">
        <div className="vstage__title">
          {title}
          {state === 'current' ? <span className="vstage__now">now</span> : null}
        </div>
        <div className="vstage__hint">{hint}</div>
        {children}
      </div>
    </li>
  );
}

export function VerificationTimeline({
  verification: v,
  ...handlers
}: { verification: ResponseVerification } & EvidenceHandlers) {
  const ended = v.ended;
  const verified = v.verified;
  const pendingState: StageState = verified ? 'done' : ended ? 'skipped' : 'current';

  return (
    <div className="vtimeline" data-action-id={v.action_id}>
      <div className="vtimeline__head">
        <span className="mono">{v.action_id}</span>
        <span className="mono vtimeline__target">{v.target_ip}</span>
        <span className="vtimeline__scope">web decoy only</span>
        <span className="vtimeline__spacer" />
        <BasisTag basis={v.basis} />
      </div>
      <ol className="vstages">
        <Stage kind="committed" state="done" title={VERIFICATION_COPY.committed} hint={VERIFICATION_COPY.committedHint}>
          <div className="vstage__meta mono">
            {timeUtcZ(v.committed.at)}
            {v.committed.policy_revision !== null ? ` · policy rev ${v.committed.policy_revision}` : ''}
            {v.committed.by ? ` · ${v.committed.by}` : ''}
          </div>
        </Stage>
        <Stage
          kind="pending"
          state={pendingState}
          title={VERIFICATION_COPY.pending}
          hint={pendingState === 'skipped' ? 'Ended before a matching request was refused.' : VERIFICATION_COPY.pendingHint}
        />
        <Stage
          kind="verified"
          state={verified ? 'done' : 'waiting'}
          title={VERIFICATION_COPY.verified}
          hint={verified ? VERIFICATION_COPY.verifiedHint : 'Not verified.'}
        >
          {verified ? (
            <div className="vstage__meta">
              <EvidenceId
                eventId={verified.event_id}
                onOpen={handlers.onOpenEvent}
                known={handlers.isKnown?.(verified.event_id) ?? true}
              />
              {verified.at ? <span className="mono"> · {timeUtcZ(verified.at)}</span> : null}
            </div>
          ) : null}
        </Stage>
        {v.needs_reconciliation ? (
          <Stage kind="ended" state="current" title={VERIFICATION_COPY.reconcile} hint={VERIFICATION_COPY.reconcileHint} />
        ) : null}
        {ended ? (
          <Stage
            kind="ended"
            state="done"
            title={ended.kind === 'expired' ? VERIFICATION_COPY.expired : VERIFICATION_COPY.revoked}
            hint={ended.kind === 'expired' ? 'The time limit ran out and the block lifted itself.' : 'An analyst undid this block.'}
          >
            <div className="vstage__meta mono">
              {ended.at ? timeUtcZ(ended.at) : 'time not reported'}
              {ended.by ? ` · ${ended.by}` : ''}
            </div>
          </Stage>
        ) : null}
      </ol>

      {v.rejected_attempts.length > 0 ? (
        <div className="vmismatch">
          <div className="vmismatch__title">{VERIFICATION_COPY.rejectedTitle}</div>
          <div className="vmismatch__hint">{VERIFICATION_COPY.rejectedHint}</div>
          <ul className="vmismatch__list">
            {v.rejected_attempts.map((attempt, index) => (
              <li key={`${attempt.event_id ?? 'none'}-${attempt.reason}-${index}`}>
                <span className="vmismatch__reason">{mismatchReasonLabel(attempt.reason)}</span>
                <span className="vmismatch__tuple">
                  {attempt.event_id ? (
                    <EvidenceId
                      eventId={attempt.event_id}
                      onOpen={handlers.onOpenEvent}
                      known={handlers.isKnown?.(attempt.event_id) ?? true}
                    />
                  ) : (
                    <span className="mono">no event id</span>
                  )}
                  {attempt.sensor_id ? <> {SENSOR_LABEL[attempt.sensor_id] ?? attempt.sensor_id}</> : null}
                  {attempt.src_ip ? <> · <span className="mono">{attempt.src_ip}</span></> : null}
                  {attempt.capture_mode ? <> <ModeBadge mode={attempt.capture_mode} /></> : null}
                  {attempt.at ? <> <span className="mono">{timeUtcZ(attempt.at)}</span></> : null}
                  {attempt.field !== 'proposed' ? (
                    <span className="vmismatch__field mono" title="Field name not yet agreed between M2 and M3">
                      {attempt.field}
                    </span>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : v.refusals_reported ? (
        <p className="vtimeline__note">{VERIFICATION_COPY.noneReported}</p>
      ) : v.basis === 'contract_v1' && !ended ? (
        <p className="vtimeline__note">{VERIFICATION_COPY.v1Tuple}</p>
      ) : null}
    </div>
  );
}

/** Why an action is or is not offered. Renders nothing when eligible. */
export function EligibilityNotice({ eligibility }: { eligibility: ResponseEligibility }) {
  if (eligibility.eligible) return null;
  return (
    <div className="eligibility" role="note">
      <div className="eligibility__title">Response not available for this source</div>
      <ul className="eligibility__reasons">
        {eligibility.reasons.map((reason) => (
          <li key={reason.code}>
            <span className="mono eligibility__code">{reason.code}</span> {reason.message}
          </li>
        ))}
      </ul>
      <div className="eligibility__foot">
        {eligibility.source === 'ui_guard' ? ELIGIBILITY_COPY.uiGuard : ELIGIBILITY_COPY.backend}{' '}
        {ELIGIBILITY_COPY.backendDecides}
      </div>
    </div>
  );
}

/** A response button that is disabled, with its reasons, when the source is ineligible. */
export function GatedActionButton({
  eligibility,
  onClick,
  children,
  className = 'btn btn--primary',
  busy = false,
}: {
  eligibility: ResponseEligibility;
  onClick: () => void;
  children: ReactNode;
  className?: string;
  busy?: boolean;
}) {
  const reasons = eligibility.reasons.map((reason) => reason.message).join(' ');
  return (
    <button
      type="button"
      className={className}
      onClick={onClick}
      disabled={!eligibility.eligible || busy}
      aria-disabled={!eligibility.eligible || busy}
      title={eligibility.eligible ? undefined : `${reasons} ${ELIGIBILITY_COPY.backendDecides}`}
      data-eligible={eligibility.eligible ? 'true' : 'false'}
    >
      {children}
    </button>
  );
}
