/**
 * Response action card. DESIGN_SPEC.md section 12.1.
 *
 * The honesty-critical component in the whole app.
 *
 * `VERIFIED` appears only when the API says `verified`. Never inferred, never
 * optimistic, never shown because the apply call returned 200. The difference
 * between "we wrote a blocklist entry" and "we observed the block rejecting a
 * request" is exactly the rigour this project is judged on, so the verified
 * card names the event that proves it and makes it clickable.
 */

import { useEffect, useState } from 'react';
import { ACTION_STATUS_LABEL, ACTION_STATUS_MEANING } from '../copy';
import { timeUtcZ } from '../lib/format';
import type { ActionStatus, ResponseAction } from '../types/api';

const PILL_TONE: Record<ActionStatus, string> = {
  applied: 'pill--warn',
  verified: 'pill--ok',
  expired: '',
  revoked: '',
};

export function ActionStatusPill({ status }: { status: ActionStatus }) {
  return (
    <span className={`pill ${PILL_TONE[status]}`} title={ACTION_STATUS_MEANING[status]}>
      {ACTION_STATUS_LABEL[status]}
    </span>
  );
}

/** mm:ss remaining. The one computed value on screen, and purely cosmetic. */
function useRemaining(until: string, active: boolean): number {
  const [remaining, setRemaining] = useState(() =>
    Math.max(0, Date.parse(until) - Date.now()),
  );
  useEffect(() => {
    if (!active) return;
    const tick = () => setRemaining(Math.max(0, Date.parse(until) - Date.now()));
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, [until, active]);
  return remaining;
}

function mmss(ms: number): string {
  const total = Math.ceil(ms / 1000);
  return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`;
}

export function ActionCard({
  action,
  onRevoke,
  onExpired,
  onOpenEvent,
  revoking,
}: {
  action: ResponseAction;
  onRevoke?: (action: ResponseAction) => void;
  /** Called when the countdown hits zero so the caller can re-fetch. */
  onExpired?: () => void;
  onOpenEvent?: (eventId: string) => void;
  revoking?: boolean;
}) {
  const active = action.status === 'applied' || action.status === 'verified';
  const remaining = useRemaining(action.until, active);
  const ttlMs = Math.max(1, Date.parse(action.until) - Date.parse(action.created_at));
  const pct = Math.max(0, Math.min(100, (remaining / ttlMs) * 100));

  // At zero we ask the caller to re-fetch. We never flip the status ourselves:
  // the backend owns it.
  useEffect(() => {
    if (active && remaining === 0 && onExpired) onExpired();
  }, [active, remaining, onExpired]);

  return (
    <article className={`action action--${action.status}`}>
      <div className="action__top">
        <span className="action__ip mono">{action.target_ip}</span>
        <ActionStatusPill status={action.status} />
        {active ? <span className="action__remaining mono">{mmss(remaining)} remaining</span> : null}
      </div>

      <div className="action__meta mono">
        scope: web-decoy-01 only · ttl{' '}
        {Math.round((Date.parse(action.until) - Date.parse(action.created_at)) / 1000)} s ·{' '}
        {action.action_id}
      </div>

      <div className="action__reason">reason: “{action.reason}”</div>

      <div className="action__meta mono">
        applied {timeUtcZ(action.created_at)}
        {action.verified_by_event_id ? (
          <>
            {' · verified by '}
            {onOpenEvent ? (
              <button
                type="button"
                className="chip"
                onClick={() => onOpenEvent(action.verified_by_event_id as string)}
              >
                {action.verified_by_event_id}
              </button>
            ) : (
              <span className="chip">{action.verified_by_event_id}</span>
            )}
          </>
        ) : null}
      </div>

      {active ? (
        <div className="action__bar" aria-hidden="true">
          <span
            className={remaining <= 30_000 ? 'action__fill action__fill--warn' : 'action__fill'}
            style={{ width: `${pct}%` }}
          />
        </div>
      ) : null}

      {action.status === 'applied' ? (
        <p className="action__note">{ACTION_STATUS_MEANING.applied}</p>
      ) : null}

      {active && onRevoke ? (
        <div className="action__actions">
          {/* No confirmation: the dangerous action takes three steps, the
              reversing one takes none. That asymmetry is deliberate. */}
          <button
            type="button"
            className="btn"
            disabled={revoking === true}
            onClick={() => onRevoke(action)}
          >
            {revoking === true ? 'Undoing…' : 'Undo block'}
          </button>
        </div>
      ) : null}
    </article>
  );
}
