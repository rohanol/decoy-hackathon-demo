/**
 * Block flow. DESIGN_SPEC.md section 13.
 *
 * Preview -> approve with a written reason -> watch for verification -> undo.
 *
 * The friction is deliberate. A one-click block is a liability, not a feature:
 * security teams are rightly afraid of automated responses that overreact. The
 * dangerous action takes three steps and a typed justification; the reversing
 * one takes a single click.
 *
 * Every value on screen is read back from the API's response, never echoed from
 * what we sent — if the backend disagrees about the target or the scope, the
 * backend is what gets shown.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ApiError,
  postBlockApply,
  postBlockPreview,
  postBlockRevoke,
  fetchActions,
} from '../api/client';
import { ActionCard } from './ActionCard';
import { ErrorCard } from './primitives';
import { COPY } from '../copy';
import type { BlockPreview, ResponseAction } from '../types/api';

const MIN_REASON = 5;
const DEFAULT_TTL_SECONDS = 120;
/** API.md: `action` is reserved and not pushed, so verification is polled. */
const POLL_MS = 2000;

type Step = 'preview' | 'approve' | 'result';

export function BlockFlowModal({
  incidentId,
  onClose,
  onChanged,
}: {
  incidentId: string;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const [step, setStep] = useState<Step>('preview');
  const [preview, setPreview] = useState<BlockPreview | null>(null);
  const [action, setAction] = useState<ResponseAction | null>(null);
  const [reason, setReason] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const reasonRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const loadPreview = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setPreview(await postBlockPreview(incidentId, DEFAULT_TTL_SECONDS));
    } catch (cause) {
      setPreview(null);
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('preview_failed', 'Could not create a preview.', 0),
      );
    } finally {
      setBusy(false);
    }
  }, [incidentId]);

  useEffect(() => {
    void loadPreview();
  }, [loadPreview]);

  useEffect(() => {
    if (step === 'approve') reasonRef.current?.focus();
  }, [step]);

  useEffect(() => {
    const onKeyDown = (keyEvent: KeyboardEvent) => {
      if (keyEvent.key === 'Escape' && !busy) onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose, busy]);

  /**
   * Poll for verification. The pill flips only when the backend reports
   * `verified`, which means a blocked_request carrying this action id arrived.
   */
  // The callback and the current action go through refs so that neither a new
  // onChanged identity from the parent nor the 1s clock tick can tear down and
  // restart the interval — which would push verification past the next poll
  // every time the component re-rendered.
  const onChangedRef = useRef(onChanged);
  onChangedRef.current = onChanged;
  const actionRef = useRef<ResponseAction | null>(action);
  actionRef.current = action;

  const actionId = action?.action_id ?? null;
  const awaitingVerification = step === 'result' && action?.status === 'applied';

  useEffect(() => {
    if (!awaitingVerification || actionId === null) return;

    let cancelled = false;
    const poll = async () => {
      try {
        const page = await fetchActions();
        if (cancelled) return;
        const fresh = page.items.find((item) => item.action_id === actionId);
        if (fresh && fresh.status !== actionRef.current?.status) {
          setAction(fresh);
          onChangedRef.current?.();
        }
      } catch {
        // A failed poll is not worth tearing the result panel down for.
      }
    };

    void poll();
    const timer = setInterval(() => void poll(), POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [awaitingVerification, actionId]);

  const previewExpiresIn = preview ? Math.max(0, Date.parse(preview.expires_at) - now) : 0;
  const previewExpired = preview !== null && previewExpiresIn === 0;
  const previewSeconds = Math.ceil(previewExpiresIn / 1000);
  const reasonTooShort = reason.trim().length < MIN_REASON;

  async function apply() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const applied = await postBlockApply(preview.preview_id, reason.trim());
      setAction(applied);
      setStep('result');
      onChanged?.();
    } catch (cause) {
      // Never retry automatically: apply changes state, and a double block is a
      // confusing thing to explain on stage.
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('apply_failed', 'The block was not applied.', 0),
      );
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (!action) return;
    setRevoking(true);
    setError(null);
    try {
      setAction(await postBlockRevoke(action.action_id));
      onChanged?.();
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('revoke_failed', 'The block was not revoked.', 0),
      );
    } finally {
      setRevoking(false);
    }
  }

  return (
    <>
      <div className="modal-backdrop" onClick={busy ? undefined : onClose} aria-hidden="true" />
      <div className="modal" role="dialog" aria-modal="true" aria-label="Block flow">
        <header className="modal__head">
          <h2 className="modal__title">
            {step === 'preview' ? 'Preview block' : step === 'approve' ? 'Approve block' : 'Block applied'}
          </h2>
        </header>

        <div className="modal__body">
          {step !== 'result' && preview ? (
            <>
              <div className="kv">
                <span className="kv__k">target</span>
                <span className="kv__v">{preview.target_ip}</span>
                <span className="kv__k">scope</span>
                <span className="kv__v">{preview.scope}</span>
                <span className="kv__k">duration</span>
                <span className="kv__v">{preview.ttl_seconds} s</span>
                <span className="kv__k">preview</span>
                <span className="kv__v">
                  {preview.preview_id} ·{' '}
                  <span className={previewSeconds <= 15 ? 'field__count--short' : ''}>
                    {previewExpired
                      ? 'expired'
                      : `expires in ${Math.floor(previewSeconds / 60)}:${String(previewSeconds % 60).padStart(2, '0')}`}
                  </span>
                </span>
              </div>
              <p className="modal__caveat">⚠ {COPY.blockScopeWarning}</p>
            </>
          ) : null}

          {step === 'approve' ? (
            <>
              <label className="field">
                <span className="label">Reason (required, min {MIN_REASON} characters)</span>
                <textarea
                  ref={reasonRef}
                  className="textarea"
                  rows={2}
                  value={reason}
                  disabled={busy}
                  onChange={(changeEvent) => setReason(changeEvent.target.value)}
                />
                <span
                  className={reasonTooShort ? 'field__count field__count--short' : 'field__count'}
                >
                  {reason.trim().length} / {MIN_REASON}
                </span>
              </label>
              <p className="state__hint" style={{ textAlign: 'left' }}>
                Recorded in the action history.
              </p>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  disabled={busy}
                  onChange={(changeEvent) => setAcknowledged(changeEvent.target.checked)}
                />
                <span>{COPY.blockScopeAck}</span>
              </label>
            </>
          ) : null}

          {step === 'result' && action ? (
            <>
              <ActionCard action={action} onRevoke={() => void revoke()} revoking={revoking} />
              {action.status === 'applied' ? (
                <p className="state__hint" style={{ textAlign: 'left' }}>
                  {COPY.blockAwaitingVerification}
                </p>
              ) : null}
              {action.status === 'verified' ? (
                <p className="modal__verified">
                  A persisted denied request matched this action&apos;s verification checks.
                </p>
              ) : null}
            </>
          ) : null}

          {error ? <ErrorCard error={error} /> : null}

          {step === 'preview' && !preview && !error && busy ? (
            <p className="state__hint">Requesting a preview…</p>
          ) : null}
        </div>

        <footer className="modal__foot">
          <button type="button" className="btn btn--ghost" onClick={onClose} disabled={busy}>
            {step === 'result' ? 'Done' : 'Cancel'}
          </button>
          <span className="toolbar__spacer" />

          {step === 'preview' ? (
            preview === null ? (
              // No preview means no block is possible, so there is nothing to
              // continue to. Offering a dead Continue button would imply there
              // is (DESIGN_SPEC.md §13.1).
              <button type="button" className="btn" disabled={busy} onClick={() => void loadPreview()}>
                {busy ? 'Requesting…' : 'Try again'}
              </button>
            ) : previewExpired ? (
              <button type="button" className="btn btn--primary" onClick={() => void loadPreview()}>
                Preview expired — request a new one
              </button>
            ) : (
              <button
                type="button"
                className="btn btn--primary"
                disabled={busy}
                onClick={() => setStep('approve')}
              >
                Continue
              </button>
            )
          ) : null}

          {step === 'approve' ? (
            <>
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() => setStep('preview')}
              >
                Back
              </button>
              <button
                type="button"
                className="btn btn--primary"
                disabled={reasonTooShort || !acknowledged || busy || previewExpired}
                onClick={() => void apply()}
              >
                {busy ? 'Applying…' : 'Apply block'}
              </button>
            </>
          ) : null}
        </footer>
      </div>
    </>
  );
}
