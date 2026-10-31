/**
 * Screen 7 — Response Center. DESIGN_SPEC.md section 12.
 *
 * Active actions as full cards, finished ones in a compact history table.
 *
 * API.md marks `type: "action"` as reserved and not pushed, so this polls
 * `GET /api/response/actions` — but only while something is actually live.
 * Polling an idle screen forever is just noise.
 *
 * The response router is M2's. Until `response/router.py` exists the backend
 * answers 503 `response_unavailable`, which this surfaces as a plain statement
 * of what is missing and who owns it, rather than as a failure.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { ApiError, fetchActions, postBlockRevoke } from '../api/client';
import { ActionCard, ActionStatusPill } from '../components/ActionCard';
import { Card, EmptyState, ErrorCard, SkeletonRows } from '../components/primitives';
import { timeUtcZ } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import type { ResponseAction } from '../types/api';

const POLL_MS = 2000;

export function ResponseCenter() {
  const { connectionEpoch } = useLiveStore();
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const page = await fetchActions();
      setActions(page.items);
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('actions_load_failed', 'Could not load response actions.', 0),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (connectionEpoch > 0) void load();
  }, [connectionEpoch, load]);

  const active = useMemo(
    () => actions.filter((a) => a.status === 'applied' || a.status === 'verified'),
    [actions],
  );
  const history = useMemo(
    () => actions.filter((a) => a.status === 'expired' || a.status === 'revoked'),
    [actions],
  );

  // Poll only while something is live, and stop once everything is terminal.
  const hasActive = active.length > 0;
  useEffect(() => {
    if (!hasActive) return;
    const timer = setInterval(() => void load(), POLL_MS);
    return () => clearInterval(timer);
  }, [hasActive, load]);

  async function revoke(action: ResponseAction) {
    setRevokingId(action.action_id);
    try {
      await postBlockRevoke(action.action_id);
      await load();
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('revoke_failed', 'The block was not revoked.', 0),
      );
    } finally {
      setRevokingId(null);
    }
  }

  const unavailable = error?.code === 'response_unavailable';

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Response Center</h1>
        <span className="page__head-spacer" />
        {active.length > 0 ? (
          <span className="pill pill--warn">
            {active.length} active action{active.length === 1 ? '' : 's'}
          </span>
        ) : null}
      </div>

      {loading && actions.length === 0 && !error ? (
        <section className="card">
          <SkeletonRows rows={5} />
        </section>
      ) : unavailable ? (
        // Not a failure: a dependency that has not landed yet. Say so plainly.
        <section className="card">
          <div className="state">
            <div className="state__title">Response router not installed</div>
            <div className="state__hint">
              The block flow is owned by M2 (<span className="mono">response/router.py</span>),
              mounted by the backend at <span className="mono">/api/response</span>. Until it
              exists the backend answers{' '}
              <span className="mono">503 response_unavailable</span> and no block can be
              applied.
            </div>
            <div className="state__hint">
              This screen and the block flow are built and work against the fixture backend
              (<span className="mono">VITE_USE_FIXTURES=1</span>), so wiring is the only step
              left once the router lands.
            </div>
            <button type="button" className="btn" onClick={() => void load()}>
              Retry
            </button>
          </div>
        </section>
      ) : error ? (
        <ErrorCard error={error} onRetry={() => void load()} />
      ) : (
        <>
          <Card title={`Active (${active.length})`}>
            <div className="card__body">
              {active.length === 0 ? (
                <EmptyState
                  title="No block applied."
                  hint="A block starts from an incident: open one and use the Block button."
                />
              ) : (
                <div className="actionlist">
                  {active.map((action) => (
                    <ActionCard
                      key={action.action_id}
                      action={action}
                      onRevoke={(target) => void revoke(target)}
                      onExpired={() => void load()}
                      revoking={revokingId === action.action_id}
                    />
                  ))}
                </div>
              )}
            </div>
          </Card>

          <div style={{ marginTop: 'var(--s4)' }}>
            <Card title={`History (${history.length})`}>
              <div className="card__body">
                {history.length === 0 ? (
                  <p className="state__hint" style={{ textAlign: 'left' }}>
                    Finished actions appear here when a block expires or is undone.
                  </p>
                ) : (
                  <table className="breakdown">
                    <thead>
                      <tr>
                        <th scope="col">Target</th>
                        <th scope="col">Status</th>
                        <th scope="col">Reason</th>
                        <th scope="col">Applied</th>
                        <th scope="col">Until</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((action) => (
                        <tr key={action.action_id}>
                          <td className="mono">{action.target_ip}</td>
                          <td>
                            <ActionStatusPill status={action.status} />
                          </td>
                          <td className="breakdown__reason">“{action.reason}”</td>
                          <td className="mono">{timeUtcZ(action.created_at)}</td>
                          <td className="mono">{timeUtcZ(action.until)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </Card>
          </div>

          <p className="graph__note">
            A block covers the web decoy only, for a fixed time, and can be undone at any
            point. The SSH decoy stays reachable. <RouterLink to="/incidents">Incidents</RouterLink>{' '}
            is where one starts.
          </p>
        </>
      )}
    </div>
  );
}
