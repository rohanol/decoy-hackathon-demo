# M2 collection and response handoff

Branch: `m2/collection-response-proof`
Suggested PR title: `[M2] collection reliability and trustworthy response`

## What this branch provides

- Collector reads complete Cowrie and web JSONL records with inode-aware offsets, restart reconciliation, batching, bounded retries, and SHA-256 source IDs. Raw passwords are hashed and removed.
- Invalid and permanently rejected records are written to `deployment/state/rejected-events.jsonl` as sanitized audit entries before the checkpoint can advance. Batch HTTP 400/413/422 responses quarantine affected events; backend per-record rejection indices are quarantined individually.
- `deployment/state/collector-health.json` updates while sensors are idle and retains the Linux preflight fields. Its `heartbeats` array contains the exact proposed M3 v1.1 request per sensor (`collector_id`, `sensor_id`, `sent_at`, process, read/ingest times, backlog and per-sensor error/rejection/quarantine totals); `heartbeat_results` reports each backend delivery and `heartbeat_api` summarizes delivery independently of event-delivery status.
- Response preview and apply call the authoritative M3 `GET /api/incidents/{incident_id}/response-eligibility`; no IP-only lookup fallback exists. The checks require eligible case status/mode, active live run, allowed exact target, empty rejection reasons and a web observation under 10 minutes old. Apply repeats eligibility and preview run/mode and policy revision checks immediately before writing policy. Verification requires an action ID, web sensor, target peer IP, same active live run, policy revision, backend-persisted event identity, and event/receive times between apply and expiry. Mismatches are stored as M3's capped `verification_rejects` without marking the action verified.
- Startup reconciliation recovers an action when the atomic policy file was written before a crash interrupted action-history persistence. If action history claims an active block that is missing or changed in policy, the action becomes `reconciliation_required` and is auditable.
- Blocklist entries carry the policy revision and recovery metadata needed by the enforcement sensor. The web decoy reads action ID and revision from the same atomic policy snapshot. The directory mount preserves atomic rename visibility.
- Cowrie stays in `backend=shell` emulated mode with the restricted command registry, canned network handlers, private binds and the manual web-only response. The dispatched canned network handler now emits a session-attributed `dgsoc.network.denied` record; the adapter maps it to a `command_input` with `network_attempt_outcome=denied` and `real_execution=false`.
- The current web route already records `synthetic_file_access` after it reads the registered CSV bytes, and records application-policy denials as `blocked_request`. An additive policy-revision field now ties those denials to the exact blocklist entry.

## Rohan integration included for review

`backend/integrations.py` supplies trusted provenance after `db.ingest` commits an event and assigns its backend ID. It calls the verifier with:

```python
on_event(event, {
    "source": "backend_ingest",
    "persisted_event_id": event["event_id"],
    "received_at": event["ingested_at"],  # backend clock, never sensor payload
})
```

Review the trusted callback in `backend/integrations.py`, the response-eligibility and heartbeat API compatibility notes in `contracts/API.md`, and proposed v1.1 field names with Rohan. Keep `/api/response` reachable only from loopback. The web policy bridge change should be reviewed with Prajwal: canonical policy errors now produce 503 while action ID and revision still come from one snapshot.

## Verification performed here

Automated regression tests use temporary state for response mismatches, restart reconciliation, collector rejection quarantine, idle health, sanitized fixtures, policy revision propagation and Cowrie mapping. Run from `dg-soc/`:

```bash
python -m pytest sensors/tests response decoys/policy decoys/ssh decoys/web/test_policy_revision.py deployment/test_lab_checks.py -q
python -m pytest backend/tests -q
```

Not performed in this workspace: Docker image check, real Cowrie event capture, Linux preflight, Kali-to-Laptop-B source-IP test, physical SFTP/SCP and forwarding-channel audit, web block/revoke through the full live stack, or live event ingestion with Rohan's trusted context. Review [`docs/COWRIE_PINNED_EVENT_FIELDS.md`](../docs/COWRIE_PINNED_EVENT_FIELDS.md) and [`docs/M2_LINUX_DEPLOYMENT.md`](../docs/M2_LINUX_DEPLOYMENT.md) before the event.

## Known limits and review notes

- The Cowrie and web fixture files are synthetic and sanitized. They are not physical captures. Add a fresh redacted sample only after the real source-IP probe passes.
- Do not add SSH event mappings unless the pinned image emits and tests that event. SFTP/SCP and forwarding channels are separate from shell command stubs and remain a physical/image audit item.
- Mismatch audit records use a generic reason and persisted event ID; do not copy attacker-supplied secret fields into response audit state.
- This PR includes a narrow additive web-decoy integration so the response verifier receives the policy revision. M4 should review that hunk because `decoys/web/` is M4-owned.
