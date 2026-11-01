# M4 web-depth implementation handoff

Integrated-release note: the adapter/heartbeat mismatches described in this
historical member handoff are resolved in the prototype release. Use
`deployment/PROTOTYPE_RUNBOOK.md` for current startup instructions and
`deployment/PROTOTYPE_RELEASE.md` for integrated verification. Compose now selects
web schema 1.1 after both producer/adapter/backend checks passed.

Date: 1 November 2026. Branch: `m4/stateful-web-evidence`.
Base: `d1adbaab41b73295ed05768fe6b1456498d52f96` (integrated main,
including the frontend redesign). Published for owner review in draft PR #12.
No VM deployment or new physical-lab verification is implied.

## Latest coordination update: M1 e8eef3d, M2 29096cf, M3 ab01a6f

M4 now emits all 19 agreed hint names, including sql_quote_breakout,
sql_union_select, sql_tautology, sql_stacked_query and sql_time_function.
The original lexical SQL hints remain truthful supporting evidence. Each
structural hint is derived within one field, never by joining separate fields.
The fixed 16-hint payload limit still holds: overflow is explicitly truncated.
No body values are logged. Producer version is m4-web@4.

Checks actually run on Windows Python 3.12 / Node 24.16.0:

- Own M4 plus main: 357 passed, one deprecation warning (21.93 seconds).
- Combined current M1/M2/M3/M4: 611 passed, one warning (45.47 seconds).
  Only local integration overlap resolutions and promotion of M4's already-fixed
  trailing-dashes xfail were needed; no expected failures remain in that run.
- All 27 M3-authored vectors match the pure hint extractor. The actual producer
  -> real loopback ingest -> rule engine matches all 27 expected class results.
  The literal encoded vector is decoded by the request pipeline, while the
  standalone extractor vectors describe already-decoded values; neither produces
  a class merely from encoding/quotes.
- M1 npm test now runs all 30 tests on Windows. Independent launcher checks from
  another directory pass; empty and deliberately failing suites both exit 1.
- Actual M4 log -> M2 mapper/sender/checkpoint -> real backend, authoritative
  eligibility -> preview/apply -> M4 denied request -> post-commit verified action
  -> revoke -> allowed request passed. A wrong source stayed pending with
  wrong_source, and replay preview returned 409. This was local test-client
  traffic with temporary policy/database and a loopback backend, not a VM run.

Remaining blockers are now specific compatibility issues, not missing endpoints:
M2's allowlist omits the five structural names (7/27 producer vectors rejected),
and its current process_state/nested-ingest heartbeat is rejected by M3's older
sensor_process/flat-counter model with HTTP 400. Refusal naming crossed again:
M2 emits verification_mismatches while M3 now documents verification_rejects.
Keep WEB_EVENT_SCHEMA_VERSION=1.0 and M1's dual reader until owners align them.
The bait_assets registry is already present in PR #12; no extra registry addition
is needed. M1 still needs to consume authoritative case/health/provenance reads.

The following sections preserve the earlier implementation and test history.

## Coordination update after PRs 8, 9, 10 and 11

The first implementation is preserved in local commit 7cdaade. Subsequent M4
adjustments align with draft PR #9 at 20041a9: string fixture versions,
`digest_scope=full_asset`, registered `web:/.env` / `ssh:/home/dg_demo/notes.txt`
asset IDs and `bait_assets` in honeytokens.yaml. Served credentials use plural
`honeytoken_ids`, not the singular client-presentation field. Auth observations
use the draft network_input/request roles. The bearer cookie remains private;
session_id is its non-reusable derived reference.

Default output remains v1.0. `WEB_EVENT_SCHEMA_VERSION=1.1` is an explicit opt-in
for the future coordinated release, producing the draft bait_served event.
Do not enable it while either current adapter or backend rejects schema 1.1.

The web bridge emits policy_revision from the same validated snapshot as
block_action_id and fails closed independent of optional host policy imports.
M2 at 715b278 has fixed the original canonical fail-open regression and now
requires authoritative eligibility on preview and apply. That backend route is
still pending. Preserve the trusted post-commit callback and both teams' guards.

Latest producer input_features now matches PR #9/#11: an object containing
source, field_count, field_names, max_value_length, indicators and truncated.
No body values are emitted. Processing reports parse_status, bytes actually read,
body_consumed and string producer/redaction versions. The 14 indicators are
lexical evidence; M3 owns their class mapping, confidence and ATT&CK labels.

Fresh M4 validation: 302 passed, 1 Starlette/httpx deprecation warning (Windows
Python 3.12, explicit Git Bash). See the separate integration review for actual
combined-branch receipts. M2 at 715b278 still rejects schema 1.1; keep producer
mode 1.0 even after backend PR #11 merges until adapter support is delivered.

## What changed

1. Bounded anonymous/authenticated synthetic sessions; login rotation, failed-login
   deauthentication, logout, absolute expiry and run isolation. Cookie values are
   not logged. Storage is process-local, 512 sessions/900 seconds, matching the
   existing single-worker deployment; restart requires a fresh login.
2. Authenticated `/dashboard` and fixed CSV download. The public `.env` lure is
   explicitly independent from report access. An asset manifest records the
   synthetic CSV digest/version/access policy and the generated environment bait.
3. GET/form/JSON search observation, including rejected methods and unknown
   routes. Capture is bounded and redacted before output; malformed/deep/opaque/
   oversized inputs suppress free text rather than leaking undiscovered secrets.
4. Existing v1 HTTP and semantic auth/file observations share request/session
   references but use distinct record IDs. Blocked traffic emits only the existing
   blocked_request type to stay out of old HTTP scoring paths.
5. Actual `.env` GET responses produce synthetic_file_access with explicit
   bait_served evidence, issuance observation ID, token/asset ID, fixture version,
   size and full-response hash. HEAD and blocked access do not produce this proof.
6. Authenticated UTF-8 plain-text uploads: at most 8 KiB inside the unchanged
   16 KiB request cap. Accepted bytes receive a complete-file digest and are
   discarded; rejected bytes do not receive a claimed full-file hash. Content
   and filenames are not rendered, stored or used as a host path.
7. Pattern catalogue v2 removes the standalone trailing-comment SQLi match.
   Four benign punctuation examples were added alongside existing positive cases.
   No backend rule engine, mapping or scoring code was changed by M4.
8. Updated workflow/scenario documentation, cookie-aware container smoke script,
   non-destructive demo preparation and a guarded `web_depth.sh` lab probe.
   Root and web development requirements now agree on pytest 9.2.0.

## Files and ownership

- `decoys/web/app.py`: routes, sessions, policy-first lifecycle and event output.
- `decoys/web/policy_bridge.py`: same-snapshot revision and fail-closed enforcement.
- `decoys/web/observation.py`: bounded request metadata and redaction.
- `decoys/web/sessions.py`: opaque cookie store and lifecycle.
- `decoys/web/assets/manifest.json`: registered local fixtures.
- `decoys/web/README.md`, `requirements-dev.txt`: setup/compatibility boundaries.
- `tests/e2e/test_m4.py`, `test_m4_depth.py`, `smoke_web_container.py`: regression
  and compatibility coverage, with explicit Git Bash selection on Windows.
- `tests/e2e/export_m4_records.py`: offline local-client producer samples for M1;
  refuses overwrite and does not contact either lab VM.
- `config/web_patterns.yaml`, `contracts/examples/payloads.json`: M4 pattern
  catalogue and corresponding benign examples; Rohan should review the catalogue
  change with the backend consumer before integration.
- `config/honeytokens.yaml`: additive bait_assets registry, existing token hashes
  unchanged.
- `scenarios/web_depth.sh`, `attack_p3.sh`, `demo_p3.md`, `M4_HANDOFF.md` and this
  document: guarded workflow, corrected claims and handoff.

Backend, frontend, response, policy enforcement, deployment, SSH code, shared
event schema/enums and API routes are unchanged. New metadata lives inside the
already extensible v1 `attributes` object and is validated against the current
backend's bounds. Proposed attribute names need reconciliation with M3's new
contract before the coordinated release.

## Cross-owner integration work

### Rohan / M3

- PR #11 consumes the fixed indicators without body values. Review benign text
  containing both apostrophes and comment punctuation: lexical hints do not
  independently establish SQL structure. Main's R07 still reads URL path/query.
- Use actual served bait endpoints for causal matching. Existing planted_lookup
  still selects generic earlier source-sensor events. The new evidence does not
  automatically repair that lookup.
- Correct R04/R07 technique mappings. The old R04 still attaches T1005 to any
  served synthetic file, including the explicit backup bait result.
- Integrate source/session/approved-parent semantics and isolate replay. Current
  backend remains one incident per IP/run, despite now receiving web session IDs.
- Review the extended attributes and pattern catalogue v2. No top-level schema or
  new event type was added independently. Request/semantic pairs are not duplicate
  records: preserve their distinct source_record_id values.

### Vedant / M2

- Preserve complete v1 web observations and nested attributes in the adapter;
  the current mapper already passes them through, verified by an API test.
- Add version-gated 1.1 validation and bait_served before enabling the producer.
  Align heartbeat names and verification refusal fields with M3's latest draft.
- Instrument successful SSH notes reads using the pinned release. M4 can prove
  its own web bait service but cannot prove SSH note delivery from command input.
- Consume canonical policy_revision, now read with the enforced action in one
  validated snapshot. Never replace it with a second read of policy state.
- Rebuild the web image with the whole decoys/web context. Keep one Gunicorn
  worker; the Dockerfile already copies the new modules/manifest. Preserve current
  mounts and log permissions. Session state resets on worker restart by design.
- Run the revised Docker smoke and physical two-laptop workflow after review.
  The strict tuple is implemented; the full live response needs the missing
  backend eligibility route and Linux validation.

### Pashmee / M1

- Existing top-level session_id is now non-null for allowed web interactions.
  Request/result joins use attributes.request_id and previous_session_id tracks
  rotations. Outcome evidence is inside attributes; source_record_id is distinct
  for each semantic observation.
- Show bait serving, token use and proposed relation as different evidence.
  Issuance observations use static shared fixture credentials, not dynamic unique
  per-client secrets. No human-identity or NAT disambiguation claim is justified.
- Upload records currently remain HTTP observations with upload_outcome and
  digest_scope metadata until the shared event vocabulary is extended.

## Example workflow and compatible shapes

One successful form login produces two v1 records: http_request and auth_success.
Both have the same request_id/session_id; only the auth record has the password
digest/token metadata. Its previous_session_id references the anonymous session.
No event_id or incident_id is invented by the sensor.

One successful `.env` GET produces an HTTP record plus a synthetic file result.
An illustrative attributes subset for that result is:

```json
{
  "request_id": "req_example",
  "observation_kind": "emulated_result",
  "evidence_kind": "bait_served",
  "asset_id": "web:/.env",
  "fixture_version": "1",
  "honeytoken_ids": ["tok_backup_01"],
  "evidence_basis": "sensor_response",
  "issuance_id": "issue_example",
  "outcome": "served",
  "digest_scope": "full_asset"
}
```

This is a partial illustrative shape, not a captured physical event or a complete
ingest envelope. Actual output also contains size/digest, HTTP metadata, versions
and the required existing envelope fields.

## Verification actually run

Runtime: disposable Windows Python 3.12 environment. Flask 3.1.2; root backend
requirements plus web requirements-dev installed. No original VM state used.

```text
python -m pytest backend sensors response decoys/policy decoys/ssh deployment tests/e2e -q
302 passed, 1 warning in 23.49s
```

Set DG_TEST_BASH to the functioning Git Bash executable on this Windows host.
All four scenario scripts are tested only with refusal arguments: no arguments,
loopback, a non-lab domain and an extra argument. The allowed attack target was
not exercised. The first web-only attempt used the broken WSL bash shim and had
12 launcher failures; after making the shell path explicit, the full suite above
passed. These were launcher failures, not silently discarded scenario failures.

Additional checks: `bash -n` on all four scripts, Python compile checks,
`git diff --check`, and `pip check` passed. The first dependency setup exposed
conflicting pytest pins (root 9.2.0 versus web-dev 8.4.2); aligning the M4 dev pin
resolved it. No runtime dependency was added. The remaining test warning is a
Starlette/httpx TestClient deprecation, not a failed case.

The new tests validate real generated events with JSON Schema and the existing
Pydantic model. An in-process WebMapper -> FastAPI -> SQLite test accepted all
generated records with no rejections and deduplicated their second submission.
This producer compatibility test disables response callbacks and does not prove
strict action verification. No external HTTP, scan or real command execution
occurs in the component checks.

NOT RUN: Linux Python 3.11 suite, rebuilt Docker image, revised Docker smoke,
real browser/VM end-to-end acceptance, physical route/packet isolation, real
response/revoke workflow. The local Docker daemon is unavailable. These need
the reviewed integration release and Vedant's native Linux engine.

## Combined local integration receipt (1 November 2026)

Tested M2 715b278, M3 contract 20041a9 + ingest a61867c, M1 8bd3cba,
plus this M4 implementation in a separate worktree. No remote merges or deployment.
Three overlap resolutions are needed: API.md keeps both owners' notes (which still
disagree on refusal fields), web app.py/policy_bridge.py retain M4 sessions and
M2's same-snapshot action/revision semantics. This worktree deliberately removes
the stale strict xfail on benign trailing dashes; M3 should do that on its branch.

- Full combined Python suite: 432 passed, 6 xfailed, one deprecation warning in
  35.96 seconds. The initial run was 415 passed, 6 xfailed and one strict XPASS
  because M4 already fixed the trailing-dash gap; it was not a broken detector.
- M1 unit tests: 30 passed using explicit file arguments on Node 24.16.0.
  npm test alone ran zero tests on this Windows host because of its quoted glob.
- M1 typecheck + production build passed; Vite reports an existing large chunk.
- Actual generated default 1.0 and opt-in 1.1 records: 20 per mode passed the new
  schema/Pydantic and direct API ingest; each second submission was 20 duplicates.
  All 1.0 records passed M2 validate(); all 1.1 records failed schema_version.
- M1's browser filter test passed against generated 1.0 records: 20 rows, six
  session references, request filter and run/mode filter, no page errors. A
  separate check showed the shared login request/result pair as exactly two rows.
- Direct 1.1 API -> M1 browser check: 20 rows, two 'bait served' fallback labels,
  no page errors. This bypasses M2 and does not justify enabling producer 1.1.
  Browser checks used installed headless Edge because Playwright Chromium was
  absent. First v1.1 assertion used an underscore instead of the actual fallback's
  space; correcting the selector passed. No frontend source was changed.
- New body-mapping probes: apostrophe + trailing comment punctuation is still
  a false positive, and UNION SELECT without a quote is missed by PR #11's
  indicator mapping. Both require M3's mapping review and regressions.
- Eligibility and heartbeat routes return 404; M2/M3 heartbeat and verification
  refusal field names still differ. No full live response success is claimed.

## Deployment and rollback procedure

Use a reviewed commit/branch and preserve the existing VM backup, lab.env,
logs/database and Cowrie mounted-file permissions. Do not overlay an unreviewed
ZIP onto the live VM or include old dependencies/state in the code package.

Build/download with decoys stopped, then disconnect temporary NAT before starting
them. Rebuild only the web decoy image when incorporating this M4 change; do not
repin Cowrie or replace deployment settings. Keep the backend/adapter/frontends
on agreed compatible versions. Test current backend compatibility first, then
the new M2/M3 contract once it lands.

Run full component checks, revised loopback Docker smoke, preflight, and a fresh
source-IP probe from Laptop A. `web_depth.sh 192.168.77.20` checks public versus
protected access, cookies, form/JSON observations and logout. Inspect actual
request/session/results in the dashboard and preserve the run evidence.

Rollback means return to the prior reviewed web code/image, preserving logs and
database. No DB migration is introduced by M4. Users must log in again after a
web worker restart. Do not reset the whole project or erase prior evidence.

## Remaining dependencies

Reviewed C-DAC-style clone assets were not provided, so no clone was invented or
copied from an external service. Shared-contract final names, causal matching,
live/replay response restrictions, trusted revision verification, SSH read proof
and independent collector health remain the other owners' integration work.
These limitations must remain visible in the demo and subsequent release review.
