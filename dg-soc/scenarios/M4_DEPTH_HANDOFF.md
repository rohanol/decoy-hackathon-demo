# M4 web-depth implementation handoff

Date: 1 November 2026. Branch: `m4/stateful-web-evidence`.
Base: `d1adbaab41b73295ed05768fe6b1456498d52f96` (integrated main,
including the frontend redesign). Changes are prepared locally for owner review;
no GitHub push, PR, VM deployment or new physical-lab verification is implied.

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
- `decoys/web/observation.py`: bounded request metadata and redaction.
- `decoys/web/sessions.py`: opaque cookie store and lifecycle.
- `decoys/web/assets/manifest.json`: registered local fixtures.
- `decoys/web/README.md`, `requirements-dev.txt`: setup/compatibility boundaries.
- `tests/e2e/test_m4.py`, `test_m4_depth.py`, `smoke_web_container.py`: regression
  and compatibility coverage, with explicit Git Bash selection on Windows.
- `config/web_patterns.yaml`, `contracts/examples/payloads.json`: M4 pattern
  catalogue and corresponding benign examples; Rohan should review the catalogue
  change with the backend consumer before integration.
- `scenarios/web_depth.sh`, `attack_p3.sh`, `demo_p3.md`, `M4_HANDOFF.md` and this
  document: guarded workflow, corrected claims and handoff.

Backend, frontend, response, policy enforcement, deployment, SSH code, shared
event schema/enums and API routes are unchanged. New metadata lives inside the
already extensible v1 `attributes` object and is validated against the current
backend's bounds. Proposed attribute names need reconciliation with M3's new
contract before the coordinated release.

## Cross-owner integration work

### Rohan / M3

- Consume `attributes.input_features` with location/field/value plus observation
  metadata. Existing R07 still sees only URL path/query; M4 does not mislabel body
  features as a URL query to conceal this missing consumer.
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
- Instrument successful SSH notes reads using the pinned release. M4 can prove
  its own web bait service but cannot prove SSH note delivery from command input.
- Agree the canonical trusted policy-revision metadata with M3 and M4. Existing
  block_action_id is preserved; M4 does not invent a revision by rereading policy
  separately and racing the actual enforcement decision.
- Rebuild the web image with the whole decoys/web context. Keep one Gunicorn
  worker; the Dockerfile already copies the new modules/manifest. Preserve current
  mounts and log permissions. Session state resets on worker restart by design.
- Run the revised Docker smoke and physical two-laptop workflow after review.
  Do not mistake the current response verifier for the completed strict tuple.

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
  "asset_id": "backup_env",
  "fixture_version": 1,
  "honeytoken_id": "tok_backup_01",
  "issuance_id": "issue_example",
  "outcome": "served",
  "digest_scope": "full_response"
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
284 passed, 1 warning in 21.99s
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

## Deployment and rollback

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
