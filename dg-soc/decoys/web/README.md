# M4 stateful web decoy

See [NEXT_MILESTONE.md](NEXT_MILESTONE.md) for opt-in schema 1.2, the inert ZIP,
signed proxy context, MySQL producer integration, actual checks and pending
dependencies. Older implementation-history notes below are not the current
integration status.

The Operations Portal is an isolated synthetic application on port 8080, separate
from the analyst dashboard on 5173. All results are canned. No supplied command,
SQL, file path or URL is executed, queried, opened as a host file or fetched.
The existing reduced Cowrie profile and SOC frontend are unchanged by M4.

## Workflow

- `/` and `/login`: public landing and synthetic form login.
- `/dashboard`: requires the decoy login session.
- `/search`: GET query, POST form or POST JSON `{ "q": "..." }`. Suspicious
  SQL-shaped input selects a fixed fake error; this is not an attack verdict.
- `/download?file=customer_data.csv`: exact registered synthetic asset; requires
  login. Unknown file selectors return 404. HEAD does not claim bytes were served.
- `POST /logout`: revokes the old cookie and returns a fresh anonymous session.
- `/.env`: intentional public credential lure, independent of report protection.
- `/upload`: requires login; accepts UTF-8 `text/plain` via multipart field
  `report`, at most 8 KiB of file content inside the unchanged 16 KiB request cap.
  Logs size and full accepted-file SHA-256, then discards bytes. No file is saved,
  rendered, unpacked, executed or later downloaded. Rejected files have no full
  file digest. The filename is neither a storage path nor logged input.
- Existing `/.git/HEAD`, `/admin`, `/ping` and canned error behavior remain.

The route list does not include an institutional/C-DAC clone: reviewed assets
were not supplied. `assets/manifest.json` registers the local fixtures and access
policy; it does not imply institutional endorsement or a new clone package.

## Sessions

The random `dg_lab_session` cookie is HttpOnly, SameSite=Lax, path `/`, and
deliberately not Secure because the isolated demo uses plain HTTP. This is not a
production identity system. The cookie is never logged. Events use a SHA-256
derived `web_...` reference. Login rotates the cookie; failed login removes any
prior authenticated state; logout, expiry and run changes invalidate access.

State is bounded to 512 process-local sessions, with a 900-second absolute TTL.
Capacity eviction removes the oldest session. Restarting the worker invalidates
sessions and requires login again. Keep the deployed one-worker/four-thread
Gunicorn arrangement. Multiple workers would need a separately designed shared
session store and JSONL serialization; do not silently increase worker count.

## Event compatibility and M3 handoff

The default v1.0 envelope, event enums and current API routes are preserved.
New context is inside existing extensible `attributes`. The opt-in configuration
`WEB_EVENT_SCHEMA_VERSION=1.1` uses PR #9's schema and emits `bait_served`.
Keep the default `1.0` until both the adapter and backend implement v1.1; a draft
JSON Schema accepting records is not proof that ingestion accepts them.

Each request produces `http_request`. Auth and successful file/bait results add
a second semantic record. The pair has one `attributes.request_id`, timestamp,
and session reference, but distinct `source_record_id` values so deduplication
does not collapse it. Records are written together under a single-worker lock.
`X-Request-ID` provides the matching non-secret response reference.

Blocked requests are the exception: only `blocked_request` is emitted, containing
HTTP and policy metadata. An HTTP companion would wrongly feed blocked traffic
back into the existing backend scoring rules. Handlers never run after a block.
Missing/malformed policy and failed logging still return 503.

New attribute context:

| Fields | Meaning |
| --- | --- |
| `request_id`, `session_state` | Request join and synthetic anonymous/authenticated state |
| `previous_session_id`, `session_transition` | Rotation/logout references; no cookie value |
| `input_features` | Source, bounded field names/counts/length and fixed indicators; no values |
| `processing` | Parse status, actual bytes read, whether the complete body was read, producer/redaction versions |
| `body_observation`, `input_truncated` | What was inspected or intentionally suppressed |
| `normalisation_version`, `redaction_version` | Bounded decoding version 1; redaction version 2 |
| `observation_kind` | network_input, emulated_result or policy_result |
| `evidence_kind`, `fixture_version`, `digest_scope` | Registered synthetic result context |
| `issuance_id` | Unique observation of the public backup lure being served |
| `upload_outcome` | accepted_discarded or an explicit rejection reason |

The default `.env` result uses existing `synthetic_file_access`; opt-in v1.1 uses
`bait_served`. Both carry `evidence_kind=bait_served`, asset `web:/.env`,
`honeytoken_ids=[tok_backup_01]`, `evidence_basis=sensor_response`, a unique
issuance observation, string fixture version and `digest_scope=full_asset` over
the complete returned fixture. Served tokens never use `honeytoken_id`, which
is reserved for client presentations. The `bait_assets` registry lives alongside
the existing hashes in `config/honeytokens.yaml`. A HEAD or
blocked request emits no successful bait-service claim. This is a server-side
response observation, not proof of client receipt or human identity.

IMPORTANT INTEGRATION LIMITS:

- Issuance observations do not mint different credentials. Existing synthetic
  credentials remain shared fixtures; they cannot distinguish every NAT client.
- M3 PRs #14–#16 implement cases, causal matching, mapping corrections,
  eligibility and health. These branches are not merged into main yet.
- M2 must instrument the SSH note read and integrate denied channel evidence.
- M3 PR #11 consumes the fixed body indicators for R07. Main's old R07 only
  reads path/query. The decoy does not copy body values into a query string.
- Main still has the old mappings/grouping; do not infer corrected semantics
  merely from this producer's richer metadata.
- The web bridge now supplies `policy_revision` with its action from one validated
  atomic snapshot and fails closed even if an optional M2 checker fails open.
  Preserve this guard when integrating PR #8. The actual current M2/M3 loopback
  response flow passed preview, apply, denial, strict verification and revoke.
- Input hints now match PR #9 at b67c6e6: 14 original names plus five structural
  SQL names. The five lexical hints never establish a class, even in combination.
  Each structure is extracted within one field; fragments from different fields
  cannot manufacture SQL structure. M3 still owns classification and mappings.
- M2 at 29096cf accepts schema 1.1 but its hint allowlist lacks the five structural
  SQL names. Seven of the 27 real producer/API vectors are rejected by its adapter.
  Keep production mode 1.0 until M2 updates the allowlist. M2 heartbeat names also
  differ from M3 ab01a6f: the actual latest heartbeat gets HTTP 400. M1 reads both
  refusal names while M2 currently sends mismatches and M3 documents rejects.

## Input and secret handling

The unchanged 16 KiB request cap is enforced for body-bearing routes, including
unsupported routes and methods. Form parsing is bounded; JSON depth is capped at
4; at most 16 scalar values and a 4 KiB inspection budget are held in memory.
Body values never leave the observation object: only the fixed 19-indicator
vocabulary and bounded names/counts/length are emitted. Payloads still allow at
most 16 hints: overflow is explicitly marked truncated and suppresses free text
and hints. Query capture is capped
at 4 KiB/256 fields. Inspected values and emitted
strings are bounded by ASCII JSON size to remain within backend attribute limits.

Sensitive named values, cookie values, Authorization material and known planted
values are removed before feature extraction/query encoding. Copied secrets in inspected
fields, paths and User-Agent are redacted. No raw body is logged. Bounded percent
decoding is applied for inspection; normalization is versioned, not an unlimited
recursive decoder. Malformed/opaque/oversized/deep/truncated requests suppress
all free-text path/query/header/features when secret discovery is incomplete.
Uploaded content is never used as a feature or retained in logs.

No redactor can identify arbitrary unknown secrets disguised as innocuous data.
The documented boundary is known values and sensitive named/header/cookie input.
Keep this limitation explicit rather than claiming universal secret detection.

Gunicorn access logging stays off; never enable Flask debug mode for the lab.
The direct peer IPv4 address is used; untrusted forwarded headers are ignored.

## Development and tests

From `dg-soc/`, install in a disposable environment:

```bash
python3.11 -m venv /tmp/dg-m4-venv
/tmp/dg-m4-venv/bin/python -m pip install -r requirements.txt -r decoys/web/requirements-dev.txt
/tmp/dg-m4-venv/bin/python -m pytest tests/e2e -q
```

M4 and root test requirements now agree on pytest 9.2.0. On Windows, explicitly
select a functioning Git Bash for refusal tests rather than a broken WSL shim:
set `DG_TEST_BASH` to the full Git Bash executable path. Tests use local clients
and temporary state. Only refusal arguments are executed for scenario scripts.

`test_m4_depth.py` also sends the generated observations through the existing
WebMapper, Pydantic model and FastAPI ingest/storage API and checks deduplication.
That integration disables the response callback: action enforcement has separate
tests, and no real policy files are changed by this producer compatibility test.

Export actual producer output for M1 without starting Docker or generating lab
traffic (choose a new output path; the helper refuses overwrites):

```bash
python tests/e2e/export_m4_records.py --output /tmp/m4-web-v1.jsonl
python tests/e2e/export_m4_records.py --schema-version 1.1 --output /tmp/m4-web-v11.jsonl
```

These are local Flask test clients with a supplied peer address, not physical
source-IP evidence. Each export contains 20 records from two independent clients,
14 request IDs and six session references including login/logout rotations.
The 1.1 export is for direct backend/schema testing until M2 supports ingestion.

## Build and isolated Linux verification

The existing Dockerfile copies this complete build context, including the new
Python modules and fixture manifest. No new runtime dependency was added.

```bash
docker build -t dg-web-decoy:m4 decoys/web
python tests/e2e/smoke_web_container.py
```

The smoke script uses loopback HTTP, maintains the login cookie, and checks
protected download/logout behavior plus existing container restrictions. Build
and run it only on an appropriate local Linux engine. Do not treat this README
as a receipt that a Docker or physical-lab run was performed.

During the actual two-laptop isolated run, use the existing Compose lab bindings,
keep temporary internet disconnected and run preflight. Laptop A may then run:

```bash
bash scenarios/web_depth.sh 192.168.77.20
```

This checks the synthetic workflow without asserting detection scores. Review
source/session/request/result records in the SOC. Existing v1 source-based
incident grouping remains until M3's migration lands.
