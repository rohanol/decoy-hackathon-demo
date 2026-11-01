# M4 next-milestone handoff — 1 November 2026

Role: Prajwal/M4. Branch: `m4/next-bait-database`, based on main
`2bfd9e80b7e12e17578bdfdbe74e514c83fe876c`. Runtime commit `85b6492`;
the next commit includes the tests and documentation in this handoff.

## Implemented

- Opt-in web schema 1.2; legacy 1.0/1.1 behavior remains supported. Existing
  Compose is not switched to 1.2 in this PR.
- Original research-portal shell matching M1's visual reference, without
  copying the normal app's credentials or session.
- Inert `/backup/backup.zip`: five fixed regular text/CSV entries, deterministic
  archive/entry digests, token placements and distinct per-serving issuance IDs.
- Request/result/bait records carry one request id. HEAD, denied access and
  log failures do not claim successful bait serving. Transfer completion is
  explicitly unknown; local download/extraction is not inferred.
- Independent verification of M1/M3's signed proxy context, with finite time,
  run/upstream/id/address checks. Unsigned forwarding headers stay untrusted.
- Bounded MySQL protocol-41 emulator, fresh challenges, verifier-only planted
  credential matching, real PyMySQL client compatibility, fixed setup no-ops,
  query refusal, metadata-only native logs, connection/time/packet/log limits.
- Hash-only database/SMB bait registration, R11/R12 rule-summary wording,
  a guarded manual lab scenario and reproducible boundary/browser checks.

M1 still owns demo-app; M2 still owns the gateway, adapter, deployment, SSH and
SMB/file producer. No changes in those paths or the backend/shared contracts.

## Exact interfaces consumed

| Dependency | Commit | Use |
|---|---|---|
| M3 contract, PR #19 | eb2a94e | event schema 1.2, telemetry 1.0, token/ingress/archive/proof fields |
| M3 backend, PR #20 | 6446ca1 | actual HTTP ingest, cases/links, R11, routing and response checks |
| M1, PR #21 | 2a614ef; visual reference 19d1cf1 | normal app and visual/runtime contract |
| M2, PR #22 | c214ff8 | actual gateway routing/affinity checked without modifying it |

The published event schema is copied, unchanged, into a clearly named test
fixture. Tests compare it with the live contract when that contract supports
1.2. It is not installed as the application's active schema or silently passed
to today's adapter.

## Verification actually run

Windows, Python 3.12, installed Edge. No Docker daemon was available.

| Check | Result |
|---|---|
| Full combined regression suite | **662 passed**, one Starlette/httpx deprecation warning, 49.84 s |
| New focused producer tests (included above) | **47 tests**: real PyMySQL, malformed wire, privacy, bounds, ZIP, context, guarded target refusal |
| M3 backend boundary, actual loopback HTTP/protocol | **9 checks**, 36 actual generated producer records accepted |
| Actual M1 app + M2 gateway + M4 decoy | **3 routing/session checks**, two integration gaps retained |
| Installed Edge browser | **6 checks**, actual backup.zip download, zero page errors/external requests, no script execution or mobile overflow |
| Python compilation, Node syntax, scoped whitespace | Passed |

Full regression command (from checkout root):

```text
DG_TEST_BASH=<working Git Bash on Windows>
python -m pytest dg-soc/backend dg-soc/sensors dg-soc/response dg-soc/decoys/policy dg-soc/decoys/ssh dg-soc/decoys/web/test_policy_revision.py dg-soc/decoys/database dg-soc/deployment dg-soc/tests/e2e -q
```

This avoids the unusable WSL bash shim and runs the Bash scenario checks rather
than deselecting them. Install `decoys/database/requirements-dev.txt` as well
as the existing test requirements. PyMySQL is a test/probe dependency only.

The M3 boundary run checks actual ZIP records and deduplication; reference-signed
request correlation; a real MySQL proof linking to the archive; five failed
protocol logins producing R11; analyst confirmation/reversal; a later use with
two eligible static-token issuances staying ambiguous; unsupported DB response
scope; HTTP denial -> direct ingest -> trusted backend verification -> revoke.

These are synthetic loopback observations, not physical captures. Reference
gateway decisions are explicitly synthetic and events are posted directly to
the API, bypassing the currently incompatible adapter. Actual M2 routing is
checked separately and is not passed off as signed-attribution verification.

## Example producer record

Shape below is illustrative; generated receipt files contain actual loopback
records with their own ids/timestamps. No password, challenge or proof is logged.

```json
{
  "schema_version": "1.2",
  "source_record_id": "db_<generated-id>",
  "sensor_id": "db-decoy-01",
  "event_type": "auth_success",
  "occurred_at": "<actual UTC timestamp>",
  "src_ip": "127.0.0.1",
  "src_port": 50000,
  "session_id": "dbs_<generated-reference>",
  "lab_run_id": "mysql-client-test",
  "capture_mode": "live",
  "attributes": {
    "protocol": "mysql",
    "username": "svc_reports",
    "outcome": "emulated_success",
    "honeytoken_id": "tok_db_01",
    "credential": {
      "scheme": "mysql_native_password",
      "proof_check": "matched_honeytoken",
      "verifier_version": "mysqlauth@1"
    }
  }
}
```

## Pending integration, by owner

M2:
1. Adapter currently rejects every 1.2 record with `schema_version`; extend
   validation/mapping/shipping and heartbeat support using M3's contract.
2. Actual gateway sends unsigned X-Forwarded-For/X-Gateway-Session, not the
   agreed X-DG-Gateway-Context. Add signed context and gateway telemetry using
   the same UTF-8 per-run key convention as both upstreams. Do not ask upstreams
   to trust the unsigned headers.
3. Preserve Content-Disposition and appropriate upstream security headers in
   the proxy. The archive works, but the filename header is currently dropped.
4. Integrate database launch/log rotation/collection, and complete the actual
   SMB producer/safety validation. A planted SMB credential is not a service.
5. Wire one-command lifecycle/readiness and run native container/network tests.

M3: land contract/runtime before enabling 1.2 producers; retain current
response_scope and correlation/evidence boundaries. Align AGENTS.md ownership
with the approved assignment: M1 demo app, M2 SMB/file producer, M4 MySQL/web.

M1: wire actual generated records after the above runtime path is available.
Use unknown transfer completion honestly and keep MySQL/SMB response disabled.

Integration order: M3 contract/runtime -> compatible adapter and trusted
gateway/normal app + M4 producers -> live UI -> full native Kali acceptance.
Keep the last working deployment available for rollback.

## Not run / not claimed

Native Docker image builds or service isolation, physical 192.168.77.10 source
proof, actual gateway-signed attribution, updated adapter delivery, live SMB
traffic, complete four-honeypot physical UI flow, or public hosting. No trained
AI model or malware verdict was added. This PR is a tested M4 implementation,
not a declaration that the entire next milestone is deployment-ready.
