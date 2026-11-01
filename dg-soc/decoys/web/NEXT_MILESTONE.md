# M4 web, ZIP and proxy boundary

Baseline: `main` 2bfd9e8. Consumes M3 contract `eb2a94e` (PR #19), backend
`6446ca1` (PR #20), M1 portal/visual reference `2a614ef` / `19d1cf1` (PR #21),
and tests against M2 gateway `c214ff8` (PR #22). These are branch dependencies,
not claims that they have merged. This note supersedes earlier README sections
about pending v1.1 indicator integration, which already landed in main.

## Opt-in and compatibility

The standalone web default remains schema 1.0; existing Compose still selects
1.1. Both retain their old routes/appearance and return 404 for the new ZIP.
Set `WEB_EVENT_SCHEMA_VERSION=1.2` explicitly only after the backend and adapter
support it. Version 1.2 enables `/backup/backup.zip`, ingress metadata, and the
research-portal presentation. `WEB_PORTAL_THEME=research` selects that shell
independently; `WEB_PORTAL_THEME=legacy` retains the older appearance. New
`CAPTURE_MODE` accepts `live`/`replay`; run identity is still `LAB_RUN_ID`.

The shell mirrors M1's original Research Portal visual reference: navy/teal
header, navigation, cards, system fonts and fictional-data footer. It never
copies the normal app's accounts or bearer cookies. Existing `svc_portal` lab
login and the decoy's own session handling remain unchanged. Reports and
resources are canned; participant text is not interpolated into the HTML.

## Archive

The fixed, deterministic ZIP has five regular files: README.txt,
admin-secrets.txt, customer_data.csv, db_settings.txt and share_accounts.csv.
They are UTF-8 plain text/CSV, without paths, symlinks, nested archives,
executables, scripts, auto-run entries or external beacons. The admin note
points to the two credential files. Synthetic credentials are:

| Token | Account | Value (planted bait only) | Valid on |
|---|---|---|---|
| tok_db_01 | svc_reports | DGLAB-DB-Reports-2026 | db-decoy-01 |
| tok_smb_01 | backup_ops | DGLAB-SMB-Backup-2026 | file-decoy-01 |

M2 owns implementation/configuration of the SMB service. Planting its credential
does not mean an SMB service exists. There is no change to Cowrie's userdb.
Hash-only inventory and exact placement are in config/honeytokens.yaml.

A GET returns application/zip and `attachment; filename="backup.zip"`, and
records an http_request, synthetic_file_access and bait_served with one web
request id. The bait record includes archive and per-entry digests, byte sizes,
token ids, a new issuance id and `evidence_basis=sensor_response`. The same
static credential in several prior servings remains ambiguous at later use.

`transfer.completion=unknown`: Flask's after_request prepares the log before
the WSGI server writes the body. There is no bytes_written/body_written claim.
No record proves client receipt, saving, extraction or execution. HEAD emits
only the request, never serving/bait evidence. Denied requests emit only
blocked_request; a logging failure substitutes a 503 HTML response for the ZIP.

## Signed gateway context

In 1.2 the decoy checks X-DG-Gateway-Context against
`DG_GATEWAY_CONTEXT_KEY=DGLAB-GWCTX-<64 lowercase hex>`. Wire format matches
M1/M3: `v1.<base64url JSON>.<base64url HMAC-SHA256>`; MAC covers `v1.<payload>`
and uses the UTF-8 bytes of the entire key string. No hex-decoding of the key.

Payload has exactly gw_req, gw_sess, client_ip, client_port, run, upstream, iat.
Upstream must be web-decoy-01; run must match; iat must be finite and within
30 s; ids and IPv4/port are checked. Duplicate JSON keys and unknown fields
are rejected. Context is a short-lived assertion, not proof of identity; no
global single-use nonce store is claimed.

Only verified context supplies source IP/port and gateway references. Absent
context preserves the actual TCP peer. Invalid context preserves the TCP peer,
records an enum reason without ids and returns 400 after checking policy.
Unsigned X-Forwarded-For, X-Real-IP and X-Gateway-Session are never trusted.
Policy runs on the verified client before handlers, including the ZIP.

## Verified branch integration and remaining gaps

- Actual M1 app + actual M2 gateway + this web decoy, loopback: ordinary traffic
  stays normal; bait request diverts before the normal app handles it; affinity
  holds; an independent session sharing an IP stays normal.
- M2 gateway does not yet emit X-DG-Gateway-Context or gateway telemetry, and
  sends unsigned headers. Our observed ingress therefore stays absent. It
  also drops Content-Disposition, losing the attachment filename header.
- M2 must add signing/telemetry, preserve required response/security headers,
  pass the per-run key to each upstream, and update the adapter for 1.2.
  Do not bypass these gaps by trusting unsigned forwarding headers.
- M1 owns demo-app, M2 owns decoys/files; conflicting ownership notes in M3's
  AGENTS.md should be aligned during integration. M4 has not edited those paths.
- Actual SMB protocol behavior, native container builds, port/source-IP checks,
  egress containment and the physical two-laptop flow remain unverified here.

## Reproduce developer checks

From dg-soc, install existing root/web dev requirements plus
decoys/database/requirements-dev.txt. No services on the physical lab IP are
contacted by these developer checks.

```bash
python -m pytest tests/e2e/test_next_bait.py decoys/database/test_server.py -q
python tests/e2e/check_next_backend.py --backend-root /path/to/m3-runtime/dg-soc --output /tmp/backend-receipt.json
python tests/e2e/check_next_gateway.py --portal-root /path/to/m1/dg-soc --gateway-root /path/to/m2/dg-soc --output /tmp/gateway-receipt.json
```

The backend check uses actual HTTP and MySQL producers, temporary config/DB,
reference-signed synthetic gateway decisions and **direct event ingest**. It
does not certify the adapter or actual gateway attribution. It checks causal
links, repeated failed logins/R11, confirmation/reversal, later-use ambiguity,
unsupported DB response scope and actual HTTP denial -> trusted backend
verification -> revoke.

For browser review, add --serve to the gateway check; it prints loopback URLs.
With Playwright installed, `node tests/e2e/check_next_portal.cjs NORMAL_URL
DECOY_URL OUTPUT_DIR` checks the portal/decoy, actual ZIP download, no executed
script, mobile overflow and external requests. Default browser channel is
installed Edge; set DG_BROWSER_CHANNEL to another installed channel as needed.
Ctrl+C stops those disposable servers.

After the integrated release is ready, on the actual attacker machine only:

```bash
python3 scenarios/next_bait.py 192.168.77.20 --exercise-failures
```

This manually invoked probe requires PyMySQL, verifies the bounded inert ZIP
in memory, attempts its planted DB credential and expects query refusal. It
refuses every non-lab target before network access. It has not been run against
the physical lab in this handoff. Follow with native preflight and SOC checks.
