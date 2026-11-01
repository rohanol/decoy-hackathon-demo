# DeceptionGraph Research Portal (`demo-app-01`)

Owner: M1 (Pashmee). The **normal synthetic demo app** behind `gateway-01`
(contract v1.2). Ordinary sessions land here; the gateway sends qualifying
suspicious sessions to `web-decoy-01` instead. This app is **not a honeypot**:
it holds no bait, no honeytokens, no gateway control and no destination
selector. Every person, project, figure and credential is fictional.

## Runtime contract (for M2)

| Item | Value |
|---|---|
| Source identity | `demo-app-01` (frozen in `contracts/sources.json`, v1.2) |
| Stack | Python 3.11, Flask 3.1.2, gunicorn 23.0.0 (same pins as `decoys/web`). No database, no external auth, no internet |
| Command (from `dg-soc/demo-app`) | `gunicorn --bind <host>:8090 --workers 1 --threads 4 "portal.app:create_app()"` |
| Container | `docker build --secret id=proxy_ca,src=<ca bundle> -t dg-demo-app .` (context `dg-soc/demo-app`), then run as built: uid 1000, `CMD` above, `EXPOSE 8090`, built-in `HEALTHCHECK` on `/readyz` |
| Default port | 8090. **Internal only**: publish it to the gateway, never on 192.168.77.20. Participants reach it only through `gateway-01` |
| Readiness | `GET /readyz` → `200 {"ok": true, "source_id": "demo-app-01", "lab_run_id": "<run>"}`. Not logged as telemetry |
| Workers | Exactly 1 worker (threads are fine): it keeps telemetry appends serialised |
| Access log | None. Do not add `--access-logfile`: it would write raw URLs |
| Dev server | `python -m portal` (127.0.0.1:8090, `PORTAL_HOST`/`PORTAL_PORT`); Werkzeug's request log is silenced |

### Environment

| Variable | Required | Meaning |
|---|---|---|
| `LAB_RUN_ID` | yes | Must equal the gateway's run. A context for another run is `invalid / wrong_run` |
| `DG_GATEWAY_CONTEXT_KEY` | for verified contexts | Per-run key, `DGLAB-GWCTX-<64 hex>`, from `deployment/lab.env` only. Never logged. Missing or malformed key: every context header is `invalid / bad_signature` |
| `PORTAL_TELEMETRY_PATH` | no | JSONL output. Default `state/demo-app/app.jsonl` (`/telemetry/app.jsonl` in the image). Mount a writable directory |
| `CAPTURE_MODE` | no | `live` (default) |
| `PORTAL_SECRET_KEY` | no | Signs the portal's own session cookie. Random per process when unset (a restart signs everyone out) |

The container runs with a read-only root filesystem, `--cap-drop ALL` and
`no-new-privileges` (checked: see "Evidence"). It needs one writable mount for
telemetry and `--tmpfs /tmp`.

### Gateway context (contract v1.2, "Gateway trust boundary")

The app verifies `X-DG-Gateway-Context: v1.<payload>.<mac>`:

- `payload` is base64url JSON `{gw_req, gw_sess, client_ip, client_port, run, upstream, iat}`.
- `mac` is base64url HMAC-SHA256 over `v1.<payload>`, keyed with the UTF-8 bytes of `DG_GATEWAY_CONTEXT_KEY`.
- base64url is accepted with or without `=` padding.

**M2:** confirm your gateway uses the same key bytes and encoding. `portal/context.py: sign()` is a reference implementation.

Checks, in order, and the resulting `invalid_reason`:

| Check | Reason if it fails |
|---|---|
| Three dot-separated parts, `v1` prefix, valid base64url | `malformed` |
| MAC (constant-time compare) | `bad_signature` |
| `gw_req` matches `^gw_[A-Za-z0-9_-]{8,64}$`, `gw_sess` matches `^gws_[0-9a-f]{16,64}$` or is null, `client_ip` is IPv4, `iat` is a number | `malformed` |
| `upstream == "demo-app-01"` | `wrong_upstream` |
| `run == LAB_RUN_ID` | `wrong_run` |
| `abs(now − iat) ≤ 30 s` | `expired` |

`verified` means `src_ip` is the context's `client_ip` and the record carries
`gateway_request_id` and `gateway_session_ref`. Otherwise `src_ip` is the TCP
peer and neither id is written. `X-Forwarded-For`, `X-Real-IP` and every other
client header are never read.

### Telemetry output

One `app_request` record per handled request (`telemetry_version` `1.0`,
`contracts/telemetry.schema.json`), one JSON object per line, for M2's
collector to ship to `POST /api/ingest/telemetry`. Every record emitted by the
tests validates against M3's published schema.

Redaction happens **before** the line is written:

- `path` only; `query_redacted` replaces values under keys matching
  pass/pwd/token/secret/key/session/cookie/auth/credential, and any `DGLAB-…`
  value anywhere, with `<redacted>`.
- `login` has `username` and `outcome` (`failed` / `emulated_success`) only.
  No password, hash, cookie, header or body is ever logged.

Example (redacted, from a test run):

```json
{"attributes":{"app_request_id":"app-req-1b65bb37b097","gateway_context":"absent","login":{"outcome":"failed","username":"researcher@example.com"},"method":"POST","path":"/login","route_class":"login","src_ip":"127.0.0.1","status_code":401},"capture_mode":"live","lab_run_id":"run-smoke","occurred_at":"2026-11-01T02:39:10.533Z","record_id":"app-50801a302c843c4f","record_type":"app_request","source_id":"demo-app-01","telemetry_version":"1.0"}
```

## Routes

| Method | Path | Login | `route_class` | Notes |
|---|---|---|---|---|
| GET | `/` | no | page | Home: hero search, quick links, announcements, recent reports |
| GET/POST | `/login` | no | login | Email + password form. Wrong credentials: 401 page. Success: 302 to `/dashboard` (or a same-site `next`) |
| POST | `/logout` | no | login | Clears the session, 302 to `/` |
| GET | `/dashboard` | **yes** (else 302 to `/login`) | page | Greeting, counts, tasks, recently updated reports |
| GET | `/search?q=` | no | page | Searches report titles/abstracts/groups and dataset titles; text is escaped |
| GET | `/reports` | no | page | Report list |
| GET | `/reports/<slug>` | no | page | One of four fixed slugs; anything else 404 |
| GET | `/resources` | no | page | Dataset catalogue (table only; no downloads) |
| GET | `/static/portal.css`, `/static/mark.svg` | no | static | |
| GET | `/readyz` | no | — | Readiness; not logged |
| any | anything else, including `/backup/backup.zip` | — | not_found | Ordinary 404 page. The gateway routes `/backup/backup.zip` to `web-decoy-01` (M4) |

Report slugs: `coastal-sensor-calibration`, `campus-energy-baseline`,
`language-corpus-survey`, `lab-equipment-utilisation`.

## Synthetic accounts (lab only)

| Email | Password | Shown as |
|---|---|---|
| `researcher@example.com` | `DGLAB-Portal-Researcher-2026` | Dr. Asha Verma, Research scientist |
| `analyst@example.com` | `DGLAB-Portal-Analyst-2026` | Rahul Menon, Data analyst |

Only salted PBKDF2-SHA256 hashes are in the code. These are the portal's own
accounts: they are **not honeytokens**, are not planted anywhere, and the portal
accepts no honeytoken. Any other email/password fails with the same response
time and message.

## Visual reference

See `../docs/demo/PORTAL_VISUAL_REFERENCE.md` (colours, layout, navigation,
screenshots) so M4 can keep the decoy side consistent.

## Tests

```bash
cd dg-soc/demo-app
pip install -r requirements-dev.txt
python -m pytest tests -q
```

The tests cover:
- the routes, readiness, login/logout/dashboard, and open-redirect refusal;
- escaping of attacker text;
- no secret reaching disk;
- every telemetry record validating against the published schema;
- verified context with spoofed `X-Forwarded-For` ignored;
- every `invalid_reason`;
- a missing key never trusting a header;
- no gateway, decoy or bait words in participant pages.

`tests/contract/telemetry.schema.json` is a copy of M3's schema from
`m3/next-telemetry-contract` @ `eb2a94e`. The tests fail if
`dg-soc/contracts/telemetry.schema.json` exists and differs.

## Not this app's job

- Routing, pinning, and the bait path are the gateway (M2) and the web decoy (M4).
- Shipping telemetry to the backend is M2's collector.
- Blocking: the web block covers `web-decoy-01` only; this app is never blocked or verified.
