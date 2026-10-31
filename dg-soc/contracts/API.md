# API contract v1.1 (v1.0 compatible)

v1.1 is in review (branch `m3/evidence-boundaries`). The new rules are in **Evidence boundaries (v1.1)** at the end, and the backend implements them in the later PRs listed under Migration.

Compatibility, precisely:
- `schema_version` selects the validation rules. A `"1.0"` event is checked exactly as before; the frozen copy is `contracts/history/event.schema.v1.0.json`, and `backend/tests/test_contracts.py` runs edge cases through both. Every new or stricter rule applies only to `"1.1"` events.
- One semantic difference applies to 1.0 too: a run can no longer mix live and replay events.
- Producers switch to `"1.1"` only after the backend accepts it (PR 2). Until then M4 keeps its v1.1 producer mode disabled.

Backend: `http://127.0.0.1:8000`. All JSON snake_case, timestamps RFC 3339 UTC. Errors: `{"error": {"code": "not_found", "message": "..."}}`. No auth (SOC is loopback only).

## Ingest (adapter only)

`POST /api/ingest/events`

```json
{ "events": [ <event.schema.json>, ... ] }
```

Max 100 events or 1 MiB. Response:

```json
{ "accepted": 3, "duplicates": 1, "rejected": [ { "index": 2, "reason": "src_ip: not an ipv4" } ] }
```

Dedup key `(sensor_id, source_record_id)`. A duplicate is not an error.

v1.1: the dedup key becomes `(ingest namespace, sensor_id, source_record_id)`, and a run cannot mix live and replay. See **Live and replay namespaces**.

## Reads

| Route | Returns |
|---|---|
| `GET /api/events?incident_id=&sensor_id=&since_seq=&limit=200` | `{ "items": [Event], "next_seq": 123 }`. Event = ingest fields + `event_id`, `seq`, `ingested_at`, `incident_id` |
| `GET /api/incidents` | `{ "items": [IncidentSummary] }` newest first |
| `GET /api/incidents/{incident_id}` | `Incident` (below) |
| `GET /api/incidents/{incident_id}/transcript?session_id=` | `{ "session_id", "lines": [ { "event_id", "occurred_at", "kind": "login_failed|login_ok|command|close", "text" } ] }` |
| `GET /api/links` | `{ "items": [Link] }` |
| `GET /api/stats/overview` | `{ "raw_events", "incidents", "low_priority_incidents", "findings_by_rule": {"R01": 2}, "first_alert_seconds": 4.2 }` |
| `GET /api/incidents/{incident_id}/export` | Incident JSON, attachment, no password hashes |
| `GET /api/health` | `{ "ok": true, "sensors": { "ssh-decoy-01": "2026-11-01T05:00:00Z", "web-decoy-01": null } }` last event time per sensor. v1.1 adds `sensor_health`, see **Health** |

IncidentSummary:

```json
{ "incident_id": "inc_01", "src_ip": "192.168.77.10", "lab_run_id": "run-01", "score": 65, "severity": "high",
  "stages_observed": ["credential_attack", "post_access"], "first_seen": "...", "last_seen": "...", "event_count": 42 }
```

Incident = IncidentSummary plus:

```json
{
  "findings": [ <finding.schema.json> ],
  "score_breakdown": [ { "rule_id": "R01", "points": 25, "counted": true, "reason": "first R01" } ],
  "links": [ Link ],
  "sessions": [ { "session_id": "a1b2", "sensor_id": "ssh-decoy-01", "started_at": "...", "commands": 4 } ],
  "summary": { "source": "rules", "text": "...", "cited_event_ids": ["evt_..."] },
  "active_block": null
}
```

Link:

```json
{ "link_id": "lnk_01", "from_event_id": "evt_a", "to_event_id": "evt_b", "from_sensor": "ssh-decoy-01", "to_sensor": "web-decoy-01",
  "kind": "candidate | strong_candidate", "basis": "same src_ip within 5 min | honeytoken tok_portal_01",
  "status": "open | confirmed | rejected", "decided_at": null, "rationale": null }
```

## Analyst actions

`POST /api/links/{link_id}/decision`  body `{ "decision": "confirm" | "reject", "rationale": "min 5 chars" }`. Confirm makes R05 (and R09 if strong_candidate) count. Reversible with another decision.

## Response (router lives in `response/`, mounted by backend at `/api/response`)

| Route | Body | Returns |
|---|---|---|
| `POST /api/response/preview` | `{ "incident_id", "ttl_seconds": 120 }` | `{ "preview_id", "target_ip", "scope": "web-decoy-01 only", "ttl_seconds", "expires_at" }` preview valid 60 s. 400 if target is not an allowed lab IP |
| `POST /api/response/apply` | `{ "preview_id", "reason": "min 5 chars", "confirm": true }` | `{ "action_id", "status": "applied", "until": "..." }` |
| `POST /api/response/{action_id}/revoke` | `{}` | `{ "action_id", "status": "revoked" }` |
| `GET /api/response/actions` | | `{ "items": [ { "action_id", "target_ip", "status": "applied|verified|expired|revoked", "reason", "created_at", "until", "verified_by_event_id" } ] }` |

`verified` means a `blocked_request` event with matching `block_action_id` arrived. The UI shows "verified" only then.

v1.1 tightens both ends: preview and apply require the eligibility check, and verification requires the full tuple. See **Response eligibility and verification**.

Allowed targets: exactly the IPs in `deployment/lab.env` `ATTACKER_IPS` (default `192.168.77.10`). Never `192.168.77.20`, `127.0.0.1`, or a range.

## Blocklist file (response writes, web decoy reads)

`deployment/state/blocklist.json`, written atomically (write tmp, rename). Web decoy mounts it read-only and reads it on every request through `decoys/policy/policy.py: check(ip) -> action_id | None`.

```json
{ "version": 3, "entries": [ { "ip": "192.168.77.10", "action_id": "act_01", "expires_at": "2026-11-01T05:12:00Z" } ] }
```

Expired entries are ignored by `check()`. A blocked request gets HTTP 403 and the web decoy logs a `blocked_request` event with `attributes.block_action_id`.

## WebSocket `/ws/events`

Server pushes after each DB commit:

```json
{ "seq": 124, "type": "event | finding | incident | link | action", "data": { ... } }
```

`data` is the same shape as the REST object (`incident` sends IncidentSummary). Messages arrive in commit order.

`seq` always means the newest event `seq` when the message was sent. How to apply each type:

| `type` | Apply when | How |
|---|---|---|
| `event` | `seq` > the last event `seq` you have | append to the feed |
| `finding` | always | replace the finding with the same `finding_id` (points and `pending_confirmation` change when a link is decided) |
| `link` | always | replace the link with the same `link_id` |
| `incident` | always | replace the summary with the same `incident_id`; if that incident's page is open, re-fetch `GET /api/incidents/{id}` (a rejected link removes its R05 finding, and there is no delete message) |
| `action` | reserved, not sent yet | poll `GET /api/response/actions` for block status |

A `finding`, `link` or `incident` message often has the same `seq` as the event before it, and an analyst decision sends messages without any new event, so never drop those three types by `seq`.

On connect and on every reconnect: open the socket, then load the snapshot (`GET /api/events` for the feed, whose `next_seq` is your last event `seq`, plus `GET /api/incidents` and `GET /api/links`), then apply messages as above.

## Evidence boundaries (v1.1)

Why: the review of 1 Nov 2026 (sections 4, 5, 11-15) showed four places where the data claims more than the evidence. IP plus run joined unrelated activity into one incident (F1). Replay records could mix into live cases and enable a block (F2). A strong token link needed no proof that the bait was ever served (F3). Some ATT&CK IDs were attached to strings alone (F4). This section fixes the meaning of the data first. Producers and screens follow in small PRs.

| Term | Meaning |
|---|---|
| observation | one stored event, never edited after ingest |
| case | the unit the analyst works on, scored on its own. Returned by `/api/incidents` (route name kept) |
| source profile | read-only roll-up of everything one `src_ip` did in one run. Never scored, never proof that one person did it all |
| investigation | a parent case that exists only after the analyst confirms a link between two cases. Combined scoring happens only here |

### Session cases versus source profiles

Each event belongs to exactly one case, assigned by these rules in order:

| Case kind | Key | `grouping_basis` | Gets |
|---|---|---|---|
| `ssh_session` | `sensor_id + session_id + lab_run_id + capture_mode` | `sensor_session` | every SSH event that has a `session_id` |
| `ssh_unsessioned` | `src_ip + lab_run_id + capture_mode`, a new bucket after 5 min without events | `inactivity_5min` | SSH events with no `session_id`; this should be rare |
| `web_session` | `session_id + lab_run_id + capture_mode` once the web decoy issues a session cookie | `sensor_session` | web events with a `session_id` |
| `web_activity` | `src_ip + lab_run_id + capture_mode`, a new bucket after 5 min without events | `inactivity_5min` | web events with no `session_id` (all of them today) |
| `investigation` | created by confirming a link | `analyst_confirmed_link` | no events of its own; it groups two or more child cases |

Rules:

- Two SSH sessions from one IP are two cases. Their scores are separate, and neither becomes critical because of the other (review T01).
- **Password guessing across sessions stays detected.** Hydra opens one session per attempt, so R01 looks at all SSH sessions of one `src_ip + username + lab_run_id + capture_mode` (5+ distinct failures in 60 s). It produces one finding in a `credential_attempts` case. That case has `grouping_basis: "credential_window"`. Its evidence points at the failing sessions' events, but it does not take over those cases or any web activity.
- Sessions that only connected and failed to log in still get their own `ssh_session` case. The case is marked `"quiet": true` while it has no findings. `GET /api/incidents?include_quiet=false` hides quiet cases. The default is `true`, which is the v1.0 behaviour of listing everything.
- An investigation's score is computed over the union of its children's findings: each rule once, R05 and R09 per the existing rules, cap 100. Children keep their own scores. Rejecting or reversing the confirming link dissolves the investigation. Its status becomes `dissolved`, children keep all their events and findings, scores are recomputed, and `summary.stale` becomes `true` until regenerated.
- `GET /api/profiles?lab_run_id=` returns `{ "items": [SourceProfile] }`, and `GET /api/profiles/{src_ip}?lab_run_id=` returns one profile (example in `examples/api_v1_1.json`). A profile is a view. It holds no score and says plainly that one address can be several people (NAT).

New IncidentSummary fields (all v1.1, present on every case): `case_kind`, `grouping_basis`, `sensor_id`, `session_id`, `capture_mode`, `parent_id`, `children`, `status` (`open` or `dissolved`) and `quiet`. `sensor_id` and `session_id` are null for `credential_attempts` and `investigation`. `children` lists case ids for an investigation and is empty for every other kind.

Links now name the cases they join (additive): `from_incident_id` and `to_incident_id`.

### Live and replay namespaces

- A run's mode is fixed by its first accepted event. A later event for that `lab_run_id` with the other `capture_mode` is rejected per record, for example `"reason": "lab_run_id: run run-x is live; replay events need their own run"`. Mixed input therefore can never reach one case (review T02).
- The dedup namespace is `live` for live events and `replay:<lab_run_id>` for replay events. Replaying the same fixture into two replay runs works. Replaying into the same replay run is deduplicated. Replay never touches live dedup.
- Replay events should carry `origin_record_id`, which is the original record's `source_record_id`. Live events must not carry one.
- `GET /api/runs` returns `{ "items": [ { "lab_run_id", "capture_mode", "first_seen", "last_seen", "events", "active" } ] }`. `active` is true for at most one live run: the live run with the newest event, and only if that event is younger than 15 minutes.
- Replay cases are read-only evidence. They never enable a response.

### Request, result and bait evidence

Every event has an `observation_kind`. If a producer omits it, the backend derives it, and `evidence_role` follows from it:

| event_type | derived observation_kind | evidence_role |
|---|---|---|
| connection_open, auth_failure, auth_success, http_request | network_input | request |
| command_input | command_input | request |
| synthetic_file_access | emulated_result | result |
| blocked_request | policy_result | result |
| bait_served | emulated_result | bait |

An `auth_success` on a decoy is still a request record. It shows the decoy accepted a login, and that is all it shows.

A **`bait_served`** event (new) says that the sensor's **own result record** shows it returned content containing honeytokens. Required attributes: `asset_id`, `honeytoken_ids`, `issuance_id` and `evidence_basis`. Recommended: `sha256` with `digest_scope`, `fixture_version`, `issued_expires_at`, and `request_id` for web.

- Web decoy, `evidence_basis: "sensor_response"`: logged by the app when it actually returns `/.env`. It has the same `request_id` as the request record.
- SSH, `evidence_basis: "session_output_log"`: only when the sensor's own recorded output for that session (for example the Cowrie TTY log) contains the bait. That is real result evidence.
- **A command alone is never result evidence.** When the adapter recognises a read of a registered bait asset, such as `cat notes.txt` in `/home/dg_demo`, it tags the `command_input` with `requested_asset_id` and `honeytoken_ids`. It stays a request record with outcome `attempted`. It does not become `bait_served`.
- Bait asset ids are `ssh:/home/dg_demo/notes.txt` (contains `tok_portal_01`) and `web:/.env` (contains `tok_backup_01`). The registry lives with the token list in `config/honeytokens.yaml` (M4) as `bait_assets: [ { asset_id, sensor_id, path, honeytoken_ids, fixture_version } ]`. `fixture_version` is a string such as `"env@1"`.
- Web `session_id` is a non-reusable reference derived by the decoy, never the bearer cookie.

**Input features and processing metadata** (M4, web 1.1). These let the backend classify request bodies without storing values:

- `attributes.input_features = { source, field_count, field_names[≤32], max_value_length, indicators[≤16], truncated }`. `indicators` uses the fixed vocabulary below, computed per decoded field value. Values never appear, sensitive or not.
- `attributes.processing = { parse_status, body_bytes, body_consumed, redaction_version, producer_version }`. `parse_status` is `parsed`, `no_body`, `rejected_too_large`, `unsupported_type` or `malformed`. A missing feature on a body that was not parsed means "not inspected", not "clean". A full-content digest is valid only when `body_consumed` is true.
- The backend owns classification. R07 combines the URL-pattern match with the classes below.

**Indicator semantics** (agreed with M4, 1 Nov). The producer reports what the text contains, honestly; it never drops a quote or a dash to avoid a match. Lexical indicators say a character or word is present and are supporting only: no combination of them creates a class. A class needs a structural indicator, which describes how the pieces sit together. Matching is case-insensitive on the URL-decoded value; "end" means only spaces or dashes follow. Labelled vectors that both sides test against: `examples/input_indicator_vectors.json`.

| Indicator | Kind | Set when the value contains | Class |
|---|---|---|---|
| `sql_quote` | lexical | any `'` or `"` | supporting |
| `sql_keyword` | lexical | a whole word `select`, `union`, `insert`, `update`, `delete`, `drop`, `from`, `where`, `or`, `and` | supporting |
| `sql_comment` | lexical | `--`, `#` or `/*` | supporting |
| `sql_quote_breakout` | structural | a quote that is not between two letters or digits (so not `John's`), then at least one space or `)`, then `union`, `select`, `order by` or `group by`; or such a quote followed directly or after spaces/`)` by `--`, `#` or `/*` at the end | `sqli` |
| `sql_union_select` | structural | `union`, optional `all` or `distinct`, then `select`, separated by spaces or `/**/` | `sqli` |
| `sql_tautology` | structural | `or` or `and`, then two identical literals compared with `=` (`1=1`, `'a'='a'`) | `sqli` |
| `sql_stacked_query` | structural | `;` then `drop table`, `drop database`, `delete from`, `insert into`, `update <word> set`, `truncate table`, `exec`/`execute` or `shutdown` | `sqli` |
| `sql_time_function` | structural | `sleep(`, `benchmark(`, `pg_sleep(` or `waitfor delay` | `sqli` |
| `script_tag` | structural | `<script` | `xss` |
| `event_handler` | structural | `<` then a tag name, then an attribute `on<letters>=` | `xss` |
| `js_scheme` | structural | `javascript:` at the start of the value or after `=`, `"` or `'` | `xss` |
| `path_traversal` | structural | `../` or `..\` | `lfi` |
| `sensitive_file_path` | structural | `/etc/passwd`, `/etc/shadow`, `/proc/self/` or `win.ini` | `lfi` |
| `php_wrapper` | structural | `php://`, `phar://`, `zip://` or `data://` | `lfi` |
| `remote_url_in_param` | structural | a value starting with `http://`, `https://` or `ftp://` | `rfi` |
| `shell_metachar_command` | structural | `;`, `|`, `&&` or a newline, then one of `id`, `whoami`, `uname`, `cat`, `ls`, `wget`, `curl`, `nc`, `bash`, `sh` as a whole word | `cmd_injection` |
| `command_substitution` | structural | `$(` or a pair of backticks | `cmd_injection` |
| `null_byte` | lexical | `%00` or a NUL character | supporting |
| `encoded_payload` | lexical | text that changed when decoded a second time | supporting |

So `John's quarterly report--` sets `sql_quote` and `sql_comment` and no class, while `UNION SELECT name FROM users` sets `sql_union_select` and is `sqli` without any quote. A producer that predates the structural names only ever sends supporting indicators, so it cannot create a false body class; it simply finds nothing in bodies until it is updated.

**Causal token matching** (review section 11, T05 and T06):

1. A token presentation is an event with `attributes.honeytoken_id` on a sensor other than the token's `planted_on`.
2. Eligible servings are every `bait_served` that meets all of these: it lists that token, it is in the same `lab_run_id` and `capture_mode`, its `sensor_id` equals the token's `planted_on`, its `occurred_at` is not after the presentation, and it has not expired.
3. **Exactly one eligible issuance** → a `strong_candidate` link from that `bait_served` event to the presentation, with `attribution: "unique"`. The basis reads, for example, `honeytoken tok_backup_01 served by web:/.env (sensor response)`. The R09 finding has `token_relation: "linked"`.
4. **Several eligible issuances of the same static credential** → the backend cannot know which serving caused the reuse, and it does not pick one.
   - It creates one `strong_candidate` link per distinct source case among them, each with `attribution: "ambiguous"` and `candidate_issuance_ids` listing all of them. `from_event_id` is the newest serving in that case.
   - The R09 finding has `token_relation: "linked"` and `attribution: "ambiguous"`.
   - The analyst can confirm at most one of these links; confirming one does not confirm the others.
   - Per-issuance credentials remove the ambiguity, because each issuance then has its own token.
5. **No serving, but an earlier `command_input` with `requested_asset_id` naming an asset that holds the token** (same run, mode and planted sensor) → a `candidate` link (not strong) with `attribution: "request_only"`. The basis reads `honeytoken tok_portal_01; bait read requested by command, output not recorded`. The R09 finding has `token_relation: "request_only"`, and it scores only if the analyst confirms that link.
6. **Neither** → no link is created and no source event is invented. The R09 finding still appears with `token_relation: "orphan"`, label "Honeytoken tok_x presented; no record of it being served in this run", 0 points, and it is never scored.

Links gain `attribution` (`unique`, `ambiguous`, `request_only` or null for IP/time candidates) and `candidate_issuance_ids` (empty unless ambiguous).

`candidate` links keep their v1.0 meaning (same `src_ip`, both sensors, within 300 s), now also requiring the same run and mode. They are possible evidence only, never proof.

### Corrected mappings (finding v1.1)

| Rule | v1.1 behaviour |
|---|---|
| R01 | T1110.001, status `attempted`. Counts **distinct** `password_sha256` values in the window, so 5 identical retries are not guessing. Spans sessions as above |
| R02 | T1059.004, status `emulated` (input to an emulated shell) |
| R03 | T1083, status `attempted`. Words inside quotes or after `echo` or `printf` do not count (`echo "ls"`, `printf 'find'`) |
| R04 | A web download of a synthetic lure: stage `lure_access`, `technique_id: null`, rationale "synthetic lure retrieved over HTTP; not collection from a local system". T1005 is kept only for a future SSH fake-filesystem read with result evidence |
| R07 | T1190, status `attempted`, only. No T1059.007 for XSS-looking text and no T1105 for a URL in a parameter; `web_attack_class` still says xss or rfi. A trailing `--` on its own is not SQLi |
| R08 | T1595.003, status `attempted`. The hidden-path trigger needs **at least 3 distinct paths** among the 5 requests, because 5 reloads of `/admin` are not wordlist scanning |
| R05, R09 | custom analytics, `mapping: []` |

`mapping_version` starts at `map@2`. Findings created before migration keep their `rule_version` and mapping. Re-running rules on old events creates findings under the new version. Nothing is rewritten in place.

### Response eligibility and verification

`GET /api/incidents/{incident_id}/response-eligibility` (backend, new). Example in `examples/api_v1_1.json`.

The route returns `{ "eligible", "target_ip", "lab_run_id", "capture_mode", "reasons": [ { "code", "message" } ], "last_web_observation_at", "checked_at" }`.

`eligible` is true only if all of these hold:

1. The case is `live`.
2. Its run is the active live run.
3. The case's `src_ip` has a `web-decoy-01` event in that run less than 10 minutes old.
4. The case is not `dissolved`.

Otherwise `reasons` lists every failed check as `{ "code", "message" }`. The codes match M1's `EligibilityReason`:

| Code | Means |
|---|---|
| `replay_data` | the case is replay evidence |
| `no_live_run` | its run is not the active live run |
| `stale_observation` | no fresh web observation |
| `case_dissolved` | the case was dissolved |
| `sensor_not_registered` | reserved for the enforcing-sensor check |

The allowed-IP check stays in `response/` (M2). Preview and apply both call this route, and M2's runtime (PR #8) already does. It fails closed on 404, a missing key, an unparsable time, `checked_at` older than 30 s, or `last_web_observation_at` 10 minutes old or more, and refuses with 409 `not_eligible` or 503 `eligibility_unavailable`. Every key above is always present: `target_ip`, `lab_run_id` and `last_web_observation_at` are null when unknown, never omitted. `checked_at` is the backend clock at the time of the answer. An unknown incident is 404 with the standard error body.

Verification tuple (M2's `on_event`, review T04). An action becomes `verified` only when a `blocked_request` meets all of these:

1. `attributes.block_action_id` equals the action id.
2. `sensor_id` is `web-decoy-01`.
3. `src_ip` equals the action's `target_ip`.
4. `capture_mode` is `live`.
5. `lab_run_id` equals the run recorded at apply.
6. `occurred_at` falls within `[applied_at, until]`.

7. `attributes.policy_revision` equals the action's policy revision.

M2 (PR #8) implements this. The backend calls `on_event(event, trusted_context)` after commit, with `trusted_context = { "source": "backend_ingest", "persisted_event_id", "received_at" }` built by the backend, never from sensor fields.

A mismatch leaves the action unchanged and is appended to the action's `verification_rejects` (M2's runtime name, at most 20 per action), which `GET /api/response/actions` returns and the M1 UI shows as rejected attempts. Each entry is `{ "event_id", "reason" }`.

Agreed `reason` codes, as M2's runtime emits them today:

| Code | Where | Means |
|---|---|---|
| `verification_context_mismatch` | `verification_rejects` | the denied request failed at least one check of the tuple above |
| `active_action_missing_or_changed_in_policy_after_restart` | `verification_rejects`, with status `reconciliation_required` | after a restart the action no longer matches the enforced policy |
| `unknown_action_id` | M2's verification audit file only | a `blocked_request` named an action that does not exist |
| `legacy_verification_mismatch` | `verification_rejects` | migrated from an older `verification_mismatches` entry |

M1 also has labels for finer codes (`wrong_sensor`, `wrong_source`, `replay_mode`, `wrong_run`, `outside_window`, `stale_policy_revision`). They are optional: M2 may later report the first failing check with one of them, and nothing else changes. The old name `verification_mismatches` is retired.

### Health

Collectors (the adapter, M2) post one heartbeat per sensor every 10 s to `POST /api/ingest/heartbeat`. The wire body is exactly what M2's adapter sends today (PR #8, `_heartbeat_payloads`); the backend translates it into M1's `CollectorHealth` names on `GET /api/health`, so neither side renames anything:

```json
{ "collector_id": "adapter-laptop-b", "sensor_id": "ssh-decoy-01", "sent_at": "2026-11-01T04:31:40.120000+00:00",
  "sensor_process": "up", "last_read_at": "2026-11-01T04:31:40.120000+00:00",
  "last_ingest_ok_at": "2026-11-01T04:31:38.900000+00:00", "backlog_lines": 0, "oldest_backlog_age_s": 0,
  "errors_total": 0, "rejected_total": 1, "quarantined_total": 1 }
```

| Wire (M2 sends) | Read (`sensor_health`, M1's `CollectorHealth`) |
|---|---|
| `sensor_process` `up`, `down`, `unknown` | `process_state` `running`, `stopped`, `unknown` |
| (backend receive time) | `heartbeat_at` |
| `last_read_at` | `last_read_at` |
| `last_ingest_ok_at` | `last_ingest_at` (the collector's last successful batch) |
| `backlog_lines` | `backlog_records` |
| `oldest_backlog_age_s` | `oldest_backlog_age_s` |
| `errors_total` | `error_count` |
| `rejected_total`, `quarantined_total` | `ingest.rejected`, `ingest.quarantined` |
| (backend's own counts for that sensor) | `ingest.accepted`, `ingest.duplicate` |
| not sent | `ingest.retry` is null |
| `sent_at` | `clock_skew_s` = `sent_at` minus backend receive time |

The response is `{ "ok": true }`; a body that fails validation is 400 with the standard error body. Unknown keys are rejected, counts are 0 to 10^9, ids are 1 to 64 characters, and `sensor_id` must be a registered sensor. The backend keeps only the latest heartbeat per `(collector_id, sensor_id)`. Heartbeats are stored apart from events and never reach rules, scores or the feed.

`GET /api/health` keeps `ok` and `sensors` (v1.0) and adds `sensor_health.<sensor_id>`:

| Field | Values | Rule |
|---|---|---|
| `service` | `up`, `down` or `unknown` | taken from the latest heartbeat's `process_state` (`running` = `up`, `stopped` = `down`); `unknown` if there is none or it is older than 30 s |
| `collection` | `ok`, `stale` or `never` | `ok` = heartbeat younger than 30 s; `never` = no heartbeat yet |
| `activity` | `recent`, `quiet` or `none` | `recent` = an event in the last 5 min; `quiet` = older; `none` = no events. A quiet sensor is not a broken one |
| `collector_id`, `heartbeat_at`, `process_state`, `last_read_at`, `last_ingest_at`, `backlog_records`, `oldest_backlog_age_s`, `error_count`, `ingest`, `clock_skew_s` | | translated from the latest heartbeat as in the table above; all null if there is none |
| `last_event_at` | | the newest `occurred_at` stored for the sensor; null if none |

`clock_skew_s` is the heartbeat's `sent_at` minus the backend's receive time. An event time in the future never makes a sensor look healthy. `ok` means only that the backend is up.

### Compatibility notes

| Consumer | What changes for it |
|---|---|
| Adapter, M2 | Nothing breaks; heartbeat, `verification_rejects` and the eligibility call already match PR #8. To adopt: accept `schema_version` 1.1 in the adapter's pre-check (today it quarantines anything that is not 1.0, so M4's 1.1 events would never reach the backend); `requested_asset_id` on bait-read commands; `bait_served` only from the session output log |
| Web decoy, M4 | Nothing breaks while it sends 1.0. Aligned for 1.1: `request_id`; a `bait_served` with `sensor_response` when `/.env` is returned; a derived (non-cookie) `session_id`; `input_features` and `processing`; string `fixture_version`; `bait_assets` in `honeytokens.yaml`. Keep the 1.1 producer mode off until PR 2 is merged |
| Frontend, M1 | All v1.0 fields stay. New fields can be ignored at first. Behaviour that changes: the incident list holds more, smaller cases; per-case scores are lower until the analyst confirms a link (the 25→100 demo climb happens on the investigation); R04 shows stage `lure_access`; R07 shows fewer technique ids; R09 can be `orphan` with no link |
| Backend tests | Several v1.0 tests encode the old grouping (one incident per IP). They change on purpose in the implementation PRs, each with a note |

### Migration and rollback

The order follows review section 12. Each step is its own PR with real test output:

1. **This PR**: contract, examples, schema tests, and the gaps reproduced as expected-failure tests.
2. Ingest accepts 1.1 (version-gated validation, `input_features` and `processing` bounded, R07 consuming the indicators), derives `observation_kind`, enforces one mode per run, and adds the dedup namespace and `/api/runs`. DB migration 1 adds columns and a `runs` table. It rebuilds the `events` table once, copying every row unchanged including `seq`, because SQLite cannot drop the old unique key in place. The file is backed up first.
3. Case model: cases, credential window, profiles, investigations and dissolve. DB migration 2 adds `cases`, `case_events` and `investigations`. Cases are **derived**: they are rebuilt from the untouched `events` table.
4. Causal token matching, orphan R09, corrected mappings and rule versions.
5. Eligibility route, health and heartbeat. M2 then wires preview, apply and verification. M4 and M2 emit `bait_served`.

The database records its schema in `PRAGMA user_version`: 0 = v1.0, then 1, 2 and so on. Migrations only add tables and columns. The `events` table is never rewritten.

Before upgrading, the backend copies the file to `backend/data/dg.db.v<old>.bak`.

Rollback:

1. Stop the backend.
2. Restore the `.bak` file.
3. Check out the previous commit.

For a hackathon reset, export the old run (`GET /api/incidents/{id}/export`), then start a new `lab_run_id`. Never replay old live records into a live run; replay them into a `replay-*` run.
