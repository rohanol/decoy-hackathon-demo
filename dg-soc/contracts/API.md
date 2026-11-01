# API contract v1.2 (v1.0 and v1.1 compatible)

v1.2 adds two honeypots, the HTTP gateway and the normal demo app: see **Four honeypots, gateway and telemetry (v1.2)** at the end. The integrated prototype implements v1.1. The rules are in **Evidence boundaries (v1.1)** below; the Migration section records the staged implementation history.

Compatibility, precisely:
- `schema_version` selects the validation rules. A `"1.0"` event is checked exactly as before; the frozen copy is `contracts/history/event.schema.v1.0.json`, and `backend/tests/test_contracts.py` runs edge cases through both. Every new or stricter rule applies only to `"1.1"` events.
- One semantic difference applies to 1.0 too: a run can no longer mix live and replay events.
- The integrated adapter and backend accept `"1.1"`, including all structural input indicators. Compose selects web producer 1.1; the app's standalone default remains 1.0 for compatibility.

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
| `GET /api/response/actions` | | `{ "items": [ { "action_id", "target_ip", "status": "applied|verified|expired|revoked|reconciliation_required", "reason", "created_at", "until", "verified_by_event_id", "verification_mismatches": [] } ] }` |

The M2 response router consumes M3's proposed v1.1 `GET /api/incidents/{incident_id}/response-eligibility` on both preview and apply. A missing, malformed or unavailable eligibility document fails closed; the IP-only incident detail route is not a fallback. `eligible` must be true with no `reasons`, the case mode and run must match the active live context, the target must be an allowed exact attacker IP, and the last web observation must be less than 10 minutes old. Apply repeats the check immediately before writing policy. The backend eligibility decision includes case status (a dissolved case is ineligible).

`verified` means a `blocked_request` event with matching `block_action_id` arrived. The UI shows "verified" only then.

v1.1 tightens both ends: preview and apply require the eligibility check, and verification requires the full tuple. See **Response eligibility and verification**.
For provenance, the enforcing web decoy adds `attributes.policy_revision` to a denied request. The
response verifier also checks `sensor_id=web-decoy-01`, the exact target `src_ip`, `lab_run_id`,
`capture_mode=live`, event and backend receive times within the action interval, and the action's
policy revision. The backend integration calls `on_event(event, trusted_context)` only after commit,
where `trusted_context` is backend-created: `{ "source": "backend_ingest", "persisted_event_id": event["event_id"],
"received_at": event["ingested_at"] }`. Never build this context from sensor payload fields. A mismatch is
retained in `verification_mismatches` (at most 20 `{ "event_id", "received_at", "sensor_id", "src_ip", "capture_mode", "reason" }` records per action) and does not verify the action. Reasons use M1's shared codes: `wrong_sensor`, `wrong_source`, `replay_mode`, `wrong_run`, `outside_window`, `stale_policy_revision`, or `duplicate`. Unknown action IDs are written to the separate verification audit with reason `unknown_action`.

Collector heartbeat integration follows the current M3 `POST /api/ingest/heartbeat` body in PR #11:

```json
{ "collector_id": "adapter-laptop-b", "sensor_id": "ssh-decoy-01", "sent_at": "...",
  "process_state": "running", "last_read_at": "...", "last_ingest_at": "...",
  "backlog_records": 0, "oldest_backlog_age_s": 0, "error_count": 0,
  "ingest": { "accepted": 412, "duplicate": 3, "rejected": 1, "quarantined": 1, "retry": 1 } }
```

The adapter keeps `deployment/state/collector-health.json` for Linux preflight and stores the exact per-sensor request payloads under `heartbeats`, with delivery results in `heartbeat_results`; backend heartbeat delivery is reported separately from event-delivery health.

Allowed targets: exactly the IPs in `deployment/lab.env` `ATTACKER_IPS` (default `192.168.77.10`). Never `192.168.77.20`, `127.0.0.1`, or a range.

## Blocklist file (response writes, web decoy reads)

`deployment/state/blocklist.json`, written atomically (write tmp, rename). Web decoy mounts it read-only and reads it on every request through `decoys/policy/policy.py: check(ip) -> action_id | None`.

```json
{ "version": 3, "entries": [ { "ip": "192.168.77.10", "action_id": "act_01", "expires_at": "2026-11-01T05:12:00Z", "policy_revision": 3, "created_at": "2026-11-01T05:10:00Z", "lab_run_id": "run-01", "capture_mode": "live" } ] }
```

Expired entries are ignored by `check()`. A blocked request gets HTTP 403 and the web decoy logs a `blocked_request` event with `attributes.block_action_id` and the entry's `policy_revision`, read from the same policy snapshot.

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
| `ssh_session` | `sensor_id + session_id + src_ip + lab_run_id + capture_mode` | `sensor_session` | every SSH event that has a `session_id` |
| `ssh_unsessioned` | `src_ip + lab_run_id + capture_mode`, a new bucket after 5 min without events | `inactivity_5min` | SSH events with no `session_id`; this should be rare |
| `web_session` | `sensor_id + session_id + src_ip + lab_run_id + capture_mode` once the web decoy derives a session reference | `sensor_session` | web events with a `session_id`; no time split inside a session |
| `web_activity` | `sensor_id + src_ip + lab_run_id + capture_mode`, a new bucket after 5 min without events | `inactivity_5min` | web events with no `session_id` (all of them today) |
| `credential_attempts` | `src_ip + username + lab_run_id + capture_mode` | `credential_window` | no events of its own; holds R01 only |
| `investigation` | created by confirming a link | `analyst_confirmed_link` | no events of its own; it groups two or more child cases |

Rules:

- Two SSH sessions from one IP are two cases. Their scores are separate, and neither becomes critical because of the other (review T01).
- **Password guessing across sessions stays detected.** Hydra opens one session per attempt, so R01 looks at all SSH sessions of one `src_ip + username + lab_run_id + capture_mode` (5+ distinct failures in 60 s). It produces one finding in a `credential_attempts` case. That case has `grouping_basis: "credential_window"`. Its evidence points at the failing sessions' events, but it does not take over those cases or any web activity.
- Sessions that only connected and failed to log in still get their own `ssh_session` case. The case is marked `"quiet": true` while it has no findings. `GET /api/incidents?include_quiet=false` hides quiet cases. The default is `true`, which is the v1.0 behaviour of listing everything.
- `src_ip` is part of the session key only as a guard: a session never changes address, so a reused id from another address is another case. The 5-minute gap is `windows.case_inactivity_seconds` in `config/scoring.yaml`.
- R01 runs only in `credential_attempts` cases, never in a session case, so one guessing burst is counted once.
- Candidate links (same `src_ip`, both sensors, within 300 s) now join two cases: at most one candidate per pair of cases, from their earliest qualifying pair of events. An SSH session that never logged in is not linked, because a one-attempt Hydra session holds no activity to compare.
- R05 belongs to the investigation, never to a child, so confirming a link cannot raise a child's own score. A child's R09 still counts once its strong link is confirmed.
- An investigation's score is computed over the union of its children's findings plus its own R05 findings: each rule once, R05 and R09 per the existing rules, cap 100. Children keep their own scores. A second confirmed link that shares a child joins the same investigation (two open investigations that come to share a child are merged into the older one). An investigation stands while at least one of its links is confirmed; its children are the cases those links join. Rejecting or reversing the confirming link dissolves the investigation. Its status becomes `dissolved`, its score 0, `children` keeps the last membership for the audit trail, children lose `parent_id` and keep all their events and findings, and scores are recomputed. Confirming a link again re-opens the same investigation. `summary.stale` is reserved for a cached summary; today the summary is regenerated on every read, so it is always `false`.
- `GET /api/profiles?lab_run_id=` returns `{ "items": [SourceProfile] }`, and `GET /api/profiles/{src_ip}?lab_run_id=` returns one profile (example in `examples/api_v1_1.json`). A profile is a view. It holds no score and says plainly that one address can be several people (NAT).

New IncidentSummary fields (all v1.1, present on every case): `case_kind`, `grouping_basis`, `sensor_id`, `session_id`, `capture_mode`, `parent_id`, `children`, `status` (`open` or `dissolved`; `superseded` only on pre-migration rows, which the list hides) and `quiet`. For an investigation, `first_seen`, `last_seen` and `event_count` cover its children; `GET /api/events?incident_id=`, `sessions`, the transcript and the export read the children's events. `sensor_id` and `session_id` are null for `credential_attempts` and `investigation`. `children` lists case ids for an investigation and is empty for every other kind.

Links now name the cases they join (additive): `from_incident_id` and `to_incident_id`.

### Live and replay namespaces

- A run's mode is fixed by its first accepted event. A later event for that `lab_run_id` with the other `capture_mode` is rejected per record, for example `"reason": "lab_run_id: run run-x is live; replay events need their own run"`. Mixed input therefore can never reach one case (review T02).
- The dedup namespace is `live` for live events and `replay:<lab_run_id>` for replay events. Replaying the same fixture into two replay runs works. Replaying into the same replay run is deduplicated. Replay never touches live dedup.
- Replay events should carry `origin_record_id`, which is the original record's `source_record_id`. Live events must not carry one.
- `GET /api/runs` returns `{ "items": [ { "lab_run_id", "capture_mode", "first_seen", "last_seen", "last_ingested_at", "events", "legacy_mixed", "active" } ] }`, newest first.
  - `active` is true for at most one live run: the run that received the newest live event (by `seq`), and only if that event reached the backend less than 15 minutes ago.
  - `legacy_mixed` is true only for runs that already mixed modes before the v1 migration.
- Event reads (`GET /api/events`, WebSocket `event`) add `schema_version` (as sent), `ingest_namespace`, `origin_record_id`, `observation_kind` and `evidence_role`. The derived fields sit next to `attributes`; the producer's attributes are stored as sent. `GET /api/events` also filters by `lab_run_id` and `capture_mode`.
- IncidentSummary adds `capture_mode`, taken from the run.
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

Runtime notes (PR 4):

- One token link per token, source case and presenting case. The first presentation of a token in a case stands for that case.
- Token links are re-derived when a serving or a bait-read request arrives, even after the presentation it explains (ingest order is not event order). A later eligible serving can turn a `unique` link into `ambiguous`. A decision already made on the link is kept.
- Step 5 needs M4's `bait_assets` registry in `config/honeytokens.yaml`. Until it is there, a bait-read command matches nothing and the use stays an orphan. Only schema 1.1 commands carry `requested_asset_id`.
- R09 lists the serving (role `bait`) or the request (role `request`) and the presentations (role `presentation`) in `evidence_event_ids` and `evidence_roles`. An orphan R09 has `points: 0`, `pending_confirmation: false` and the breakdown reason "R09 orphan: no record of the token being served; shown, never scored".
- Strong links made before PR 4 (by IP and time, not by a serving) are kept with their decisions as history, `attribution` null. They no longer make R09 count; a confirmed one still stands for its investigation and R05.

`candidate` links keep their v1.0 meaning (same `src_ip`, both sensors, within 300 s), now also requiring the same run and mode. They are possible evidence only, never proof.

### Corrected mappings (finding v1.1)

| Rule | v1.1 behaviour |
|---|---|
| R01 | T1110.001, status `attempted`. Counts **distinct** `password_sha256` values in the window, so 5 identical retries are not guessing. A failure without a hash cannot be shown to repeat another, so it counts as distinct. Spans sessions as above |
| R02 | T1059.004, status `emulated` (input to an emulated shell) |
| R03 | T1083, status `attempted`. Words inside quotes or after `echo` or `printf` do not count (`echo "ls"`, `printf 'find'`) |
| R04 | A web download of a synthetic lure: stage `lure_access`, `technique_id: null`, status `emulated`, rationale "synthetic lure retrieved over HTTP; not collection from a local system". A `synthetic_file_access` from the SSH decoy keeps T1005, status `emulated`, stage `data_access` |
| R07 | T1190, status `attempted`, only. No T1059.007 for XSS-looking text and no T1105 for a URL in a parameter; `web_attack_class` still says xss or rfi. A trailing `--` on its own is not SQLi |
| R08 | T1595.003, status `attempted`. The hidden-path trigger needs **at least 3 distinct paths** among the 5 requests, because 5 reloads of `/admin` are not wordlist scanning |
| R05, R09 | custom analytics, `mapping: []` |

Every finding carries `mapping`, `mapping_version` and `evidence_roles`; `technique_ids` is derived from `mapping`, so the two never disagree. Rule versions after PR 4: R01@3, R02@2, R03@3, R04@2, R07@5, R08@3, R09@2. `mapping_version` starts at `map@2`. Findings created before migration keep their `rule_version` and mapping. Re-running rules on old events creates findings under the new version. Nothing is rewritten in place.

### Response eligibility and verification

`GET /api/incidents/{incident_id}/response-eligibility` (backend, new). Example in `examples/api_v1_1.json`.

The route returns `{ "incident_id", "eligible", "target_ip", "lab_run_id", "capture_mode", "reasons": [ { "code", "message" } ], "last_web_observation_at", "checked_at" }`. `target_ip` is the case's `src_ip`. `last_web_observation_at` is the newest `web-decoy-01` event from that address in the case's run and mode (by `seq`), its `occurred_at` capped at the backend's receive time, so a sensor clock running ahead cannot make old traffic look fresh.

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
| `case_superseded` | a pre-migration row; the session case that replaced it is the one to act on |
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

A mismatch leaves the action unchanged and is appended to `verification_mismatches`, capped at 20 per action. Each item carries `event_id`, `received_at`, `sensor_id`, `src_ip`, `capture_mode` and a reason. Current reasons identify the first failed check: `wrong_sensor`, `wrong_source`, `replay_mode`, `wrong_run`, `outside_window`, `stale_policy_revision`, `duplicate` or `unknown_action`. Historical generic reasons remain verbatim; migration never infers a specific failed check. The old `verification_rejects` spelling is read during state migration only.

Apply, revoke and the action list return the complete action record: action identity, target, status, reason, creation/expiry, verified event ID, incident/run/mode, policy revision and mismatch list. Clients can display the immediate response without inventing absent target or timing fields.

### Health

Collectors post one heartbeat per sensor every 10 seconds to `POST /api/ingest/heartbeat`. The canonical wire body matches the current adapter:

```json
{ "collector_id": "adapter-laptop-b", "sensor_id": "ssh-decoy-01", "sent_at": "2026-11-01T04:31:40Z",
  "process_state": "running", "last_read_at": "2026-11-01T04:31:39Z", "last_ingest_at": "2026-11-01T04:31:38Z",
  "backlog_records": 0, "oldest_backlog_age_s": 0, "error_count": 0,
  "ingest": { "accepted": 412, "duplicate": 3, "rejected": 1, "quarantined": 1, "retry": 1 } }
```

`process_state` describes the reporting collector (`running`, `stopped`, `unknown`); it is not an independent measurement of the Cowrie or web container process. Counters are cumulative per sensor since collector start. `last_ingest_at` is the adapter's latest successful batch time. A readable file or recent attacker event is not a container-health probe.

For backward compatibility, the earlier `sensor_process`/`last_ingest_ok_at`/`backlog_lines`/`errors_total`/`rejected_total`/`quarantined_total` form is accepted and normalized. A request cannot mix the two formats. Unknown keys, invalid counts, incomplete canonical counters and timestamps without offsets are rejected with HTTP 400. Canonical requests require all five counters; legacy records may have an unknown retry count.

The response is `{"ok":true}`. Heartbeats are stored apart from events and never enter rules, scores or the event feed. Only the newest heartbeat per collector and sensor is retained.

`GET /api/health` preserves `ok` and legacy `sensors`, and adds `sensor_health.<sensor_id>`:

| Field | Meaning |
|---|---|
| `service` | Reported collector state: up/down/unknown; unknown after a stale heartbeat |
| `collection` | ok for heartbeat age under 30 seconds, stale afterward, never if none |
| `activity` | recent for backend-received event age under five minutes; quiet or none otherwise |
| `collector_id`, `heartbeat_at`, `process_state`, `last_read_at`, `last_ingest_at`, `backlog_records`, `oldest_backlog_age_s`, `error_count`, `ingest` | Canonical collector values; null when not reported |
| `clock_skew_s` | Sensor sent time minus backend receive time |
| `last_event_at` | Latest sensor occurred_at, separate from activity freshness |

`ok` means the backend is answering. A future event cannot make collection healthy. Canonical ingest counters come from the collector. For older flat-counter heartbeats only, accepted/duplicate totals fall back to persisted backend counts and retry remains unknown.

### Compatibility notes

| Consumer | What changes for it |
|---|---|
| Adapter, M2 | Nothing breaks; canonical heartbeat, `verification_mismatches` and the eligibility call match the integrated runtime. The adapter accepts schema 1.0 and 1.1 with all 19 indicator names. Future work: `requested_asset_id` on bait-read commands; `bait_served` only from the session output log |
| Web decoy, M4 | Nothing breaks while it sends 1.0. Aligned for 1.1: `request_id`; a `bait_served` with `sensor_response` when `/.env` is returned; a derived (non-cookie) `session_id`; `input_features` and `processing`; string `fixture_version`; `bait_assets` in `honeytokens.yaml`. Keep the 1.1 producer mode off until PR 2 is merged |
| Frontend, M1 | All v1.0 fields stay. New fields can be ignored at first. Behaviour that changes: the incident list holds more, smaller cases; per-case scores are lower until the analyst confirms a link (the 25→100 demo climb happens on the investigation); R04 shows stage `lure_access`; R07 shows fewer technique ids; R09 can be `orphan` with no link |
| Backend tests | Several v1.0 tests encode the old grouping (one incident per IP). They change on purpose in the implementation PRs, each with a note |

### Migration and rollback

The order follows review section 12. Each step is its own PR with real test output:

1. **This PR**: contract, examples, schema tests, and the gaps reproduced as expected-failure tests.
2. Ingest accepts 1.1 (version-gated validation, `input_features` and `processing` bounded, R07 consuming the indicators), derives `observation_kind`, enforces one mode per run, and adds the dedup namespace and `/api/runs`. DB migration 1 adds columns and a `runs` table. It rebuilds the `events` table once, copying every row unchanged including `seq`, because SQLite cannot drop the old unique key in place. The file is backed up first.
3. Case model: cases, credential window, profiles, investigations and dissolve. DB migration 2 rebuilds the `incidents` table once (SQLite cannot drop the old `UNIQUE(src_ip, lab_run_id)` in place) with the case columns. Old rows are kept unchanged as `legacy_ip_run` cases with status `superseded`, findings included, and stay readable by id. Each event is then assigned to its derived case in `seq` order: only `events.incident_id` changes; every observed field stays as stored. Link endpoints are re-pointed from their events, credential cases are derived, and every confirmed link rebuilds its investigation.
4. Causal token matching, orphan R09, corrected mappings and rule versions. DB migration 3 adds `links.attribution` and `links.candidate_issuance_ids` (`ALTER TABLE ... ADD COLUMN`; the file is backed up first).
5. Eligibility route, health and heartbeat. New tables `collector_heartbeats` (latest per collector and sensor) and `ingest_counters`, created on start (`CREATE TABLE IF NOT EXISTS`; no data is rewritten, so no version bump). M2's preview, apply and heartbeat already match. M4 and M2 emit `bait_served`.

The database records its schema in `PRAGMA user_version`: 0 = v1.0, then 1, 2 and so on. An observation's fields are never edited: migration 1 copies rows unchanged, and migration 2 changes only the derived `incident_id`.

Before upgrading, the backend copies the file to `backend/data/dg.db.v<old>.bak`.

Rollback:

1. Stop the backend.
2. Restore the `.bak` file.
3. Check out the previous commit.

For a hackathon reset, export the old run (`GET /api/incidents/{id}/export`), then start a new `lab_run_id`. Never replay old live records into a live run; replay them into a `replay-*` run.

## Four honeypots, gateway and telemetry (v1.2)

Status: contract published 2 Nov 2026 for the next milestone. Producers (gateway, demo app, MySQL decoy, SMB decoy, `backup.zip`) do not exist yet, so every v1.2 example in `examples/telemetry_v1_2.json` is **provisional synthetic** and says so. The milestone brief explicitly authorises the gateway, the normal demo app and the two extra honeypots; the old "no third decoy" limit no longer applies to them. Containment and evidence rules are unchanged.

### Versions, precisely

| Interface | Version | What it accepts |
|---|---|---|
| Honeypot events, `POST /api/ingest/events` | `schema_version` `"1.0"`, `"1.1"`, `"1.2"` | 1.0 and 1.1 are checked exactly as before (frozen copies in `history/event.schema.v1.0.json` and `history/event.schema.v1.1.json`). Only 1.2 may name `db-decoy-01`, `file-decoy-01`, `db_request` or `file_operation`, or carry the new attributes below. Any other version, for example `"1.3"`, is rejected per record |
| Gateway and normal-app telemetry, `POST /api/ingest/telemetry` (new) | `telemetry_version` `"1.0"` | `contracts/telemetry.schema.json`. Separate interface on purpose: these sources are not honeypots |
| Heartbeat, `POST /api/ingest/heartbeat` | unchanged body | Additive: `sensor_id` may name all four honeypots; a telemetry source sends `source_id` instead (exactly one of the two) |

Nothing old is reinterpreted: a stored 1.0/1.1 event keeps its meaning, and no 1.0/1.1 record gains a v1.2 field or a v1.2 sensor.

### Source identities (frozen)

Registry: `contracts/sources.json`, served as `GET /api/sources`.

| Id | Kind | Protocol | Proposed binding (M2 confirms) | Response capability |
|---|---|---|---|---|
| `ssh-decoy-01` | honeypot | ssh | 192.168.77.20:2222 (deployed) | `unsupported` |
| `web-decoy-01` | honeypot | http | 192.168.77.20:8080 direct (deployed), and the gateway's decoy upstream | `supported`, scope "web-decoy-01 only" |
| `db-decoy-01` | honeypot | mysql | 192.168.77.20:3306 | `unsupported` |
| `file-decoy-01` | honeypot | smb | 192.168.77.20:445 | `unsupported` |
| `gateway-01` | gateway (telemetry) | http | 192.168.77.20:8081 | `not_applicable` |
| `demo-app-01` | application (telemetry) | http | internal, reachable only through the gateway | `not_applicable` |

There are **four honeypots**. The gateway and the demo app never appear in `sensor_health`, honeypot counts, event feeds, cases or scores. The gateway does not proxy MySQL or SMB; those decoys are reached directly.

Event types per honeypot (1.2 enforces this for the new ones):

| Sensor | Event types |
|---|---|
| `db-decoy-01` | `connection_open`, `auth_failure`, `auth_success`, `db_request`, `connection_close` |
| `file-decoy-01` | `connection_open`, `auth_failure`, `auth_success`, `file_operation`, `synthetic_file_access`, `bait_served`, `connection_close` |
| `ssh-decoy-01`, `web-decoy-01` | as in 1.1 |

`attributes.protocol` (`ssh`, `http`, `mysql`, `smb`) is required on the two new sensors and must match them. `password_sha256` and `ingress` are forbidden on them.

### Gateway trust boundary

The gateway decides before any upstream handles the request: ordinary sessions go to `demo-app-01`, qualifying suspicious ones to `web-decoy-01`, and once a session is diverted its later requests in that run stay on the decoy (`pin.scope`). There is no promise that the diversion is undetectable.

How upstreams learn the gateway context (for M2's gateway and M4's upstreams; the backend never sees the key):

1. The gateway strips every incoming `X-DG-*` and `X-Forwarded-*` header. Nothing a client sends is ever trusted as a client address, session or result.
2. The gateway adds `X-DG-Gateway-Context: v1.<payload>.<mac>`. `payload` is base64url JSON `{ "gw_req", "gw_sess", "client_ip", "client_port", "run", "upstream", "iat" }`. `mac` is base64url HMAC-SHA256 over `v1.<payload>` with `DG_GATEWAY_CONTEXT_KEY`. That key is generated per lab run, kept in `deployment/lab.env` only (format `DGLAB-GWCTX-<64 hex>`), and never logged or committed.
3. The upstream checks the MAC (constant-time), `run` equal to its own run, `upstream` equal to itself, and `iat` within 30 s. If all pass, the context is `verified`, and the record's `src_ip` is the context's `client_ip`. Otherwise the context is `absent` (no header, for example direct 8080 traffic) or `invalid` with `invalid_reason`; `src_ip` is then the TCP peer, and the record must not carry `gateway_request_id` or `gateway_session_ref`. Schema and backend both reject records that break this.
4. `gateway_session_ref` (`gws_<hex>`) is a keyed digest of the gateway's own session cookie under the per-run key. It is never the cookie and cannot be replayed as one.

Web decoy events (1.2) carry `attributes.ingress = { gateway_context, gateway_request_id?, gateway_session_ref?, invalid_reason? }`. The normal app's `app_request` telemetry carries the same fields.

### Telemetry records (`telemetry_version` 1.0)

Common fields: `telemetry_version`, `record_id`, `source_id`, `record_type`, `occurred_at`, `lab_run_id`, `capture_mode`, `origin_record_id` (replay only) and `attributes`. Every level is closed: unknown keys are rejected, so no cookie, password or token can ride along.

| `record_type` | Source | Says | Never says |
|---|---|---|---|
| `route_decision` | `gateway-01` | which upstream the gateway chose and why: `decision` (`normal_app` or `decoy`), `upstream_id`, `reasons`, `indicator_classes`, `routing_policy_id`, `routing_policy_revision`, `pin`, `client_ip` (TCP peer), `gateway_session_ref`, `decided_before_upstream: true` | how the upstream handled the request |
| `upstream_result` | `gateway-01` | what the gateway saw come back: `outcome`, `status_code`, `response_bytes`, `elapsed_ms` | what the upstream logged |
| `app_request` | `demo-app-01` | the normal app's own handling record: `app_request_id`, gateway context, `src_ip`, `path`, `status_code`, `route_class`, optional `login.outcome` | any password, hash, cookie or real data |

Routing reasons: `no_trigger` (only with `normal_app`), `session_pinned`, `source_pinned`, `web_attack_indicator` (needs `indicator_classes` from the shared structural indicator vocabulary; lexical indicators alone never divert), `hidden_path_probe`, `bait_path_requested`, `honeytoken_presented`, `manual_lab_rule`.

Ingest: `POST /api/ingest/telemetry` with `{ "records": [ ... ] }`, max 100 records or 1 MiB, JSON only. The response has the same shape as event ingest: `{ "accepted", "duplicates", "rejected": [ { "index", "reason" } ] }`. Dedup key: `(namespace, source_id, record_id)`, where the namespace is `live` or `replay:<lab_run_id>`. A record whose run already has the other capture mode, in events or telemetry, is rejected. Telemetry never creates or activates a run, so `/api/runs`' `active` flag and response eligibility depend on honeypot events only.

### Requested routing versus observed handling

Three different claims, kept apart:

1. **Requested**: the gateway's `route_decision`.
2. **Gateway-observed**: the gateway's `upstream_result`.
3. **Upstream-observed**: the upstream's own record (a `web-decoy-01` event or a `demo-app-01` `app_request`) with a `verified` context naming the same `gateway_request_id`.

The backend joins these only through that verified id, never by IP and time alone. `GET /api/gateway/requests/{gateway_request_id}` returns the decision, the gateway-observed result, the upstream records and `correlation`:

| `correlation.status` | Means |
|---|---|
| `observed` | decision and upstream record agree: same run and mode, the upstream named in the decision, the same client address, and the upstream record within 30 s of the decision |
| `gateway_only` | a decision exists; no upstream record carries its id (not received, not logged, or never handled) |
| `upstream_only` | an upstream record carries a verified id with no matching decision received |
| `conflict` | they disagree; `reasons` lists `wrong_upstream`, `client_mismatch`, `run_mismatch`, `time_skew` or `context_reused` (more than one upstream record with one id) |

`GET /api/incidents/{id}/routing` (web cases and investigations) lists the case's gateway requests with their correlation status, the case's `gateway_session_refs`, an `ingress` count (`verified`, `absent`, `invalid`), and `normal_app_contact`. Normal-app contact is the `app_request` records whose verified `gateway_session_ref` is one of the case's. It always comes with `coverage` (`first_record_at`, `last_record_at`, `records_in_run`, and the demo app's collection state) and a statement. Missing logs never prove an asset was untouched.

Gateway decisions and upstream results never enter rules or scores and never verify a block. Verification is unchanged: only a `blocked_request` from `web-decoy-01` with the full tuple counts. Behind the gateway, its `src_ip` comes from the verified context; with an `absent` or `invalid` context, it is the gateway's peer address and fails `wrong_source`.

### Database authentication deception (`db-decoy-01`)

MySQL sends a salted challenge-response proof, never the password. So there is no `password_sha256`, and attempts cannot be shown to repeat or differ. Auth events carry `attributes.credential = { scheme, proof_check, verifier_version }`:

- `scheme` is one of `mysql_native_password`, `caching_sha2_password`, `ntlmv2`, `ntlmv1`, `smb_anonymous`, `smb_guest` or `other`.
- `proof_check: matched_honeytoken` means the decoy verified the proof against a planted lab credential it was configured with (it holds only the protocol verifier, for example SHA1(SHA1(password)), never the value). `honeytoken_id` is then required. With any other `proof_check`, `honeytoken_id` is forbidden.
- `not_matched` means checked against every planted credential for that user, and none verified. `not_checked`, `unsupported_scheme` and `malformed` mean nothing is known about the password.
- The decoy never asks a client to switch to cleartext authentication.
- `auth_success` means the emulator completed the handshake as if the login succeeded. It does not mean a database session exists.

`db_request` records a command packet received after the handshake. `attributes.db = { command, statement_verb, length_bytes, schema_name?, execution: "not_supported", error_code? }`. There is no statement text. The emulator executes nothing.

### File service (`file-decoy-01`)

Auth uses the same `credential` record (NTLM is challenge-response too). `file_operation` carries `attributes.file = { operation, share, path, bytes, content_sha256, digest_scope, storage, magic_type_hint }`.

- Uploads are stored `quarantined_inert` or `discarded`. They are never executed, opened by a parser, or scanned into a verdict.
- `magic_type_hint` comes from the first bytes only and is not a verdict.
- No 1.2 attribute key may contain `verdict`, `malware` or `malicious`.
- A synthetic file read over SMB is `synthetic_file_access` (and `bait_served` if it holds tokens).

### Archive bait (`web:/backup/backup.zip`)

The zip is served by `web-decoy-01`, normally behind the gateway's `bait_path_requested` or pinned diversion. It holds only fixed plain-text and CSV entries with synthetic `DGLAB-` values and `example.com` identities.

The serving emits `synthetic_file_access` (outcome `served`) and `bait_served` with:
- `asset_id`, `honeytoken_ids` (every token in any entry), `issuance_id`, `evidence_basis: "sensor_response"`;
- `sha256` and `size_bytes` with `digest_scope: "full_asset"`, and `fixture_version`;
- optional `issued_expires_at`;
- `archive = { format: "zip", compression, entries: [ { name, size_bytes, sha256, honeytoken_ids } ], contains_executable: false, auto_run: false }`. Entry names must end in `.txt` or `.csv` and have no path. Anything else is rejected.

`transfer = { response_status, content_length, bytes_written, completion }` describes the server's side only. `body_written` means the decoy finished writing the body to its socket.

Claims ladder:

| Claim | Evidence | Shown as |
|---|---|---|
| requested | `http_request` for the path | request |
| served | `bait_served` / `synthetic_file_access`, `sensor_response` | response evidence |
| client finished downloading | **never observed** (`body_written` is not this) | not claimed |
| extracted or opened | **never observed** | not claimed |
| a planted credential from it was used | a later `honeytoken_id` presentation on the token's `valid_on` sensor | causal token link (below) |

Tokens `tok_db_01` (valid on `db-decoy-01`) and `tok_smb_01` (valid on `file-decoy-01`) are planted in the zip on `web-decoy-01`. Causal token matching is unchanged. One serving gives a `unique` strong candidate. Several servings of the same static credential give `ambiguous`, and the backend never picks one. No serving gives an orphan R09. Re-serving the zip, ingest duplicates, gateway decisions and analyst decisions add no points.

### Cases and rules (v1.2)

| Case kind | Key | Gets |
|---|---|---|
| `db_session` / `db_activity` | as `ssh_session` / `ssh_unsessioned`, on `db-decoy-01` | MySQL events with / without a connection id |
| `file_session` / `file_activity` | as above, on `file-decoy-01` | SMB events with / without a session reference |
| `credential_attempts` | SSH: unchanged key (existing case ids kept). New sensors: `sensor_id + src_ip + username + run + mode` | R01 (SSH) or R11 |

No IP/time `candidate` links are made for the new sensors; they join investigations only through causal token links the analyst confirms.

| Rule | Fires when | Mapping | Weight |
|---|---|---|---|
| R11@1 | 5+ `auth_failure` on `db-decoy-01` or `file-decoy-01`, same sensor + src_ip + username, within 60 s, across connections | T1110, `attempted`; the label counts attempts, because a challenge-response proof cannot show distinct passwords | 20 |
| R12@1 | `file_operation` `write`/`create` with `bytes` > 0 and `storage: quarantined_inert` | no technique (`technique_id: null`, `emulated`): "content written to an emulated share; stored inert; not a malware verdict" | 15 |
| R04@3 (file only) | `synthetic_file_access` served by `file-decoy-01` | stage `lure_access`, "synthetic lure retrieved over SMB". Web and SSH output stays R04@2 | 30 |
| R09@2 | unchanged; covers the new `valid_on` sensors | — | 15 after confirmation |

`db_request` is stored and shown, and not scored. All summaries stay rule-generated text; there is no AI feature in v1.2.

### Health and capabilities

`GET /api/health`:
- `sensors` and `sensor_health` list all four honeypots. A honeypot with no heartbeat shows `collection: "never"`.
- New `telemetry_health.gateway-01` and `telemetry_health.demo-app-01` use the same fields, with `last_record_at` in place of `last_event_at`, plus `counted_as_honeypot: false`.

`GET /api/sources` returns the registry with `honeypot_count: 4`.

`GET /api/incidents/{id}/response-eligibility` adds:
- `response_scope = { "enforced_on": ["web-decoy-01"], "not_enforced_on": ["ssh-decoy-01", "db-decoy-01", "file-decoy-01"] }`;
- reason code `response_unsupported_sensor` for a case on `db-decoy-01` or `file-decoy-01`. A web block never blocks MySQL or SMB.

Errors:

| Case | Answer |
|---|---|
| A body that is not JSON, or not `{ "records": [...] }` | 400 `bad_request` |
| Wrong content type | 415 |
| More than 100 records or 1 MiB | 413 |
| `GET /api/gateway/requests/{id}` with no record of that id | 404 `not_found` |
| `/routing` on a case kind without web traffic | 200 with empty lists and the coverage statement |

### Migration and rollback (v1.2)

DB migration 4 creates the `telemetry` and `telemetry_heartbeats` tables. The file is backed up first to `backend/data/dg.db.v3.bak`. No event, case, finding or link row is rewritten, and all case ids are kept. Rollback: stop the backend, restore `dg.db.v3.bak`, and check out the previous commit. A v4 file may hold 1.2 events that older code does not understand.
