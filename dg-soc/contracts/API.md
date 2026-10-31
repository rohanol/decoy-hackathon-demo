# API contract v1.1 (v1.0 compatible)

v1.1 is in review (branch `m3/evidence-boundaries`). Everything marked v1.1 is additive; a v1.0 client keeps working. The new rules are in **Evidence boundaries (v1.1)** at the end, and the backend implements them in the later PRs listed under Migration.

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

A **`bait_served`** event (new) says that a sensor returned content containing honeytokens. Required attributes: `asset_id`, `honeytoken_ids`, `issuance_id` and `evidence_basis`. Recommended: `sha256` with `digest_scope`, `fixture_version`, `issued_expires_at`, and `request_id` for web.

- Web decoy, `evidence_basis: "sensor_response"`: logged by the app when it returns `/.env`. It has the same `request_id` as the request record.
- SSH, `evidence_basis: "derived_from_command"`: Cowrie does not log file output. The adapter may emit `bait_served` when a `command_input` reads a registered bait path that exists in the emulated filesystem, for example `cat /home/dg_demo/notes.txt` or `cat notes.txt` in that home directory. It must set `derived_from_record_id` to the command record. The UI shows this as weaker evidence: "read command for a bait file; output not logged".
- Bait asset ids are `ssh:/home/dg_demo/notes.txt` (contains `tok_portal_01`) and `web:/.env` (contains `tok_backup_01`). The registry lives with the token list in `config/honeytokens.yaml` (M4) as `bait_assets: [ { asset_id, sensor_id, path, honeytoken_ids, fixture_version } ]`.

**Causal token matching** (review section 11, T05 and T06):

1. A token presentation is an event with `attributes.honeytoken_id` on a sensor other than the token's `planted_on`.
2. It matches the newest `bait_served` that meets all of these: it lists that token, it is in the same `lab_run_id` and `capture_mode`, its `sensor_id` equals the token's `planted_on`, its `occurred_at` is not after the presentation, and it has not expired.
3. Match → a `strong_candidate` link from the `bait_served` event to the presentation. The basis reads, for example, `honeytoken tok_portal_01 served by ssh:/home/dg_demo/notes.txt (derived from command)`. The R09 finding has `token_relation: "linked"`.
4. No match → no link is created and no source event is invented. The R09 finding still appears with `token_relation: "orphan"`, label "Honeytoken tok_x presented; no record of it being served in this run", 0 points, and it is never scored.
5. Two clients who received different issuances stay distinguishable through `issuance_id`.

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

`eligible` is true only if all of these hold:

1. The case is `live`.
2. Its run is the active live run.
3. The case's `src_ip` has a `web-decoy-01` event in that run less than 10 minutes old.
4. The case is not `dissolved`.

Otherwise `reasons` lists every failed check. The allowed-IP check stays in `response/` (M2). Preview and apply must both call this route. Apply re-checks at execution time and refuses with 409 `not_eligible` (review T03). The lookup `response/` already makes switches from `GET /api/incidents/{id}` to this route.

Verification tuple (M2's `on_event`, review T04). An action becomes `verified` only when a `blocked_request` meets all of these:

1. `attributes.block_action_id` equals the action id.
2. `sensor_id` is `web-decoy-01`.
3. `src_ip` equals the action's `target_ip`.
4. `capture_mode` is `live`.
5. `lab_run_id` equals the run recorded at apply.
6. `occurred_at` falls within `[applied_at, until]`.

A mismatch leaves the action unchanged. It is recorded in the action's `verification_rejects: [ { "event_id", "reason" } ]`, at most 20 entries.

### Health

Collectors (the adapter, M2) post a heartbeat every 10 s to `POST /api/ingest/heartbeat`. The body is in `examples/api_v1_1.json`; `sensor_process` is `up`, `down` or `unknown`, and the response is `{ "ok": true }`. Heartbeats are stored apart from events and never reach rules, scores or the feed.

`GET /api/health` keeps `ok` and `sensors` (v1.0) and adds `sensor_health.<sensor_id>`:

| Field | Values | Rule |
|---|---|---|
| `service` | `up`, `down` or `unknown` | taken from the latest heartbeat; `unknown` if there is none or it is older than 30 s |
| `collection` | `ok`, `stale` or `never` | `ok` = heartbeat younger than 30 s; `never` = no heartbeat yet |
| `activity` | `recent`, `quiet` or `none` | `recent` = an event in the last 5 min; `quiet` = older; `none` = no events. A quiet sensor is not a broken one |
| `last_heartbeat_at`, `last_event_at`, `backlog_lines`, `rejected_total`, `quarantined_total`, `clock_skew_s` | | taken from the heartbeat and the event table; null if unknown |

`clock_skew_s` is the heartbeat's `sent_at` minus the backend's receive time. An event time in the future never makes a sensor look healthy. `ok` means only that the backend is up.

### Compatibility notes

| Consumer | What changes for it |
|---|---|
| Adapter, M2 | Nothing breaks. To adopt: heartbeat, `observation_kind`, `bait_served` (derived) for the notes.txt read, the verification tuple, and the eligibility call |
| Web decoy, M4 | Nothing breaks. To adopt: `request_id` on every record, a `bait_served` record when `/.env` is returned, a session cookie id in `session_id`, and `bait_assets` in `honeytokens.yaml` |
| Frontend, M1 | All v1.0 fields stay. New fields can be ignored at first. Behaviour that changes: the incident list holds more, smaller cases; per-case scores are lower until the analyst confirms a link (the 25→100 demo climb happens on the investigation); R04 shows stage `lure_access`; R07 shows fewer technique ids; R09 can be `orphan` with no link |
| Backend tests | Several v1.0 tests encode the old grouping (one incident per IP). They change on purpose in the implementation PRs, each with a note |

### Migration and rollback

The order follows review section 12. Each step is its own PR with real test output:

1. **This PR**: contract, examples, schema tests, and the gaps reproduced as expected-failure tests.
2. Ingest accepts 1.1, derives `observation_kind`, enforces run mode, adds the dedup namespace and `/api/runs`. DB migration 1 adds columns only.
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
