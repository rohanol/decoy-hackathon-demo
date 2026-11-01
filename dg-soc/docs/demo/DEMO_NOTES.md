# Demo notes — dashboard side (M1)

Owner: Pashmee (M1). Companion to `scenarios/demo_p3.md` (M4's attack run sheet),
which stays the source of truth for what Laptop A does. This file says what to
show on Laptop B, what each screen establishes, and what it must not be used to
claim. Structure follows review section 20.

Screenshots in `evidence/` come from a live-backend browser run
(`frontend/tests/e2e/evidence.e2e.cjs`) against the real FastAPI backend with
M2's response router, plus `lab-*.png` from the dev-only evidence lab
(fixture build). See "Evidence" at the end.

## Before the run

- Fresh start per `scenarios/demo_p3.md` (reset, bump `LAB_RUN_ID`, preflight ALL PASS).
- Frontend in **live mode**: `npm run dev` with `VITE_USE_FIXTURES` unset or `0`.
  The topbar must not show `FIXTURES`. A `REPLAY` chip means replayed data is in
  view: say so, and do not use it for response.
- No internet on the lab link: sign in with **Continue as lab analyst** (needs
  `VITE_AUTH_DEV_BYPASS=1` and no Supabase keys). Fonts ship locally; the
  offline-entry check (`tests/e2e/offline-entry.e2e.cjs`) confirms no external
  request is attempted.
- UI on `127.0.0.1:5173`, backend on `127.0.0.1:8000`: loopback only.

## Seven-minute run

| Step | Laptop A (see demo_p3.md) | Show on Laptop B | What it establishes | Do not claim |
|---|---|---|---|---|
| 1 Lab boundary | — | **Sensors**: Service (backend answering, stream connected), Collection, Attacker activity — three separate panels | The SOC is up and listening on loopback | That a decoy is healthy because it had recent traffic. v1.0 has no collector heartbeat: Collection reads **not reported** |
| 2 SSH interaction | hydra, login, `whoami`, `ls -la` | **Live Feed**, then the incident's **Session cases**: each hydra connection and `sess01` are separate cases | Supported observations, in order, with event ids | Account compromise or real execution |
| 3 Bait read | `cat notes.txt` | Session case `sess01` → **Transcript**; Feed filtered to `session=sess01` | The read command was submitted in that session | That the file was served: v1.0 does not record it (relation card says *serving not recorded*) |
| 4 Web workflow | portal login with `svc_portal`, SQLi, CSV download | Web case (labelled **bounded fallback**: v1.0 web has no session id); outcome facets on feed rows | Web requests from this source in this run | Successful exploitation; data theft |
| 5 Relationship | — | **Relations**: candidate (same IP + time) and strong candidate (token), each with "proposed because" and a caveat | Why a relation is proposed, and why IP alone is not enough | Same person. Relations never identify a person |
| 6 Analyst decision | — | Strong relation → **Confirm or reject…** with a rationale → **Approved cross-decoy parent** appears; **Mapping rationale** under findings | A reproducible, reversible analyst judgement; techniques with limitations | That the score is a parent score: the hero is a **v1.0 source score** pooling every case on the address |
| 7 Web containment | request after block, then undo | **Block source** (only offered for a live source) → Response panel: **Policy committed** → **Pending verification** → **Verified denial** with the event id | The web policy refused a request carrying that action id | Host isolation; SSH blocked; verification of sensor/source/run (v1.0 checks the action id only, review F5) |
| 8 Evidence package | — | Export report; this file; `evidence/` | Another teammate can inspect the claim | Measured accuracy. Grouping on Overview is compression, not false-positive reduction |

## Answers to have ready (review section 20)

- **Why is this a candidate, not an identified person?** Relations connect sessions on
  observed evidence. A NAT or shared laptop produces the same pattern; the card says so.
- **What if two users share an IP?** Each SSH session stays its own case (step 2). v1.0
  still scores per address; the source score is labelled as exactly that.
- **What proves the block worked?** Only a refused request carrying the action id. Until
  then the timeline sits at *Pending verification*. Committed is not verified.
- **Can replay drive response?** No. A replay-only or mixed source shows the Block button
  disabled with the reason (`replay_data`, `mixed_modes`). That is a UI guard; the backend
  must still enforce it (review T03, owned by M3/M2).
- **What does Overview's funnel mean?** Events grouped by source and run. Not accuracy.
- **Time to first alert?** Backend arrival to first finding for one incident; not
  end-to-end latency.

## If something fails live

- **Wheel misbehaves:** ChakraView → **2D**, or `/graph?view=network`.
- **Socket drops:** the feed reconnects and reconciles the snapshot with live events by
  event id; `tests/e2e/reconnect.e2e.cjs` shows no missing or duplicate ids.
- **Falling back to a recorded run:** it will show **REPLAY**; say so, and do not apply
  a block from it.

## What is v1.0 and what is proposed

Every evidence panel carries a tag:

- `contract v1.0` — reshaped from today's API in `frontend/src/evidence/fromV1.ts`.
  Nothing scored or inferred; missing values say "not in v1.0".
- `PROPOSED · dev fixture` — only in a fixture build, on **Evidence lab · dev**
  (`/dev/evidence`). Shapes in `frontend/src/evidence/model.ts`, pending Rohan's
  contract. Never on the demo path; the release bundle contains none of it.

Waiting on the shared contract (review section 17): per-session cases and scores,
approved parents and parent scores, `request_id`, `observation_kind`/`outcome`,
bait issuance and `bait_served`, collector heartbeat, the full verification tuple
with rejection reasons, and backend response eligibility. The components already
render each of these from the fixtures.

## Evidence

| File | Shows |
|---|---|
| `01-sensors-health.png` | Service, Collection (not reported), Activity apart |
| `02-feed-session-filter.png` | Feed narrowed to one session in one run |
| `03-incident-evidence.png` | Source profile (escaped attacker text), distinct session cases |
| `04-incident-mapping.png` | Mapping rationale with limitations and rule versions |
| `05-parent-approved.png` | Parent appears only after confirmation |
| `06-block-committed-pending.png` | Policy committed, pending verification |
| `07-block-verified.png` | Verified denial with the event id |
| `08-replay-withheld.png` | Replay-only source: block withheld with reasons |
| `09-response-center.png` | Response Center with verification stages |
| `10-chakra-2d.png`, `11-network-fallback.png` | 2D and network fallbacks |
| `12-reconnect.png` | Feed after a forced socket drop and held snapshot |
| `13-m2-mismatches-pending.png` | M2's runtime (PR #8 backend): two refused verifications shown verbatim, action still pending |
| `14-m2-verified.png` | Same action verified by the matching request; refusals kept |
| `15-filter-request-id.png` | Request filter on M3's v1.1 example web records (1.0 envelope) |
| `16-filter-web-session.png` | Session filter on web records carrying a session id (synthetic until M4 pushes) |
| `lab-*.png` | Proposed shapes in the dev evidence lab (fixtures) |

## Coordination status (PR #10 follow-up)

| Item | State in the UI | Waiting on |
|---|---|---|
| Verification refusals | Reads **both** `verification_mismatches` (M2 runtime, PR #8) and `verification_rejects` (M3 contract, PR #9); each row shows which field it came from; reasons shown verbatim. M2 sends one generic reason (`verification_context_mismatch`), so the UI says the backend did not name the failed check | M2 + M3 agree one name; ideally a specific reason per failed check |
| `reconciliation_required` (M2) | Shown as its own stage and kept in active actions, never as verified | Agreement that it joins the contract |
| Collector health | Still **not reported**. M2's heartbeat is a local file only | Backend `sensor_health` in `/api/health` (M3 v1.1) |
| Cases and investigations | Every case and parent is tagged **display grouping**; backend-owned ones will be tagged **backend case** | M3's case model at runtime |
| Web `session_id` / `request_id` | Filters work on M3's v1.1 example web records via the real backend. Web session ids are synthetic in the test | M4 pushing its generator; re-run `RECORDS=… node tests/e2e/filters.e2e.cjs` |
| v1.1 event types, stages, `bait_served` provenance | Unknown types and stages render as raw text instead of breaking. No v1.1 meaning is wired | Contract v1.1 merge |

## Contract v1.2 in the SOC (m1/next-portal-ui)

The UI reads the v1.2 shapes from M3's PR #19 (`m3/next-telemetry-contract` @
`eb2a94e`, **not merged**). On today's v1.1 backend every v1.2 view says it is not served
and shows nothing in its place.

| View | v1.2 source | On a v1.1 backend |
|---|---|---|
| Sensors · Honeypots (4) and Telemetry sources (gateway-01, demo-app-01) | `GET /api/sources`, `sensor_health`, `telemetry_health` | "Source registry not served"; MySQL and SMB cards say **not on this backend**; no health is made up |
| Topbar dots | `health.sensors` | Only the sensors the backend reports (2 today) |
| Feed rows: DB and SMB facts | `attributes.db`, `.file`, `.credential` | Not present, so not shown |
| Incident · Gateway routing | `GET /api/incidents/{id}/routing`, `GET /api/gateway/requests/{id}` | "The backend does not serve routing views yet" |
| Incident · Archive bait | `bait_served` + `attributes.archive` / `.transfer`, token links | Shown only when an archive serving exists |
| Incident · Response scope | `response_scope`, reason `response_unsupported_sensor` | "Web block on web-decoy-01 only; does not block SSH, MySQL or SMB" |

What these views never do:
- infer a diversion, a gateway session or an identity from a shared IP;
- count a telemetry source as a honeypot;
- claim a client finished a download, opened or extracted an archive, or that a DB
  statement ran.

They also never offer the web block for DB or SMB activity.

The provisional fixture (M3's example records, verbatim) renders only on
**Evidence lab · dev** in a fixture build, under the **PROVISIONAL** tag. The release
bundle contains none of it.
