# Frontend (M1)

React + TypeScript + Vite. Owner: Pashmee (M1), with Rohan. Design source of truth:
[`DESIGN_SPEC.md`](./DESIGN_SPEC.md).

## Redesign (November 2026)

- Theme: black, white and one neon green (`src/styles/tokens.css`). Green means
  brand or live only. Analytics and reports use white and the validated
  severity palette, never green. Fonts are Inter and JetBrains Mono, shipped
  with the app, so nothing loads from the internet.
- New routes: `/welcome` (landing, no scroll), `/login`, `/sensors`. The
  console routes are unchanged and need a signed-in analyst.
- ChakraView is 3D by default (`src/chakra/Chakra3D.tsx`): the rings form a
  funnel, so depth into the fiction is real depth. The timeline under it
  replays the incident by rebuilding the same wheel model from the events up
  to the cursor (`src/chakra/Timeline.tsx`). The 2D wheel stays one click away
  and is used automatically when the browser has no WebGL.
- The blue hat (blue team mark) is built from geometry in code; there is no
  model file to download.
- three.js loads only when ChakraView or the hat is shown.

### Sign-in

Supabase Auth, Google plus email and password (`src/auth/AuthProvider.tsx`).
Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in `.env.local`, enable the
Google provider in the Supabase dashboard, and add `http://127.0.0.1:5173/` as a
redirect URL. Google sign-in needs internet on the SOC laptop.

This gates the UI only. The backend has no auth yet, so `/api` stays open on
loopback until it verifies the Supabase token. Until a provider is set,
`VITE_AUTH_LOCAL=1` replaces the Google and email form with a single "Enter the
console" sign-in for the lab machine. The login page never shows controls that
cannot work.

## Run

```bash
cd dg-soc/frontend
npm install
cp .env.example .env.local
```

Against the fixture, with no backend running — this is how to build screens
before M3 ships:

```bash
VITE_USE_FIXTURES=1 npm run dev
```

Against the live backend (M3 on `127.0.0.1:8000`):

```bash
npm run dev
```

Either way the app serves on <http://127.0.0.1:5173>. The port is `strictPort`,
bound to loopback — the SOC UI is never served over the lab link
(`AGENTS.md` section 3).

```bash
npm run typecheck   # tsc --noEmit, strict
npm run build       # typecheck + production build
```

## Against the real backend

Verified end to end against M3's FastAPI (see DESIGN_SPEC.md §16b). In one terminal:

```bash
cd dg-soc
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m backend.main
```

```bash
python -m backend.tools.load_fixtures
```

Then `npm run dev` with no fixture flag. The backend already allows
`127.0.0.1:5173` via CORS.

## Fixture mode

`VITE_USE_FIXTURES=1` runs the whole UI off
`contracts/examples/events_p3.json`, imported read-only from `contracts/` so it
cannot drift from the contract. `src/api/fixtures.ts` is a mock backend: it
serves the first 13 events as the REST snapshot and streams the last 10 over a
fake socket at 1.2s intervals, so both the snapshot path and the live-append
path get exercised.

Two independent guards keep fake data off the demo path
(`AGENTS.md` section 9):

1. The flag defaults to off, and when on, the topbar shows a loud amber
   `FIXTURES` chip on every screen.
2. Fixture events carry `capture_mode: "replay"`, so the chip would read
   `REPLAY` rather than `LIVE` even if the flag check were bypassed.

With no events at all the chip reads `NO DATA`, never `LIVE`.

## Layout

```
src/
  api/        config, REST client, WebSocket with backoff, fixture backend
  components/ shell (topbar, sidebar, sensor health), connection pill,
              raw event drawer, primitives
  lib/        formatting, event glyph/colour map
  screens/    LiveFeed (built), stubs for the other six
  state/      LiveStore — snapshot + socket + pause buffer
  styles/     tokens.css (design tokens), app.css
  types/api.ts  hand-written from the contracts
  copy.ts     the AGENTS.md section 7 wording dictionary
```

## Types

`src/types/api.ts` is hand-written from `contracts/event.schema.json`,
`contracts/finding.schema.json` and `contracts/API.md`. Once M3's backend serves
`/openapi.json`, regenerate:

```bash
npx openapi-typescript http://127.0.0.1:8000/openapi.json -o src/types/api.ts
```

These are a frozen interface (`AGENTS.md` section 3). If the backend disagrees
with this file, the contract changes by PR with Rohan's OK — we do not patch
around it in the UI.

## The three laws

1. **The browser never decides anything.** Score, severity, link status and
   whether a block worked all arrive from the API and are displayed as received.
2. **Attacker text is hostile.** It renders through `AttackerText`, which is
   escaped, mono and bounded. `dangerouslySetInnerHTML` appears nowhere.
3. **Claim only what the evidence proves.** User-facing wording comes from
   `copy.ts`, which encodes `AGENTS.md` section 7.

## What works now

- App shell: topbar (capture chip, `lab_run_id`, connection pill, UTC clock),
  sidebar nav, sensor health strip from `GET /api/health`
- Live Feed: REST snapshot then `/ws/events`, newest first, new-row flash,
  pause/resume with buffering, filters by sensor / event type / src_ip, DOM
  capped at 500 rows, every row showing its `event_id` and `incident_id`
- Raw event drawer: every schema field, attacker values in bounded wells,
  hashes truncated with copy, `Esc` to close
- Connection pill: live / reconnecting with attempt count / offline with
  last-data time and click-to-retry; exponential backoff with jitter;
  snapshot reload on every reconnect
- All six global states on the feed: loading, empty, error, filtered, capped,
  no-backend
- Incident detail: header with severity and score, kill-chain bar with a
  clickable stage filter and a real "not observed" segment, rule-based summary
  with clickable citations, finding cards showing label *and* limitation with
  every evidence id opening its raw event, score breakdown including uncounted
  rows and the cap note, cross-decoy links, sessions with replay links, and the
  response panel
- Link decision modal: both evidence events inline, mandatory rationale with a
  live character count, confirm and reject, reversible, and a reload from the
  API rather than an optimistic restyle
- Incident list: severity-bordered cards sorted by newest activity, each with
  the compact kill-chain strip, updating live from `type: "incident"` messages
- Response Center and the block flow: preview, approve with a written reason
  and an acknowledged scope, then a polled wait for verification, with undo.
  Verified end to end against M2's real router (DESIGN_SPEC.md §13.5), and it
  held at `APPLIED` for 6s with no blocked request before flipping to
  `VERIFIED` in 500ms once one arrived
- Overview: the noise-reduction counter, time to first alert, findings by
  rule with every rule visible at zero, and active incidents with their
  kill-chain silhouettes
- Attack graph: inline SVG with no graph library, fixed deterministic layout,
  traffic edges drawn only where the API confirms that source on that sensor,
  and the cross-decoy link turning from dashed candidate to solid
  analyst-confirmed in place
- Transcript replay: terminal-styled, mandatory non-dismissible banner, a dim
  prompt prefix separating our chrome from attacker text, per-line timestamps
  and clickable event ids, and a stepper with play/pause, speed and full
  keyboard control (`←` `→` `Space` `Home` `End`)

## Known gaps

- The block flow cannot run against the repository as it stands. M2's
  `response/router.py` is written and tested but lives in
  `m2/m2-upload/dg-soc/`, not `dg-soc/`, so `backend/integrations.py` does not
  find it and `/api/response/*` returns 503. It was verified by copying the
  router into place locally; no frontend change is expected once that merge
  lands

- Screen 7 (Response Center) is a stub that name their spec section and build order
- The incident list has no rule chips or "awaiting decision" flag:
  `IncidentSummary` carries no findings and `Link` has no `incident_id`, so
  neither has an honest source at that endpoint (open question 2)
- The attack graph cannot attribute a cross-decoy link to a particular source
  when more than one source IP has links, for the same reason
- Overview's rule bars are not clickable: the incident list cannot filter by
  rule, for the same reason again
- The incident Block button is disabled until M2's response router exists
- Export needs the live backend, so it is disabled in fixture mode
- The drawer closes on `Esc` and autofocuses, but does not fully trap focus yet
- Sensor health polls every 15s, so it can lag the feed by up to that long
- `GET /api/events` has no `src_ip` filter in the contract, so IP filtering is
  client-side over the loaded window; the UI says so above the table
- Fixture incidents carry placeholder `score: 0` / `severity: "low"` — scoring
  belongs to M3 and is never computed here
