# Current frontend (Pashmee's work), summarised for Codex

Source: `dg-soc/frontend/` on branch `claude/peaceful-edison-nvvyny` (latest commit `bd0b60e`,
31 Oct 2026). Not merged into `main` yet. The full design spec is `../frontend/DESIGN_SPEC.md`;
this file is the short version.

## Product in one paragraph

DeceptionGraph SOC is a hackathon project with decoys and a small security operations
dashboard. A Kali laptop attacks two decoys (a fake SSH server and a fake web portal). Their logs
become events, rules turn events into findings, findings are grouped into an incident per
attacker IP with a score, and an analyst can confirm cross-decoy links and apply a short,
web-decoy-only block. The dashboard is what judges watch during the live demo, often on a
projector.

## Stack

- Vite 5.4.9, React 18.3.1, React Router 6.26.2, TypeScript 5.6.3 (strict). No UI library, no CSS
  framework, no graph library: plain CSS with tokens, and inline SVG for the graph.
- Styles: `src/styles/tokens.css` (design tokens on `:root`) and `src/styles/app.css`.
- Dark theme only, designed for 1440x900, degrades to 1280x800.

## Screens and routes

| # | Screen | Route | File | What it shows |
|---|---|---|---|---|
| 1 | Overview | `/` | `screens/Overview.tsx` | Noise counter ("N raw events → M incidents, K low priority"), time to first alert, findings by rule (R01–R09, no R06), active incidents with kill-chain silhouettes |
| 2 | Live Feed | `/events` | `screens/LiveFeed.tsx` | Table of events, newest first, live via WebSocket, pause/resume, filters, raw event drawer |
| 3 | Incident List | `/incidents` | `screens/IncidentList.tsx` | One card per attacker IP: severity border, badge, score, compact kill-chain strip |
| 4 | Incident Detail | `/incidents/:incidentId` | `screens/IncidentDetail.tsx` | The demo centrepiece: kill-chain bar, summary, finding cards, score breakdown, cross-decoy links, sessions, response panel |
| 5 | Transcript Replay | `/incidents/:incidentId/transcript/:sessionId` | `screens/TranscriptReplay.tsx` | Terminal-style replay of SSH commands with a stepper and keyboard controls |
| 6 | Attack Graph | `/graph` | `screens/AttackGraph.tsx` | Attacker node and two sensor nodes in a fixed layout; link edge turns from dashed (candidate) to solid (analyst-confirmed) |
| 7 | Response Center | `/response` | `screens/ResponseCenter.tsx` | Active and past blocks; preview → approve → applied → verified flow, undo |

## Components

`components/`: `Shell` (topbar + sidebar + sensor health), `ConnectionPill`, `RawEventDrawer`,
`FindingCard`, `KillChainBar` (compact and full), `ScoreBreakdown`, `LinkDecisionModal`,
`ActionCard`, `primitives.tsx` (Badge, Pill, Chip, Card, buttons, empty/error/skeleton states,
`AttackerText`).

Other: `copy.ts` (the only approved wording), `lib/eventStyle.ts` (glyph and colour per event
type), `lib/format.ts` (time and number formatting), `types/api.ts` (types hand-written from the
contracts).

## Data flow

- `api/config.ts`: `VITE_USE_FIXTURES=1` switches to the fixture backend; `VITE_API_BASE` is the
  real backend (`http://127.0.0.1:8000`).
- `api/fixtures.ts`: a fake backend. It serves the first 13 events of `events_p3.json` as the
  REST snapshot and streams the last 10 over a fake socket every 1.2 s. It also mocks one incident
  (`inc_01`, critical, score 95, or 100 once the cross-decoy link is confirmed), its findings,
  links, sessions (`sess01` has the commands) and the block flow, built from the shapes in
  `contracts/API.md`.
- `api/client.ts`, `api/socket.ts`: REST and WebSocket with backoff and reconnect.
- `state/LiveStore.tsx`: snapshot + socket + pause buffer, shared by the screens.

## Design tokens (current, variant A)

| Group | Values |
|---|---|
| Surfaces | `--bg-base #0B0F14`, `--bg-surface #111822`, `--bg-raised #1A232F`, `--bg-inset #080C11`, `--border #243040`, `--border-strong #33465C` |
| Text | `--text-primary #E6EDF3`, `--text-secondary #9BA9B7`, `--text-muted #6B7A8A` |
| Accent | `--accent #3DA9FC` |
| Severity | low `#4A90A4`, medium `#D99A2B`, high `#E0703B`, critical `#D9394B`, as outlined badges with 12% fill |
| Status | ok `#3DD68C`, warn `#D99A2B`, danger `#D9394B`, pending `#A78BFA` (needs a human), neutral `#6B7A8A` |
| Type | UI: system sans stack. Mono: JetBrains Mono → system mono. Everything machine-made (IPs, IDs, timestamps, commands) is mono |
| Spacing | 4px base: 4, 8, 12, 16, 24, 32, 48. Radius 4 (controls), 8 (cards), 12 (modals) |

Two deliberate colour inversions: `auth_success` is red (a login to a decoy is bad news) and
`blocked_request` is green (the block is working).

## Known gaps (from Pashmee's README)

- Incident list has no rule chips or "awaiting decision" flag; the API summary lacks that data.
- Overview rule bars are not clickable for the same reason.
- Drawer does not fully trap keyboard focus yet.
- In fixture mode, the incident data is a hand-made mock, and Export and the real block flow need
  the live backend.

These are API limits, not design choices. Do not fake the missing data in a variant.
