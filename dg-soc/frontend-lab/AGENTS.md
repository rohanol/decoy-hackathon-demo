# AGENTS.md: frontend-lab (design playground for Codex)

These rules add to `dg-soc/AGENTS.md`. If they conflict, `dg-soc/AGENTS.md` wins on safety and
wording. The ownership exception is section 2 below.

## 1. What this folder is

- A **throwaway design playground**: Rohan and Pashmee (M1) use it to try design options and pick one.
- It is a copy of Pashmee's real frontend (`dg-soc/frontend/`, branch `claude/peaceful-edison-nvvyny`)
  taken on 31 Oct 2026. It runs on the fixture data, with no backend.
- It is **not** the product frontend. It lives on branch `m1/codex-design` and is **never merged
  into `main`**.
- Pashmee builds the chosen design into `dg-soc/frontend/` later. This folder's job is to make
  that choice easy: working variants, screenshots and a short decision note.

Read first: `START_HERE.md`, `CURRENT_FRONTEND.md`, `DESIGN_BRIEF.md`, then
`../frontend/DESIGN_SPEC.md` (Pashmee's full spec).

## 2. What you may touch

- **Write:** only `dg-soc/frontend-lab/`.
- **Read only:** everything else. In particular, never edit `dg-soc/frontend/` (Pashmee's real app),
  `dg-soc/contracts/`, `dg-soc/backend/`, `dg-soc/config/`, or any decoy, sensor or response folder.
- No commits to `main`, no pushes or pull requests unless Rohan or Pashmee asks in chat.

## 3. Run

```bash
cd dg-soc/frontend-lab
npm ci
VITE_USE_FIXTURES=1 npm run dev     # http://127.0.0.1:5174  (Pashmee's real app uses 5173)
npm run typecheck                   # must pass before you say a task is done
```

On Windows PowerShell: `$env:VITE_USE_FIXTURES='1'; npm run dev`.

The fixture is read from `../contracts/examples/events_p3.json`. Do not copy it or edit it.

## 4. How design options are built

- **Variant A is Pashmee's current design.** Never change how A looks. It is the baseline every
  option is compared against.
- Each new option is a variant (`b`, `c`, ...) switched with `?variant=b` in the URL plus a small
  floating switcher (bottom-right, lab only). Set `document.documentElement.dataset.variant`.
- Prefer token overrides: `:root[data-variant="b"] { --bg-base: ...; }` in
  `src/styles/variants/b.css`. Change structure (layout, component shape) only when the option
  needs it, and keep it behind `variant === 'b'` checks in a lab component.
- One variant per task. Name it in `DESIGN_OPTIONS.md` with a one-line idea and what it changes.
- Screenshots: every screen of every variant at **1440x900**, saved as
  `reference/<variant>/<screen>.png` (screens: overview, events, incidents, incident, transcript,
  graph, response).

## 5. Rules no variant may break

These come from `../frontend/DESIGN_SPEC.md` section 0, and from `dg-soc/AGENTS.md` sections 4 and 5.

1. **The browser never decides anything.** Score, severity, link status and block status are shown
   exactly as the API (or fixture) gives them. No arithmetic on scores, no optimistic "verified".
2. **Attacker text is hostile.** Render it as plain React children through `AttackerText`, mono and
   bounded. Never `dangerouslySetInnerHTML`, never syntax-highlight a command.
3. **Claim only what the evidence proves.** All wording comes from `src/copy.ts`. Never write
   "compromised", "exploited", "breached", "attacker isolated", "identified", "data stolen",
   "attack stopped", "safe" or "clear". Unreached stages say "not observed". Every finding shows its
   `label` and its `limitation` together.
4. Severity and status are never shown by colour alone: the word is always there too.
5. The `FIXTURES` chip stays visible in the topbar on every screen of every variant.
6. The transcript banner ("Commands submitted to an emulated shell. Nothing executed on a real
   host.") stays above the transcript and cannot be dismissed.
7. **No webfonts, CDNs or images from the internet.** The demo laptop is offline. System font stacks
   only; any image or icon must be a local file or inline SVG.
8. **Loopback only:** keep `host: '127.0.0.1'`.
9. **Dependencies:** none by default. If a variant truly needs one, say why, pin the exact version,
   and keep it inside `frontend-lab/`.
10. Projector-safe: body text contrast at least 7:1, secondary text at least 4.5:1, legible at
    1280x800. No mobile layout needed.
11. Keep the six global states (loading, empty, error, stale, degraded, refresh) working in every
    variant.

## 6. How to work (from `dg-soc/AGENTS.md` section 6)

- Before writing code, give a plan of 10 lines or fewer and the files you will change. Wait for OK.
- After each step, run `npm run typecheck` and report the real output. Never claim a screenshot,
  test or result you did not produce.
- End each task with: what changed, files changed, how to view it (URL with `?variant=`), checks run,
  known limits.
