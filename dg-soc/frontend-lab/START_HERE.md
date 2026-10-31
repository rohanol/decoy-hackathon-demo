# Start here (Rohan and Pashmee, using Codex)

This folder is a design playground: a copy of Pashmee's frontend that runs on fixture data, for
trying design options with Codex and picking one. It is not the real frontend. See `AGENTS.md`.

## Files

| File | Purpose |
|---|---|
| `AGENTS.md` | Rules Codex reads automatically when started in this folder |
| `CODEX_SETUP.md` | Tools to add to Codex first (Playwright browser for screenshots) |
| `reference/a/` | Baseline screenshots of Pashmee's current design |
| `CURRENT_FRONTEND.md` | Short summary of what Pashmee built (screens, components, tokens) |
| `DESIGN_BRIEF.md` | What is fixed, what to explore, what each option must produce |
| `DESIGN_OPTIONS.md` | Codex fills this: one row per variant |
| `DECISION.md` | The team fills this after picking; it is the handover to Pashmee |
| `../frontend/DESIGN_SPEC.md` | Pashmee's full design spec (read-only) |

## One-time setup

```bash
git fetch origin
git switch m1/codex-design
cd dg-soc/frontend-lab
npm ci
```

Run it (no backend needed):

```bash
VITE_USE_FIXTURES=1 npm run dev
```

PowerShell:

```powershell
$env:VITE_USE_FIXTURES='1'; npm run dev
```

Open http://127.0.0.1:5174. You should see the amber `FIXTURES` chip in the topbar.

## Add Codex tools (once per laptop)

Follow `CODEX_SETUP.md`. At minimum add the Playwright MCP server, so Codex can open the app
and take screenshots itself.

## Start Codex in this folder

Open Codex with `dg-soc/frontend-lab` as its working folder, so it picks up both
`dg-soc/AGENTS.md` and this folder's `AGENTS.md`. Then paste the first prompt below.

### First prompt: set up the variant switcher and DESIGN_OPTIONS.md

```
ROLE = M1     NAME = [Rohan | Pashmee]     BRANCH = m1/codex-design
TASK = Add a lab-only variant switcher (?variant= plus a floating bottom-right control) with
       variant A = current design unchanged, and create DESIGN_OPTIONS.md with a row for A.
ACCEPTANCE = AGENTS.md sections 4 and 5 hold; npm run typecheck passes; ?variant=a looks
       identical to the current app.
MAY TOUCH = dg-soc/frontend-lab/ only
DO NOT TOUCH = everything else, especially dg-soc/frontend/ and dg-soc/contracts/
INPUTS I HAVE = CURRENT_FRONTEND.md, DESIGN_BRIEF.md, ../frontend/DESIGN_SPEC.md,
       ../contracts/examples/events_p3.json
First: summarise your plan and the files you will change in under 10 lines, then wait for my OK.
```

### Next prompts: one variant each

```
ROLE = M1     NAME = [Rohan | Pashmee]     BRANCH = m1/codex-design
TASK = Build variant B "Projector" from DESIGN_BRIEF.md section 2: higher contrast, larger type,
       fewer borders, bolder severity. Tokens first; layout only where needed.
ACCEPTANCE = AGENTS.md section 5 holds in variant B; variant A unchanged; typecheck passes;
       DESIGN_OPTIONS.md row for B filled.
MAY TOUCH = dg-soc/frontend-lab/ only
DO NOT TOUCH = everything else
First: summarise your plan and the files you will change in under 10 lines, then wait for my OK.
```

Repeat with C ("Console": denser layout, timeline-first incident detail), or any idea the team
wants. One variant per prompt.

### Checking Codex's work

- Open `?variant=a` and the new variant side by side; click every screen in the sidebar.
- Check the never-break list in `AGENTS.md` section 5, especially: wording (no "compromised",
  "exploited", "isolated"), the `FIXTURES` chip, the transcript banner, "not observed" on the
  kill-chain bar.
- Ask "what did you actually run?" if it reports results without output.

## When the team has picked

Fill `DECISION.md` (chosen variant, borrowed pieces, exact token and layout changes). Pashmee
uses it to build the real thing in `dg-soc/frontend/` with Claude.
