# Design brief: what to explore and how the team picks

Goal: give the team two or three real, clickable design options next to Pashmee's current design
(variant A), so we can pick a direction quickly. The picked direction is then built properly in
`dg-soc/frontend/` by Pashmee.

Audience for the design: hackathon judges watching a live demo on a laptop or projector, plus the
analyst (one of us) clicking through it under time pressure.

## 1. Fixed: do not change these in any variant

- The seven screens, their routes and what data each shows (`CURRENT_FRONTEND.md`).
- The approved wording in `src/copy.ts`, and the rules in `AGENTS.md` section 5.
- The meaning of colours: four severities, plus `pending` = "needs a human" (never a severity
  colour), `ok` for confirmed/verified, the two inversions (auth accepted = red, blocked = green).
- Every finding shows label and limitation together. Every evidence ID stays clickable.
- The `FIXTURES` chip, the transcript honesty banner, the 3-step block flow (preview → approve →
  result), and "APPLIED" vs "VERIFIED" as separate states.

## 2. Open: what the options can differ on

Explore these, roughly in priority order. A variant does not need to change all of them.

1. **Overall visual direction** (tokens): surfaces, accent colour, border vs shadow, density,
   radius, type scale. Must stay projector-safe and dark-first.
2. **Incident Detail layout** (the screen judges watch longest): today it is two columns
   (evidence left, score/links/sessions/response right). Alternatives: a vertical timeline of the
   attack, or a story-first header with the kill chain as the hero.
3. **Kill-chain bar**: segmented bar today. Alternatives: stepped chevrons, a progress track with
   stage dots. Unobserved stages must still read "not observed".
4. **Overview hero**: how the noise-reduction claim ("1,284 raw events → 2 incidents") lands in
   one glance.
5. **Attack graph**: node and edge styling, and the dashed → solid "link confirmed" moment
   (the visual climax of the demo).
6. **Block flow modals**: clarity of scope ("web decoy only") and the APPLIED → VERIFIED change.
7. **Brand bits for the deck** (optional): a simple wordmark or logo as inline SVG, and a cover
   screenshot style for `docs/demo/`.

Suggested starting set (change if the team prefers):

| Variant | Idea |
|---|---|
| A | Pashmee's current design, untouched (baseline) |
| B | "Projector": higher contrast, larger type, fewer borders, bolder severity |
| C | "Console": denser analyst layout, timeline-first incident detail |

## 3. Output for each variant

1. Working variant at `http://127.0.0.1:5174/?variant=<x>` on fixture data.
2. Screenshots of all seven screens at 1440x900 in `reference/<x>/`.
3. A row in `DESIGN_OPTIONS.md`: idea, what changed (tokens, layouts, components), risks
   (contrast, effort for Pashmee to port), and an effort estimate (small, medium, large).

Codex takes screenshots with the Playwright MCP server (`CODEX_SETUP.md`). If that tool is not
set up, it says so, and Rohan or Pashmee takes them.

## 4. How the team picks, and the handback

1. The team compares variants on the projector or the laptop at 1440x900, using the screenshots and
   the live switcher.
2. Write the choice in `DECISION.md`: chosen variant, any pieces borrowed from others, and the
   exact token values and layout changes to port.
3. Pashmee implements it in `dg-soc/frontend/` (with Claude) on her own branch. Nothing is copied
   from `frontend-lab/` into `frontend/` blindly; `DECISION.md` is the handover.
