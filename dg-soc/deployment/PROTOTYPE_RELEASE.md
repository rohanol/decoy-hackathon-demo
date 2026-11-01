# Integrated prototype release — 1 November 2026

The project owner explicitly authorized centralized integration, cross-owner
bug fixes and merging the member PRs into main. This release retains the full
member commit history and resolves the overlapping web changes together.

Included PR heads: M2 #8/#13 29096cf, M3 #9 b67c6e6, #11 d638c38, #14 2aff611,
#15 4b24c4b, #16 ab01a6f; M1 #10 e8eef3d; M4 #12 79ae697.

## Changes completed during integration

- Adapter validation accepts all 19 agreed indicator names and still rejects
  invalid versions/features. Actual producer records survive the complete path.
- Heartbeat ingest accepts current process_state/nested counters, preserving
  per-sensor values. Earlier flat-counter records remain compatible; mixed wire
  formats and incomplete modern counters fail validation.
- Verification_mismatches is the canonical rich refusal field. Historical generic
  reasons remain generic rather than being relabelled outside_window.
- Apply/revoke/list return complete action records, including run/case/revision,
  so immediate dashboard cards have valid target and timing fields.
- The dashboard reads backend cases, source profiles, investigations, eligibility,
  mapping rationale, bait provenance and collector health. It labels actual case
  scores separately from legacy source scores and does not invent a parent.
- Static-token ambiguity and request-only relations remain explicit. Response is
  always backed by authoritative preview/apply and post-commit verification.
- Live and replay observations in the loaded library get a combined label;
  per-case modes remain distinct. Only the two deployed decoys are listed.
- Compose selects web schema 1.1. The standalone Flask default remains 1.0.
- The obsolete trailing-dashes xfail was promoted to a normal passing regression.
- The browser evidence test now uses current case semantics and actual generated
  denied-request logs rather than a fabricated partial verification event.

## Verification actually performed

Windows Python 3.12, Node 24.16.0 and installed headless Edge. Explicit Git Bash
was selected for scenario refusal tests; no allowed-target attack script ran.

| Check | Result |
|---|---|
| Combined Python suite: backend, sensors, response, policy, SSH, deployment, web/e2e | 613 passed; one Starlette/httpx deprecation warning; 46.22 s |
| Frontend Node unit suite | 34 passed across five files |
| Typecheck and production build | Passed; existing large-chunk warning |
| Release JavaScript scan | No development fixture markers |
| Compose config, Python compilation, git diff whitespace | Passed |
| Browser integrated evidence/response acceptance | 13 checks passed, no page errors |
| WebSocket disconnect/reconnect with a held snapshot | 50 backend and 50 displayed events; zero missing, duplicate or extra IDs |
| Offline local-analyst entry | Passed; zero external requests attempted |
| Mixed library label / two deployed sensor cards | Passed |

The 13 browser checks cover real collector heartbeat display; authoritative cases
and scores; escaped attacker text with no injected HTML; actual bait-service
provenance; analyst-created investigation; preview/apply with complete action
data; denied web request through the real adapter and trusted backend callback;
verified action; revoke and restored access; investigation dissolve after
reversal; replay response disabled; 2D/network graphs; and no page errors.

Two early browser harness assertions used a wrong CSS class and a case-sensitive
label comparison. Correcting the test selectors passed; no product behavior was
changed to satisfy those assertions. The old unit test treating bait_served as an
unknown type was updated because it is now a supported type. A legacy migration
test now expects the preserved generic reason deliberately.

These checks used temporary local databases, policies and generated sensor
records. They are not physical captures. No Docker daemon was available here:
the rebuilt image, pinned Cowrie runtime, source-IP proof, channel/SFTP/forwarding,
network egress and physical two-laptop run still require Vedant's Linux engine.

## Startup and rollback

Use [PROTOTYPE_RUNBOOK.md](PROTOTYPE_RUNBOOK.md). Prepare a separate checkout,
backup the stopped deployment, snapshot its database, start a new lab run with
fresh sensor logs/checkpoints, build while decoys are stopped, restore isolation,
then start the host services and decoys. Preserve the original deployment for
rollback; old code must not open a newly migrated database.
