# M2 Progress Log (append-only, newest at bottom)

Owner: Vedant (M2). Rule: one row appended after every finished file. Never edit old rows.

> **TOKEN WARNING:** Claude usage is shared between chat and Claude Code and resets in 5-hour windows,
> with a weekly cap. If the agent says it is near the limit: stop, write a HANDOFF block at the bottom,
> commit, and push to `backup` first. Anything not committed and pushed is lost when the session ends.

Push order for every file: 1) `git push backup m2/sensors-response`  2) `git push origin m2/sensors-response` (never `main`).

| Time (IST) | Agent | File | M2 done (est.) | Next | Pushed to backup |
|---|---|---|---|---|---|
| 2026-10-31 17:07 | Claude (M2) | `.gitignore` | 3% | policy module | pending |
| 2026-10-31 17:07 | Claude (M2) | `deployment/state/.gitignore` | 5% | policy module | pending |
| 2026-10-31 17:07 | Claude (M2) | `decoys/policy/policy.py` | 12% | policy tests | pending |
| 2026-10-31 17:07 | Claude (M2) | `decoys/policy/test_policy.py` | 15% | response router | pending |
| 2026-10-31 17:07 | Claude (M2) | `response/__init__.py` | 16% | router | pending |
| 2026-10-31 17:07 | Claude (M2) | `response/router.py` | 40% | router tests | pending |
| 2026-10-31 17:07 | Claude (M2) | `response/test_router.py` | 45% | sensors adapter | pending |
| 2026-10-31 17:09 | Claude (M2) | `sensors/requirements.txt` | 47% | adapter | pending |
| 2026-10-31 17:09 | Claude (M2) | `sensors/adapter.py` | 65% | adapter tests | pending |
| 2026-10-31 17:09 | Claude (M2) | `sensors/tests/fixtures/cowrie_sample.json` | 66% | adapter tests | pending |
| 2026-10-31 17:09 | Claude (M2) | `sensors/tests/test_adapter.py` | 72% | deployment + fsctl | pending |
| 2026-10-31 17:10 | Claude (M2) | `decoys/ssh/patch_fs.py` | 78% | ssh fs test | pending |
| 2026-10-31 17:10 | Claude (M2) | `decoys/ssh/test_patch_fs.py` | 80% | build script | pending |
| 2026-10-31 17:10 | Claude (M2) | `decoys/ssh/build_fs.sh` | 82% | bootstrap | pending |
| 2026-10-31 17:10 | Claude (M2) | `deployment/bootstrap_state.sh` | 84% | pin script | pending |
| 2026-10-31 17:10 | Claude (M2) | `deployment/pin_cowrie.sh` | 86% | compose/cfg | pending |
| 2026-10-31 17:10 | Claude (M2) | `deployment/docker-compose.yml` | 88% | cowrie.cfg | pending |
| 2026-10-31 17:10 | Claude (M2) | `deployment/cowrie/cowrie.cfg` | 89% | preflight | pending |
| 2026-10-31 17:10 | Claude (M2) | `deployment/preflight.sh` | 92% | docs/handoff | pending |
| 2026-10-31 17:10 | Claude (M2) | `.gitignore` | 93% | handoff | pending |
| 2026-10-31 17:11 | Claude (M2) | `deployment/M2_HANDOFF.md` | 95% | push branch, run pin_cowrie + lab network test | pending |
