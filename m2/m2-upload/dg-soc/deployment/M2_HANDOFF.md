# M2 handoff (AGENTS.md section 11)

Branch: `m2/sensors-response` (never pushed to `main`). PR title: `[M2] sensors, response, policy, deployment`.

## 1. What works now (tested here, no Docker available)
- `decoys/policy/policy.py`: `check(ip) -> action_id | None`, ignores expired, fails open on bad file. 5 tests.
- `response/router.py`: preview (valid 60 s) / apply / revoke / list, `on_event(event)` verify hook, TTL expiry, atomic `blocklist.json`. 13 tests: wrong IP, expired preview, revoke restores access, expiry, verify.
- `sensors/adapter.py`: Cowrie + web log mapping, password hashing + honeytoken match, byte-offset checkpoint, batching, retry. 14 tests incl. restart-no-resend and backend-down-no-loss.
- `decoys/ssh/patch_fs.py` + `build_fs.sh`: adds `/home/dg_demo/notes.txt` to Cowrie's fake filesystem. 3 tests on a synthetic tree.
- `deployment/`: `bootstrap_state.sh`, `pin_cowrie.sh`, compose mounts `fs.pickle`, extra preflight checks.

## 2. Integration for Rohan (M3)
```python
from response.router import router, on_event, configure
app.include_router(router, prefix="/api/response")
on_event(event)            # call after each ingested event has its event_id
# optional: configure(incident_lookup=lambda incident_id: src_ip_or_None)
```
Default lookup calls `GET {BACKEND_URL}/api/incidents/{id}` and reads `src_ip`. Handlers are sync `def` so that self-call does not deadlock.
Run tests from `dg-soc/`: `python -m pytest sensors/tests response decoys/policy decoys/ssh -q` (32+3 tests).

## 3. For Prajwal (M4)
Adapter expects `web.json` = one JSON object per line shaped like `contracts/event.schema.json` (envelope fields are filled if missing). A key named `password` is hashed and removed. Blocked requests must log `event_type=blocked_request` with `attributes.block_action_id` from `policy.check()`.

## 4. NOT verified (needs Docker + Kali, do before the event)
- Cowrie image pin, in-container paths, `cowrie.cfg` option names (incl. `[shell] filesystem`), fs.pickle node layout, where `dg_demo` lands after login: run `deployment/pin_cowrie.sh`, then `decoys/ssh/build_fs.sh`, then `ls` and `cat notes.txt` over SSH.
- Task 1: Kali -> 2222 with Cowrie logging `src_ip` 192.168.77.10 (LAB_NETWORK.md). Biggest risk.
- `cowrie_sample.json` is SYNTHETIC. Replace with 20 real sanitised lines and send to Rohan.
- Real preflight run (ss/docker are missing in my sandbox, so only the new checks were exercised).
- Nothing was pushed: no GitHub credentials in the sandbox.

## 5. Known gaps
- Previews are in memory (lost on backend restart; actions and blocklist survive).
- Block TTL limited to 10 to 600 s. One active block per IP.
- `client_version` pending state is lost if the adapter restarts between the version line and the next event.
