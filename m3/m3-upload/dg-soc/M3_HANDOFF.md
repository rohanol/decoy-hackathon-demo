# M3 handoff (Rohan): backend

## What and why
Backend tasks 1-7 from `prompts/M3_backend.md`. Everything lives in `dg-soc/backend/`, plus `dg-soc/requirements.txt`, `.gitignore` and `.env.example`.

1. **What works now**
   - `POST /api/ingest/events` validates each event against `event.schema.json`. Batches are capped at 100 events and 1 MiB.
   - Duplicates are detected by `(sensor_id, source_record_id)`. Each new event gets an `event_id` and a global `seq`.
   - There is one incident per `src_ip` per `lab_run_id`.
   - `/ws/events` sends `event`, `finding`, `link` and `incident` messages, always after the database commit.
   - Rules R01, R02, R03, R04, R05, R07, R08 and R09 live in `backend/rules/`, one file per rule. They run in the same database transaction as each ingest.
   - Scoring reads `config/scoring.yaml`. Each rule counts once per incident, R05 and R09 count only after the analyst confirms the link, the total is capped at 100, and `score_breakdown` has one row per finding.
   - Links: `candidate` means the same IP was seen on both decoys within 300 s. `strong_candidate` means a honeytoken was reused on the other decoy. `POST /api/links/{id}/decision` can confirm or reject, and the decision can be reversed.
   - Read routes: `GET /api/incidents`, `/api/incidents/{id}`, `/transcript`, `/export`, `/api/links`, `/api/stats/overview`, `/api/health`.
   - Hooks for teammates' code:
     - Vedant: `response/router.py` (`router`, `on_event(event)`, optional `active_block(src_ip)`). Until it exists, `/api/response/*` returns 503.
     - Prajwal: `analyst/summarise.py` (`summarise(incident)`). Until it exists, the backend writes a rule-based summary.
2. **Files and config:** `backend/{main,db,models,config,scoring,links,integrations}.py`, `backend/rules/*`, `backend/tools/load_fixtures.py`, and `backend/tests/*`. Two optional environment variables: `DG_DB_PATH` (default `backend/data/dg.db`) and `DG_CONFIG_DIR` (default `config/`).
3. **Example:** after loading `contracts/examples/events_p3.json` (contract v1.0), `inc_01` scores 95 (critical) with R09 pending. Confirming the `strong_candidate` link takes it to 100.

## How I tested (real commands and output)
```
python -m pytest backend -q           -> 102 passed
python -m backend.main                -> listening on 127.0.0.1:8000 only
python -m backend.tools.load_fixtures -> 200 {"accepted":23,"duplicates":0,"rejected":[]}
python -m backend.tools.load_fixtures -> 200 {"accepted":0,"duplicates":23,"rejected":[]}
```
- The test that walks the demo path gets 25, 40, 50, 65, 95, then 100, with R04 trimmed by the cap.
- R01 boundaries pass: 4 failures no, 5 yes, 5 spread over 61 s no, exactly 60 s yes.
- R07 passes every positive and negative vector in `payloads.json`.
- `blocked_request` events never add points.
- The export contains no `password_sha256`.

Run from `dg-soc/`:
```
pip install -r requirements.txt
python -m backend.main
```

**Not tested**
- No real Cowrie event has gone through the backend yet; that's the H4 check with M2.
- Tested on Python 3.13, not 3.11.
- R08 is only covered by unit tests, because nothing in the fixture triggers it.

## Reviewer: please check
- Pashmee (M1): please check the response shapes against `contracts/API.md`.
- One addition beyond the contract: each `score_breakdown` row also has `finding_id`, so the UI can match a row to its finding.
- New pinned dependency: `PyYAML==6.0.3`, used to read the `config/*.yaml` files.

## Known limitations and next steps
- This PR is about 1,960 lines, well over the ~300-line guideline, because tasks 1-7 landed together.
- M2: add `router` and `on_event` to `response/router.py`. M4: add `summarise` to `analyst/summarise.py`.

## Contract change?
- [ ] yes
- [x] no (the `finding_id` field in breakdown rows is additive)



