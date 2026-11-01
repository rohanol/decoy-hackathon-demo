# OC-05: controlled web trip and Chain Health

The Sensors screen adds an on-demand web-chain check using existing read APIs.
No backend, schemas, database migration, rules, ports, containers or scoring
weights change. This is one scoped OC-05 implementation, not completion of all
OC requirements or a certificate for SSH/MySQL/SMB/production attribution.

## Demo in under a minute

1. Keep the existing isolated Kali lab running. Open the SOC on Vedant and go
   to **Sensors → Chain health · controlled web trip**.
2. Click **Start web trip**. One active live run must exist; if it does not,
   make a normal portal request from attacker .10 and retry.
3. Copy the generated curl command and run it on attacker **192.168.77.10**
   within 90 seconds. It sends one SQL-shaped request to .20:8080/search.
   Expected status is the existing canned HTTP **500**; no SQL is executed.
4. The panel observes the exact nonce, .10 source, live run, fresh event,
   R07 SQLi finding citing that event and current web collector heartbeat/
   read/ingest evidence. It displays the real event/finding IDs and an incident
   link. All three stages must be observed before **Last web trip passed**.

Wrong source, replay, another run, old evidence, missing alert, missing/stale
collector data and backend read failure cannot yield a successful check.
The check stops polling after success or 90 seconds. A successful result is a
historical observation, not continuous health, and expires after five minutes.
Reload/navigation clears the local result; it is not written as a new backend
incident type or silently reused for another run. The trip itself is ordinary
observed lab traffic and its R07 finding remains in the SOC audit evidence.
The Sensors health panel continues to show ordinary current collection health.

The operator command runs only on the attacker; the SOC reads loopback APIs.
The browser never tries to contact the participant portal directly. Fixture
mode disables this control. There is no automatic block, confirmation, policy
change or direct event injection. No extra package or internet is needed for
this feature on a prepared lab.

## Verification

- Frontend: 54 unit tests, including exact nonce/source/run/time matching,
  alert evidence linkage, stale/missing collection, timeout and expiry.
- Production build/typecheck.
- Six browser checks using actual local curl → Flask → existing adapter →
  HTTP backend/R07 → UI. The local fixture explicitly supplies a synthetic
  .10 peer; it does not prove physical source preservation. Browser checks
  also reject defender-source traffic, a stored response without its alert,
  and unavailable evidence reads, with no page errors/external requests.
- Native two-laptop trip remains to be run with the displayed command.

Reproduce the browser check with the existing test dependencies:

```bash
python tests/e2e/kali_four_stack.py --trip-web-port 18080
# In another terminal, start Vite with VITE_API_BASE=http://127.0.0.1:18011,
# VITE_USE_FIXTURES=0 and VITE_AUTH_LOCAL=1, port 15173.
node frontend/tests/e2e/controlled-trip.e2e.cjs
```

The optional test endpoint binds only to loopback and is never launched by
deployment/kali_lab.sh. Its peer override exists solely in that test fixture.
The launcher now supplies VITE_AUTH_LOCAL=1 for M1's already-merged local
sign-in; the previous flag is retained for older frontend compatibility.
