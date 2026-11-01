# Four-honeypot integration acceptance — 1 November 2026

The current release keeps the original Kali deployment, dark SOC and Operations
Portal. It integrates M3's v1.2 contract/runtime and M1's SOC consumers, then
adds direct ZIP bait, a bounded SMB producer, four-source collection and a
guarded Linux start/status/stop/logs helper. The canceled portal/gateway app
branches are not deployed. Original two-decoy Compose remains available.

## Checks actually run

- Python backend/sensors/response/decoys/deployment/end-to-end regression on
  Windows: **805 passed**, one Starlette/httpx deprecation warning, with Python
  3.12 and Git Bash for Bash scenarios. PyMySQL 1.1.2 and
  Impacket 0.13.1 exercised actual loopback protocol traffic. Impacket's wheel
  supplied its Python modules because the Windows example-script installation
  failed; no Impacket command-line attack tools were used.
- Frontend: 45 unit tests, typecheck and production build with Node 24.16.
  Provisional fixture markers were absent from emitted JavaScript. Existing
  3D bundle size warning remains.
- Four-source acceptance: 41 generated events passed through the actual
  adapter and HTTP backend, with no duplicates on checkpoint reload, four
  fresh collector heartbeats, MySQL proof/query refusal, SMB proof/read/inert
  upload, R11/R12 and ZIP-to-service credential links. SSH/web participants
  were synthetic; MySQL/SMB clients used actual loopback sockets. Physical
  source-IP capture is explicitly false in the receipt.
- Four-source browser acceptance: ten checks, including protocol/archive
  evidence, four graph nodes, analyst confirmation, preview/apply pending,
  collected denial through trusted backend verification, and revoke to 200.
  Zero page errors and external requests.
- Original prototype browser flow: thirteen checks passed. Reconnect preserved
  all 52 backend events with zero missing/duplicate/extra rows. Offline analyst
  entry passed with zero external requests attempted.
- Both Compose files parse together; each modified/new deployment shell script
  passes Bash syntax checking. Scoped Git whitespace checks pass.

## Operational limits

No Docker daemon or physical Kali machines were available here. Image builds,
native Linux process-group lifecycle, actual .10 peer preservation, port
conflicts, egress and physical Cowrie forwarding/SFTP acceptance are pending.
Run deployment/KALI_FOUR_RUNBOOK.md and record the release commit plus native
outputs before calling the physical lab accepted.

MySQL is authentication deception, not a database engine; data queries are
refused. SMB supports a narrow SMB2.0.2/NTLMv2 client flow, fixed synthetic
reads and bounded inert uploads, not full Windows Explorer/RPC compatibility.
There is no malware execution or verdict. ZIP serving never proves download
or extraction. Static-credential attribution can remain ambiguous. Response
blocks only the web decoy and does not enforce on SSH/MySQL/SMB.

See tests/e2e/M4_NEXT_HANDOFF.md for reproducible disposable acceptance and
the protocol-service READMEs for supported operations and resource limits.
