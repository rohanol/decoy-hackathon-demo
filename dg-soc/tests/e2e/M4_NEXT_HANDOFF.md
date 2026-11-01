# Central Kali integration

The owner replaced the parallel portal/gateway milestone with direct central
integration of the existing Kali lab. Follow deployment/KALI_FOUR_RUNBOOK.md.
The earlier M4 handoff is retained in Git history; its proxy/theme/gateway
instructions are superseded.

This release incorporates M3's contract/runtime changes and M1's SOC consumers,
then adds native SMB, four-source adapter delivery, direct ZIP bait, a guarded
Linux lifecycle and four-service Compose. The old dark SOC and Operations
Portal stay in place. Original two-service Compose remains available.

Reproduce disposable loopback acceptance from dg-soc with Python test
dependencies, PyMySQL 1.1.2, Impacket 0.13.1 and Node/Playwright installed:

1. `python tests/e2e/kali_four_stack.py --output /tmp/kali-four-receipt.json`
2. Start the existing frontend on 127.0.0.1:15173, fixture mode off, API base
   http://127.0.0.1:18011 and local analyst entry enabled.
3. `node frontend/tests/e2e/kali-four.e2e.cjs`
4. Stop both test servers after checking the receipt/screenshots.

The stack generates labeled synthetic SSH/web traffic and actual MySQL/SMB
loopback protocol traffic. Every record crosses the real adapter and HTTP
backend. It asserts restart deduplication, four collector heartbeats, R11/R12
and ZIP-to-service links. Browser checks exercise protocol/archive details,
analyst confirmation, four graph nodes and web block/denial/verify/revoke.
`--once` exits after backend acceptance and cleans up temporary state.

These checks do not certify physical source IPs, Docker images, Linux lifecycle,
Cowrie transport channels or egress. Record native Kali acceptance separately.
