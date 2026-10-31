# M4 — Prajwal: web decoy, summaries and lab scenarios

`m4-upload/dg-soc/` contains the M4 handoff files, organized like `m2/m2-upload/dg-soc/`. The runnable integrated copy is in the repository root `dg-soc/`. Do development there; this upload folder is a handoff snapshot.

Includes the Flask web decoy and Dockerfile, redacted ingest-shaped JSONL, synthetic customer export, policy bridge, deterministic incident summaries, P1/P2/P3 lab scripts, tests and minimal Compose connections.

- Setup and run: [Web README](m4-upload/dg-soc/decoys/web/README.md)
- Owner connections and validation: [M4 handoff](m4-upload/dg-soc/scenarios/M4_HANDOFF.md)

The upload is an overlay, not a standalone application: it uses the shared contracts, honeytokens and web patterns from root `dg-soc/`. Apply only the required web-service wiring to M2's newer Compose file; do not overwrite M2's Cowrie changes with the older full Compose snapshot.

Validation: 51 M4 tests passed; Docker image built; real loopback HTTP smoke check passed with UID 1000, read-only root, schema-valid logs and atomic blocklist replacement. Physical-lab attack scripts and the complete dashboard demo remain unverified.
