# M2 gateway and service integration status

## Start, status, logs, stop

On the native Linux lab VM, after completing the preparation and isolation steps in
`PROTOTYPE_RUNBOOK.md`, run from `dg-soc/`:

```bash
bash deployment/labctl.sh start
bash deployment/labctl.sh status
bash deployment/labctl.sh logs
bash deployment/labctl.sh stop
```

`start` checks native Linux, Docker Engine, no IPv4/IPv6 default route, the local
virtual environment and frontend dependencies. It launches the host backend,
loopback dashboard and sanitized adapter, then starts Cowrie and the existing
web decoy. It does not run with Docker Desktop, WSL, privileged containers, or a
Docker socket mount.

The gateway is an opt-in Compose profile. After M1 supplies a normal application
on the fixed lab address and port in `NORMAL_APP_UPSTREAM`, start with
`bash deployment/labctl.sh start --gateway`. It is bound to `LAB_HOST_IP:8081`
using Linux host networking so the socket peer remains the client; the gateway
strips all incoming forwarding/routing headers and constructs its own peer
header. The current M4 web app ignores trusted proxy headers, so response events
from a proxied client would currently show the gateway's socket address. M4 must
add a single-hop allowlist for this gateway before gateway-forwarded observations
can be used for incident attribution or response eligibility. Do not add the
gateway address to `ATTACKER_IPS` or relabel it as the client.

Gateway sessions use a mode-0600 random signing key in the dedicated ignored
`deployment/state/gateway/` directory, a 15-minute default TTL and 4,096-entry
cap. A signed cookie maps to bounded in-memory route state; expired, tampered,
unknown-after-restart, and capacity-exhausted sessions fail closed. A new exact
`/backup/backup.zip` request is assigned to the decoy before any upstream call;
all later requests in that session stay on that upstream. Other sessions stay on
the configured normal application. Cookies, authorization, forwarded headers,
request bodies, and query strings are not logged or copied between applications.
The gateway makes one upstream request only and returns 502 if its selected
upstream is unavailable. It rejects unsupported Host values, unknown upstream
hosts, request upgrades, transfer encoding, and bodies over 1 MiB.

## Pending contract and upstream work

The fetched `origin/main` v1.1 schema accepts only `ssh-decoy-01` and
`web-decoy-01`; there are no `db-decoy-01` or `file-decoy-01` event definitions.
Do not create accepted events under those IDs until M3 publishes the frozen
schema, heartbeat shape, and example records. Required M3 additions: sensor IDs,
allowed event types, event-specific required attributes, redaction rules,
source/session provenance, health/heartbeat fields, and representative live and
replay records. Adapters must version-gate support and reject unknown versions.

The checked-out repo has no M1 normal application listener, no MySQL deception
producer, and no SMB producer. `NORMAL_APP_UPSTREAM` defaults to the reserved
lab address `192.168.77.20:8082`; `--gateway` refuses to start unless it answers.
The current portal remains `web-decoy-01` on 8080. The synthetic archive asset
is under `decoys/files/assets/backup.zip`, but the current M4 app does not serve
that exact path. M4 must add its own instrumented route and actual server-side
`bait_served` record before a served file can be truthfully ingested. The asset
contains only an explanatory text file and synthetic CSV.

Dionaea implements actual SMB and is GPL-2.0-or-later. Its upstream documentation
reports default shellcode emulation, downloaded-file storage, and configurable
external submission, which violate this lab's containment rules unless removed.
The upstream repository currently publishes no tagged releases. No pinned SMB-
only build was validated, so this branch does not enable an unsafe third-party
sensor or mislabel a TCP banner as SMB. Physical Linux checks for safe SMB
negotiation, source-IP capture, credentials-before-log redaction, native service
health and event provenance remain required after the upstream M3/M4 components
are ready.
