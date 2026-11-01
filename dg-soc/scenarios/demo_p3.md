# Evidence-led isolated demonstration

Owner: M4. Preserve the working lab and existing run data. This run sheet replaces
the former destructive reset commands and fixed-score promises.

## Prepare Laptop B

Keep the same reviewed release across decoys, adapter, backend and dashboard.
Back up the existing run before a migration or a deliberately fresh demo run.
Coordinate the new LAB_RUN_ID and any storage migration with M2/M3; do not clear
logs, databases or blocklists just to make a screen look clean.

Build/download dependencies with the decoys stopped. During lab activity, keep
Wi-Fi off, no IPv4/IPv6 default route, the decoys bound to 192.168.77.20, and SOC
ports bound to 127.0.0.1. Start backend, adapter and the live-mode dashboard.

Run `bash deployment/preflight.sh --static` before the manual source-IP probes,
then full preflight within five minutes of a new web request and SSH connection
from Laptop A. ALL PASS checks the existing deployment gates, not all review
acceptance criteria.

## Walkthrough

| Step | Laptop A action | Evidence to inspect |
| --- | --- | --- |
| 1 | Public landing and anonymous CSV request | Anonymous session; report denied with HTTP 401 |
| 2 | SSH failed logins, fake login, discovery and note read | Captured inputs; separate result/read proof only if M2 has instrumented it |
| 3 | Portal login with synthetic planted credential | HTTP/auth pair, shared request ID, rotated web session and token use |
| 4 | Authenticated dashboard, form and JSON search | Session/request context; sanitised body features, not a claim that SQL executed |
| 5 | Protected customer report | HTTP/file-result pair with complete-response digest and size |
| 6 | Public backup environment bait | Explicit bait-service result, token ID and issuance observation; HEAD proves no body service |
| 7 | Optional small synthetic UTF-8 text upload | Full accepted-file metadata; content discarded, no later download |
| 8 | Analyst inspects and decides a relationship | Show actual supporting endpoints and uncertainty; do not fabricate a read from command text |
| 9 | Manual web block, matching request, undo/expiry | Web policy denial and current verification state; SSH remains outside scope |
| 10 | Logout and retry protected report | Old session revoked; report denied again |

For a focused web-only workflow, run on Laptop A:

```bash
bash scenarios/web_depth.sh 192.168.77.20
```

The broader scripted scenario remains:

```bash
STEP_DELAY=6 bash scenarios/attack_p3.sh 192.168.77.20
```

Only run allowed-target scenarios in the authorised isolated lab. Component
tests execute refusal arguments only. Browser users must keep their login cookie;
the protected report can no longer be retrieved anonymously.

## Current integration limits

M4 produces compatible evidence but does not fix M3's source-based case pooling,
generic prior-event token lookup, R04/R07 mappings or body classification. It does
not implement M2's SSH read proof or trusted response-verification tuple. Until
those changes land, display the limitations and actual backend output; do not
promise an exact score, a proven actor chain or replay-safe response.

`issuance_id` identifies a serving observation, not a distinct per-client secret.
Do not describe two sessions sharing the static credential as proven same-person
activity. No institutional clone is included without reviewed local assets.

The correct claims are synthetic data served, input submitted to an emulated
shell, a candidate relation, and a narrow application-level web denial. Capture
a clean recording of the final reviewed Linux run as a demo fallback; replay
must be labelled and must not operate live policy.
