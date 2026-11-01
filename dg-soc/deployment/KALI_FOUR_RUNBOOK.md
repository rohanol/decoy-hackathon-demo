# Existing Kali lab, four honeypots

This release retains the existing dark SOC on 127.0.0.1:5173 and the existing
Operations Portal on 192.168.77.20:8080. It adds inert ZIP bait, MySQL on 3306,
and bounded SMB2 on 445. There is no gateway, normal demo app, new portal design,
public hosting or AI model in the runtime path.

The original docker-compose.yml remains a two-decoy entry point. Add
docker-compose.four.yml to opt in to the two additional containers and web
schema 1.2. The four-decoy override disables container auto-restart: a boot
must pass the isolation guard before this mode is started.

## Preserve the working installation

Use the existing PROTOTYPE_RUNBOOK.md backup/new-checkout procedure. Stop the
old three host services with Ctrl+C and stop its two containers; do not use
down -v, delete state, reset a working checkout or overwrite an old database.
Archive its state and snapshot the stopped database into a fresh release.
Migrations retain backups. Old backend code must use its retained old database,
not a newly migrated one. Keep the old checkout for rollback.

## Prepare while temporary NAT is available

Run on Vedant's native-Docker Kali VM, in the **fresh release's dg-soc** folder.
Decoys must be stopped during all preparation/downloads. Leave eth0's lab IP
unchanged. Use the previously configured DG-TEMP-NAT/eth1 only for this phase.
Use Python 3.11+ and a maintained Node version; this release was built with
Node 24.16. The TypeScript unit-test launcher requires Node 22.6 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r sensors/requirements.txt
python -m pip check
npm ci --prefix frontend --ignore-scripts
npm run build --prefix frontend
bash deployment/bootstrap_state.sh
docker pull cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d
python deployment/cowrie_image.py build
chmod 644 deployment/cowrie/cowrie.cfg deployment/cowrie/userdb.txt \
  decoys/ssh/fs.pickle decoys/ssh/lab_command_registry.py decoys/ssh/lab_network.py
python decoys/ssh/check_image.py
bash deployment/kali_lab.sh build
```

Settings remain in deployment/lab.env: LAB_HOST_IP=192.168.77.20,
ATTACKER_IPS=192.168.77.10, BACKEND_URL=http://127.0.0.1:8000, LAB_RUN_ID=current
run. Use a new LAB_RUN_ID and fresh sensor logs/checkpoints only for a deliberate
new run, retaining prior evidence in the backup. Do not relabel old raw logs as
new live evidence. Resume uses the same run/state.

Prepare the attacker VM's probe dependencies before returning to isolation:
PyMySQL==1.1.2 and impacket==0.13.1 in an appropriate local virtual environment.
Do not download them automatically from an attack script. The server runtime
dependencies for SMB live inside its prepared image; the host adapter uses
the root Python environment already installed above.

## Restore isolation, then start

```bash
sudo nmcli connection down DG-TEMP-NAT
sudo nmcli radio wifi off
ip -4 route show default
ip -6 route show default
source .venv/bin/activate
python deployment/lab_checks.py host
bash deployment/kali_lab.sh start
```

Both default-route outputs must be empty. Disconnect VirtualBox Adapter 2's
cable again. Keep the isolated Ethernet lab connection. Open the original SOC
on Vedant at http://127.0.0.1:5173 and select Continue as lab analyst.

The lifecycle helper refuses occupied SOC ports, unknown existing containers,
partial launches and unsafe networking. It tracks only process groups launched
from this checkout, keeps persistent logs, and cleans up its own partial launch.
It does not kill arbitrary Python/Node processes. Initial Docker/service-start
checks do not prove protocol readiness; perform the client probes below.

Manual terminals remain supported: backend `python -m backend.main`; frontend
the existing fixture-free/local-analyst Vite command; decoys with both Compose
files; adapter `python sensors/adapter.py --backend http://127.0.0.1:8000
--capture-mode live`. Its default sources now include database/file logs.

## Test from attacker 192.168.77.10

Use the original SSH test and submit a few emulated commands:

```bash
ssh -p 2222 dg_demo@192.168.77.20
# Lab password: DemoPass-2026
# Inside: pwd; ls -la; cat notes.txt; exit
```

With this repository's scenario available on the attacker:

```bash
python3 scenarios/next_bait.py 192.168.77.20 --exercise-failures
```

The probe uses the original web port 8080, verifies the fixed ZIP in memory,
tries the planted MySQL credential and expects data-query refusal, then uses
the planted SMB credential for the fixed README and a harmless text upload.
It refuses every target except the lab address. No file is executed/extracted
and no real malware is needed. Successful output is client evidence, not a
claim that the SOC collected it: inspect actual events, cases, R11/R12,
credential links and current health on the dashboard.

Then on Vedant:

```bash
bash deployment/preflight_four.sh
```

This requires fresh source-IP evidence from .10 on **all four** services.
Do not use Vedant's browser for the participant portal while gathering that
proof. SOC access stays local to Vedant. A window with defender/gateway peer
IPs is not a successful physical source-IP check.

Test web response last: preview/apply from a live web case, issue another web
request from .10, wait for collected 403 -> verified, revoke and confirm 200.
MySQL/SMB cases correctly disable this web-only action. SSH is also unaffected
by web blocking. Archive response/credential evidence never proves extraction
or personal identity; repeated static credential servings stay ambiguous.

## Stop, status and rollback

```bash
bash deployment/kali_lab.sh status
bash deployment/kali_lab.sh logs
bash deployment/kali_lab.sh stop
```

Stop preserves database, logs, checkpoint, sample quarantine and policy history.
Do not reconnect NAT while decoys run. On a full sample quarantine, archive
evidence deliberately before removing old samples; the server does not evict it.
Rollback stops this release and resumes the retained old checkout/database.

## Verification boundary

Windows loopback acceptance can test protocol clients, adapter delivery,
backend rules, SOC screens and response. It cannot certify native Docker
images, Linux process-group lifecycle, actual 192.168.77.10 source preservation,
port conflicts, host egress or the physical Cowrie channels. Record those Kali
outputs with the release commit before calling the physical lab accepted.
