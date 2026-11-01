# Integrated prototype — Vedant's native Docker Engine / Kali VM

This release combines M1–M4, case/investigation APIs, causal token links, current
adapter indicators, canonical/legacy heartbeats, truthful refusal migration and
the dashboard consumers. Compose selects web schema 1.1. Keep SOC ports on
loopback and decoy ports on 192.168.77.20. No Docker Desktop is involved.

Use a fresh release directory. The old working deployment, full backup and old
sensor logs stay available for rollback. The new run has fresh sensor logs and
checkpoints so old Cowrie lines are not relabelled as a new live run. A database
snapshot retains prior observed evidence and is migrated with backups by the
backend. Do not copy the old adapter checkpoint to a different absolute path.

## 1. Stop the old services and take a backup

In the three old backend/frontend/adapter terminals press Ctrl+C. In a fourth
terminal on Vedant's VM run this block (stop containers, not volumes):

```bash
old="$HOME/DeceptionGraphLab/dg-soc"
cd "$old"
docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env stop cowrie web-decoy
backup="$HOME/DeceptionGraphLab/backups/prototype-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup"
tar --exclude=.git --exclude=.venv --exclude=frontend/node_modules \
    --exclude=frontend/dist -cf "$backup/project.tar" -C "$old" .
printf 'Backup saved: %s/project.tar\n' "$backup"
```

The uncompressed archive includes prior logs, database, policy/action history,
checkpoints and lab settings. Keep the printed path. Check that no old host
service is still listening on 8000/5173 with `ss -ltnp` before proceeding.

## 2. Prepare a new checkout while temporary internet is available

Use the already configured DG-TEMP-NAT profile only if eth1 is present. Decoys
must remain stopped during preparation. Do not alter the isolated eth0 address.

```bash
ip -br link
sudo nmcli connection up DG-TEMP-NAT ifname eth1
release="$HOME/DeceptionGraphLab/prototype-$(date -u +%Y%m%dT%H%M%SZ)"
git clone --branch main --single-branch https://github.com/rohanol/decoy-hackathon-demo.git "$release"
cd "$release/dg-soc"
printf '%s\n' "$PWD" | tee "$HOME/DeceptionGraphLab/current-prototype-path.txt"
git rev-parse HEAD
cp "$old/deployment/lab.env" deployment/lab.env
python3 - <<'PY'
from datetime import datetime, timezone
from pathlib import Path
p = Path('deployment/lab.env')
lines = p.read_text().splitlines()
run = 'run-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
lines = [line for line in lines if not line.startswith('LAB_RUN_ID=')]
lines.append('LAB_RUN_ID=' + run)
p.write_text('\n'.join(lines) + '\n')
print('New live run:', run)
PY
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r sensors/requirements.txt
python - "$old/backend/data/dg.db" "$PWD/backend/data/dg.db" <<'PY'
import sqlite3, sys
from pathlib import Path
source, destination = map(Path, sys.argv[1:])
if source.is_file():
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(source)) as before, sqlite3.connect(str(destination)) as after:
        before.backup(after)
    print('Prior database snapshot preserved in the new checkout')
else:
    print('No prior database at this path; backend will create a new database')
PY
npm ci --prefix frontend --ignore-scripts
npm run build --prefix frontend
bash deployment/bootstrap_state.sh
docker pull cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d
python deployment/cowrie_image.py build
chmod 644 deployment/cowrie/cowrie.cfg deployment/cowrie/userdb.txt \
  decoys/ssh/fs.pickle decoys/ssh/lab_command_registry.py decoys/ssh/lab_network.py
docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env build web-decoy
docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env config -q
```

If the exact pinned Cowrie image is missing, `cowrie_image.py build` reports the
problem; pull that pinned image during preparation, then repeat the build step.
Do not repin to a different image. Node 22.6+ is needed for `npm test`; it is not
necessary to rerun all developer tests merely to start the lab.

## 3. Return to isolation before starting the decoys

```bash
sudo nmcli connection down DG-TEMP-NAT
sudo nmcli radio wifi off
ip -4 route show default
ip -6 route show default
python deployment/lab_checks.py host
```

Both default-route outputs must be empty and the host check must pass. If a
different internet connection is still active, stop it before starting decoys.

## 4. Start the three host services and the two decoys

Each new terminal can find the release with the saved path. Keep the terminals
open. The backend's first open migrates the copied database and creates backups.

Terminal 1 — backend:

```bash
cd "$(cat "$HOME/DeceptionGraphLab/current-prototype-path.txt")"
source .venv/bin/activate
python -m backend.main
```

Terminal 2 — analyst dashboard:

```bash
cd "$(cat "$HOME/DeceptionGraphLab/current-prototype-path.txt")"
VITE_USE_FIXTURES=0 VITE_API_BASE=http://127.0.0.1:8000 \
VITE_SUPABASE_URL='' VITE_SUPABASE_ANON_KEY='' VITE_AUTH_DEV_BYPASS=1 \
npm run dev --prefix frontend -- --host 127.0.0.1 --port 5173 --strictPort
```

Terminal 3 — decoys and collector:

```bash
cd "$(cat "$HOME/DeceptionGraphLab/current-prototype-path.txt")"
source .venv/bin/activate
curl --noproxy '*' -fsS http://127.0.0.1:8000/api/health
python deployment/lab_checks.py host
docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env up -d --no-build
python sensors/adapter.py --backend http://127.0.0.1:8000 --capture-mode live
```

Open `http://127.0.0.1:5173` on Vedant's VM and select Continue as lab analyst.
That local entry does not grant remote backend authentication: keep the SOC on
loopback. The web decoy on 8080 is separate from the analyst dashboard.

## 5. Verify the physical run

After a few seconds, Sensors should report collector heartbeats even before new
traffic. An idle collector is separate from attacker activity. From Laptop A:

```bash
curl --noproxy '*' --connect-timeout 3 --max-time 5 -sS -o /dev/null \
  -w 'Web HTTP status: %{http_code}\n' http://192.168.77.20:8080/login
ssh -p 2222 dg_demo@192.168.77.20
```

The synthetic `dg_demo` password is recorded in the lab's userdb and the existing
demo notes. On the emulated SSH shell, inspect `notes.txt` for the planted portal
credential; use it only on the isolated web decoy. On Laptop A, use the project's
guarded `scenarios/web_depth.sh 192.168.77.20` workflow if a copy is available.

Then, in a fourth terminal on Vedant's VM:

```bash
cd "$(cat "$HOME/DeceptionGraphLab/current-prototype-path.txt")"
source .venv/bin/activate
bash deployment/preflight.sh
```

Preflight requires fresh traffic from 192.168.77.10 on both decoys. Inspect new
case/session/request IDs, actual bait observations and candidate links. Confirm
a relation to create an investigation; reverse it to dissolve the investigation.
Preview a block, approve it with a reason, send another web request from Laptop A,
observe the matching verified denial, and revoke. A policy write alone is pending.

The Windows acceptance run does not certify this physical source-IP, forwarding,
SFTP or egress check. Preserve the actual Linux output with the release commit.

## Stop and resume

Ctrl+C each of the three host-service terminals, then run Compose `stop` for the
two decoys from this release directory. Existing data remains on disk. Resume
with step 4 using the same path; a web worker restart requires logging in again.
Do not reconnect temporary internet while decoys run.

For rollback, stop this release, return to the unchanged old project directory
and its old database/state, restore isolation, then start its services. Never
open a newly migrated database using old backend code; use the retained old
deployment or an appropriate migration backup.

## Developer-only browser acceptance

Use a disposable environment with root, sensors and web-dev requirements, and
Playwright available to Node. From dg-soc run `python tests/e2e/prototype_stack.py`.
Start a fixture-free Vite server on 15173 with API base http://127.0.0.1:18011 and
the local lab-analyst entry enabled. Then from frontend run
`node tests/e2e/prototype.e2e.cjs`. On Windows, `DG_BROWSER_CHANNEL=msedge` selects
an installed Edge browser. All generated sensor data is synthetic and temporary.
It does not contact 192.168.77.20. Use a new harness instance for acceptance runs.
