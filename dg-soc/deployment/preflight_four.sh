#!/usr/bin/env bash
# Read-only extended acceptance. Probe all services from attacker .10 first.
set -euo pipefail
cd "$(dirname "$0")/.."
bash deployment/preflight.sh --static
set -a
source deployment/lab.env
set +a
for entry in '3306:dg-db-decoy' '445:dg-file-decoy'; do
  port=${entry%%:*}
  name=${entry#*:}
  listeners=$(ss -ltnH | awk '{print $4}' | grep -E ":${port}$" || true)
  [[ $listeners == "${LAB_HOST_IP}:${port}" ]] || { echo "FAIL  $port must bind only to $LAB_HOST_IP"; exit 1; }
  [[ $(docker inspect -f '{{.State.Running}}' "$name") == true ]] || { echo "FAIL  $name not running"; exit 1; }
  [[ $(docker inspect -f '{{.HostConfig.Privileged}}' "$name") == false ]] || { echo "FAIL  $name privileged"; exit 1; }
  [[ $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$name") == true ]] || { echo "FAIL  $name root filesystem writable"; exit 1; }
  mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$name")
  [[ $mounts != *docker.sock* ]] || { echo "FAIL  $name mounts Docker socket"; exit 1; }
  echo "PASS  $name running with restricted lab binding"
done
python3 deployment/lab_checks.py source-four deployment/state/cowrie-log/cowrie.json \
  deployment/state/web-log/web.json deployment/state/db-log/db.json deployment/state/file-log/file.json
echo 'ALL FOUR PASS'
