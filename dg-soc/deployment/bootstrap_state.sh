#!/usr/bin/env bash
# Owner: M2. Run once on Laptop B before the first `docker compose up` (safe to re-run).
# Docker would create a DIRECTORY at the blocklist path if the file is missing, and Cowrie/web decoy
# run as non-root users that must be able to write their log folders.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p state/cowrie-log state/web-log state/db-log state/file-log state/file-quarantine
[ -f state/blocklist.json ] || echo '{"version":0,"entries":[]}' > state/blocklist.json
chmod 644 state/blocklist.json
chmod 777 state/cowrie-log state/web-log state/db-log state/file-log   # isolated lab only
if [ "$(id -u)" = 1000 ]; then
  chmod 700 state/file-quarantine
else
  sudo chown 1000:1000 state/file-quarantine
  sudo chmod 700 state/file-quarantine
fi
echo "state ready:"; ls -la state
