#!/usr/bin/env bash
# Owner: M2. Run on Laptop B before every demo run. Read-only checks, changes nothing.
set -u
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --static ]; }; then
  echo "Usage: preflight.sh [--static]" >&2; exit 2
fi
source "$(dirname "$0")/lab.env"
export ATTACKER_IPS
python3 "$(dirname "$0")/lab_checks.py" host || exit 1
fail=0
pass() { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fail=1; }

ip -4 addr | grep -q "inet ${LAB_HOST_IP}/" && pass "lab IP ${LAB_HOST_IP} is configured" || bad "lab IP ${LAB_HOST_IP} missing"

ip route | grep -q '^default' && bad "default route present (internet reachable): $(ip route | grep '^default')" || pass "no default route"

if command -v nmcli >/dev/null; then
  [ "$(nmcli radio wifi)" = "disabled" ] && pass "Wi-Fi off" || bad "Wi-Fi is on"
fi

listening() { ss -ltnH | awk '{print $4}'; }
for p in 2222 8080; do
  listening | grep -qE "^${LAB_HOST_IP}:${p}$" && pass "decoy port ${p} bound to ${LAB_HOST_IP}" || bad "decoy port ${p} not bound to ${LAB_HOST_IP} (or bound wider)"
  listening | grep -qE "^(0\.0\.0\.0|\[::\]|\*):${p}$" && bad "port ${p} bound to all interfaces"
done
for p in 8000 5173; do
  if listening | grep -qE ":${p}$"; then
    listening | grep -qE "^127\.0\.0\.1:${p}$" && pass "SOC port ${p} on loopback only" || bad "SOC port ${p} bound beyond loopback"
  else
    bad "SOC port ${p} not listening"
  fi
done

docker ps --format '{{.Names}}' | grep -q dg-cowrie && pass "cowrie running" || bad "cowrie not running"
docker ps --format '{{.Names}}' | grep -q dg-web-decoy && pass "web decoy running" || bad "web decoy not running"
for c in dg-cowrie dg-web-decoy; do
  [ "$(docker inspect -f '{{.HostConfig.Privileged}}' $c 2>/dev/null)" = "false" ] && pass "$c not privileged" || bad "$c privileged or missing"
  docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' $c 2>/dev/null | grep -q docker.sock && bad "$c mounts the Docker socket"
done

grep -q 'backend *= *shell' "$(dirname "$0")/cowrie/cowrie.cfg" && pass "cowrie in emulated shell mode" || bad "cowrie backend is not shell"
python3 "$(dirname "$0")/lab_checks.py" profile && pass "read-only Cowrie lab command profile" || bad "Cowrie command profile not active"

curl --connect-timeout 2 --max-time 5 -fsS "${BACKEND_URL}/api/health" >/dev/null 2>&1 && pass "backend health" || bad "backend health"

# --- M2 additions: state files, adapter, lab.env safety ---
[ -f "$(dirname "$0")/state/blocklist.json" ] && python3 -c "import json,sys;d=json.load(open(sys.argv[1]));assert isinstance(d['entries'],list)" "$(dirname "$0")/state/blocklist.json" 2>/dev/null \
  && pass "blocklist.json exists and is valid JSON" || bad "blocklist.json missing or invalid (run deployment/bootstrap_state.sh)"
[ -f "$(dirname "$0")/../decoys/ssh/fs.pickle" ] && pass "cowrie fs.pickle built" || bad "decoys/ssh/fs.pickle missing (run decoys/ssh/build_fs.sh)"
pgrep -f '^python3? .*sensors/adapter\.py' >/dev/null && pass "adapter running" || bad "adapter not running (python sensors/adapter.py)"
python3 - "$(dirname "$0")/state/collector-health.json" <<'PY' && pass "collector heartbeat fresh and healthy" || bad "collector heartbeat missing, stale or degraded"
import json, sys
from datetime import datetime, timezone
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    stamp = datetime.fromisoformat(data["last_poll_at"].replace("Z", "+00:00"))
    age = (datetime.now(timezone.utc) - stamp.astimezone(timezone.utc)).total_seconds()
    raise SystemExit(0 if data.get("status") == "healthy" and 0 <= age <= 30 else 1)
except (OSError, ValueError, KeyError, TypeError):
    raise SystemExit(1)
PY
echo "$ATTACKER_IPS" | tr ',' '\n' | grep -qxE "${LAB_HOST_IP}|127\.0\.0\.1|.*/.*" && bad "ATTACKER_IPS contains the lab host, loopback or a range" || pass "ATTACKER_IPS are exact attacker IPs"
grep -qE '^[[:space:]]*image:[[:space:]]*cowrie/cowrie@sha256:[0-9a-f]{64}' "$(dirname "$0")/docker-compose.yml" && pass "cowrie image pinned by digest" || bad "cowrie image not pinned (deployment/pin_cowrie.sh)"

if [ "${1:-}" = --static ]; then
  [ $fail -eq 0 ] && echo "STATIC PASS; real source IPs remain unverified" || exit 1
  exit 0
fi
python3 "$(dirname "$0")/lab_checks.py" source "$(dirname "$0")/state/cowrie-log/cowrie.json" "$(dirname "$0")/state/web-log/web.json" || fail=1

echo
[ $fail -eq 0 ] && echo "ALL PASS" || { echo "FIX FAILURES BEFORE ANY TRAFFIC"; exit 1; }
