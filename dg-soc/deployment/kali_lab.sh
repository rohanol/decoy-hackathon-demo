#!/usr/bin/env bash
# Direct-LAN lab lifecycle. No gateway, redesign or public hosting.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$root"
action=${1:-status}
case "$action" in start|stop|status|logs|build) ;; *) echo 'Usage: bash deployment/kali_lab.sh start|stop|status|logs|build'; exit 2 ;; esac
[[ $(uname -s) == Linux ]] || { echo 'Use the native Kali/Linux VM for lab lifecycle.'; exit 1; }
[[ -f deployment/lab.env ]] || { echo 'Missing deployment/lab.env'; exit 1; }
set -a
source deployment/lab.env
set +a
export NO_PROXY="127.0.0.1,localhost,192.168.77.20,192.168.77.10"
export no_proxy="$NO_PROXY"
state="$root/deployment/state/lifecycle"
mkdir -p "$state"
chmod 700 "$state"
exec 9>"$state/lock"
flock -n 9 || { echo 'Another lab lifecycle command is active.'; exit 1; }
compose=(docker compose -f deployment/docker-compose.yml -f deployment/docker-compose.four.yml --env-file deployment/lab.env)
python="$root/.venv/bin/python"
roles=(backend frontend adapter)
containers=(dg-cowrie dg-web-decoy dg-db-decoy dg-file-decoy)

owned() {
  local role=$1 pid pgid cwd cmd
  [[ -f "$state/$role.pid" ]] || return 1
  read -r pid < "$state/$role.pid"
  [[ $pid =~ ^[0-9]+$ && $pid -gt 1 && -d /proc/$pid ]] || return 1
  pgid=$(ps -o pgid= -p "$pid" | tr -d ' ')
  cwd=$(readlink -f "/proc/$pid/cwd" || true)
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline")
  [[ $pgid == "$pid" && $cwd == "$root" ]] || return 1
  case "$role:$cmd" in backend:*backend.main*|adapter:*sensors/adapter.py*|frontend:*vite/bin/vite.js*) return 0 ;; *) return 1 ;; esac
}
stop_role() {
  local role=$1 pid
  if owned "$role"; then
    read -r pid < "$state/$role.pid"
    kill -TERM -- "-$pid" 2>/dev/null || true
    for _ in {1..30}; do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
    if owned "$role"; then kill -KILL -- "-$pid" 2>/dev/null || true; fi
  fi
  rm -f -- "$state/$role.pid"
}
status() {
  for role in "${roles[@]}"; do
    if owned "$role"; then echo "$role: running"; else echo "$role: stopped or not owned by this checkout"; fi
  done
  "${compose[@]}" ps
}
if [[ $action == status ]]; then status; exit; fi
if [[ $action == logs ]]; then
  for role in "${roles[@]}"; do
    echo "$role log: $state/$role.log"
    [[ ! -f "$state/$role.log" ]] || tail -n 20 "$state/$role.log"
  done
  "${compose[@]}" logs --tail 20
  exit
fi
if [[ $action == stop ]]; then
  for role in adapter frontend backend; do stop_role "$role"; done
  "${compose[@]}" stop
  echo 'Lab stopped; database, logs, samples and policy history preserved.'
  exit
fi
[[ -x "$python" ]] || { echo 'Prepare .venv and dependencies first; see KALI_FOUR_RUNBOOK.md.'; exit 1; }
if [[ $action == build ]]; then
  for container in "${containers[@]}"; do
    [[ $(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true) != true ]] || {
      echo "Stop $container before preparing images or connecting temporary internet."; exit 1;
    }
  done
  "${compose[@]}" build web-decoy db-decoy file-decoy
  "${compose[@]}" config -q
  exit
fi
"$python" deployment/lab_checks.py host
[[ ${LAB_HOST_IP:-} == 192.168.77.20 && ${ATTACKER_IPS:-} == 192.168.77.10 ]] || { echo 'Unexpected lab host/attacker configuration'; exit 1; }
ip -4 -o addr show | grep -q '192\.168\.77\.20/24' || { echo 'Lab IP missing'; exit 1; }
if command -v nmcli >/dev/null; then [[ $(nmcli radio wifi) == disabled ]] || { echo 'Disable Wi-Fi before starting'; exit 1; }; fi
count=0
for role in "${roles[@]}"; do if owned "$role"; then count=$((count+1)); fi; done
if [[ $count == 3 ]]; then echo 'Host services already running for this checkout.'; status; exit; fi
[[ $count == 0 ]] || { echo 'Partial existing launch: run stop, inspect logs, then start.'; exit 1; }
for port in 8000 5173; do
  if ss -ltnH | awk '{print $4}' | grep -qE ":$port$"; then echo "Port $port is occupied. Stop the old host service first."; exit 1; fi
done
for container in "${containers[@]}"; do
  [[ $(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true) != true ]] || {
    echo "Stop existing $container before switching checkouts."; exit 1;
  }
done
started=()
containers_started=0
cleanup() {
  local code=$?
  if (( code != 0 )); then
    for role in "${started[@]}"; do stop_role "$role"; done
    if (( containers_started )); then "${compose[@]}" stop || true; fi
    echo 'Startup failed; only this launch was stopped. Inspect lifecycle logs.'
  fi
}
trap cleanup EXIT
launch() {
  local role=$1
  shift
  setsid "$@" >"$state/$role.log" 2>&1 < /dev/null 9>&- &
  echo "$!" > "$state/$role.pid"
  started+=("$role")
}
ready() {
  local url=$1 role=$2
  for _ in {1..60}; do
    if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "$url" >/dev/null 2>&1; then return; fi
    owned "$role" || { echo "$role exited; inspect its lifecycle log"; return 1; }
    sleep .5
  done
  echo "$role readiness timed out"
  return 1
}
launch backend "$python" -m backend.main
ready http://127.0.0.1:8000/api/health backend
export VITE_USE_FIXTURES=0 VITE_API_BASE=http://127.0.0.1:8000 VITE_SUPABASE_URL='' VITE_SUPABASE_ANON_KEY='' VITE_AUTH_DEV_BYPASS=1
launch frontend node "$root/frontend/node_modules/vite/bin/vite.js" "$root/frontend" --host 127.0.0.1 --port 5173 --strictPort
ready http://127.0.0.1:5173 frontend
containers_started=1
"${compose[@]}" up -d --no-build
for container in "${containers[@]}"; do
  sleep .3
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { echo "$container did not remain running"; exit 1; }
done
launch adapter "$python" sensors/adapter.py --backend http://127.0.0.1:8000 --capture-mode live
sleep 1
owned adapter || { echo 'Adapter exited'; exit 1; }
echo 'Host services and four containers started. Open http://127.0.0.1:5173 on Vedant Kali.'
echo 'Native protocol/source-IP acceptance is still required; run the attacker probes and preflight.'
