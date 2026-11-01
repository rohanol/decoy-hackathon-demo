#!/usr/bin/env bash
# Owner: M2. Manage the isolated native-Linux prototype's host and decoy processes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
STATE="$ROOT/deployment/state/labctl"
LOGS="$ROOT/deployment/state/labctl/logs"
PIDDIR="$STATE/pids"
COMPOSE=(docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env)
mkdir -p "$PIDDIR" "$LOGS"

alive() { [[ -f "$PIDDIR/$1.pid" ]] && kill -0 "$(cat "$PIDDIR/$1.pid")" 2>/dev/null; }
start_process() {
  local name="$1"; shift
  if alive "$name"; then echo "$name already running (pid $(cat "$PIDDIR/$name.pid"))"; return; fi
  nohup "$@" >>"$LOGS/$name.log" 2>&1 </dev/null &
  echo $! >"$PIDDIR/$name.pid"
  sleep 1
  if ! kill -0 "$(cat "$PIDDIR/$name.pid")" 2>/dev/null; then
    rm -f "$PIDDIR/$name.pid"
    echo "Failed to start $name; inspect $LOGS/$name.log" >&2
    return 1
  fi
  echo "started $name (pid $(cat "$PIDDIR/$name.pid"))"
}
stop_process() {
  local name="$1" pid
  [[ -f "$PIDDIR/$name.pid" ]] || return 0
  pid="$(cat "$PIDDIR/$name.pid")"
  if kill -0 "$pid" 2>/dev/null; then kill "$pid"; for _ in {1..30}; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done; fi
  rm -f "$PIDDIR/$name.pid"
  echo "stopped $name"
}

case "${1:-}" in
  start)
    [[ "$(uname -s)" == Linux ]] || { echo 'Use native Linux Docker Engine.' >&2; exit 1; }
    python3 deployment/lab_checks.py host
    [[ -x .venv/bin/python ]] || { echo 'Create dg-soc/.venv per PROTOTYPE_RUNBOOK.md first.' >&2; exit 1; }
    [[ -d frontend/node_modules ]] || { echo 'Run npm ci --prefix frontend first.' >&2; exit 1; }
    gateway=0
    if [[ "${2:-}" == --gateway ]]; then
      gateway=1
      normal="$(sed -n 's/^NORMAL_APP_UPSTREAM=//p' deployment/lab.env | tail -n 1)"
      [[ -n "$normal" ]] || { echo 'Set NORMAL_APP_UPSTREAM to the fixed M1 application origin.' >&2; exit 1; }
      curl --noproxy '*' --connect-timeout 2 -fsS "${normal%/}/" -o /dev/null || {
        echo 'Configured M1 normal application upstream is unavailable; gateway remains stopped.' >&2; exit 1; }
      "${COMPOSE[@]}" build gateway
      export COMPOSE_PROFILES=gateway
    elif [[ -n "${2:-}" ]]; then echo 'Usage: labctl.sh start [--gateway]' >&2; exit 2; fi
    bash deployment/bootstrap_state.sh
    start_process backend .venv/bin/python -m backend.main
    for _ in {1..20}; do curl --noproxy '*' -fsS http://127.0.0.1:8000/api/health -o /dev/null && break; sleep 1; done
    curl --noproxy '*' -fsS http://127.0.0.1:8000/api/health -o /dev/null || { echo 'Backend did not become healthy.' >&2; exit 1; }
    "${COMPOSE[@]}" up -d --no-build
    start_process dashboard env VITE_USE_FIXTURES=0 VITE_API_BASE=http://127.0.0.1:8000 VITE_SUPABASE_URL= VITE_SUPABASE_ANON_KEY= VITE_AUTH_DEV_BYPASS=1 npm run dev --prefix frontend -- --host 127.0.0.1 --port 5173 --strictPort
    start_process adapter .venv/bin/python sensors/adapter.py --backend http://127.0.0.1:8000 --capture-mode live
    echo 'Lab started. Use: labctl.sh status | logs | stop'
    ;;
  status)
    for name in backend dashboard adapter; do if alive "$name"; then echo "$name running (pid $(cat "$PIDDIR/$name.pid"))"; else echo "$name stopped"; fi; done
    "${COMPOSE[@]}" ps
    curl --noproxy '*' -fsS http://127.0.0.1:8000/api/health 2>/dev/null || true
    ;;
  stop)
    stop_process adapter; stop_process dashboard; stop_process backend
    "${COMPOSE[@]}" stop gateway web-decoy cowrie
    ;;
  logs)
    touch "$LOGS/backend.log" "$LOGS/dashboard.log" "$LOGS/adapter.log" "$LOGS/containers.log"
    "${COMPOSE[@]}" logs --no-color --follow cowrie web-decoy gateway >>"$LOGS/containers.log" 2>&1 &
    composepid=$!
    tail -n 100 -F "$LOGS/backend.log" "$LOGS/dashboard.log" "$LOGS/adapter.log" &
    tailpid=$!
    trap 'kill "$tailpid" "$composepid" 2>/dev/null || true' INT TERM
    wait "$tailpid"
    ;;
  *) echo 'Usage: labctl.sh {start [--gateway]|status|stop|logs}' >&2; exit 2 ;;
esac
