#!/usr/bin/env bash
# M4. Manual workflow probe: authorised isolated lab only. No external target.
set -euo pipefail
if [ "$#" -ne 1 ] || [ "$1" != "192.168.77.20" ]; then
  echo 'Refusing: only the lab decoy 192.168.77.20 is allowed' >&2
  exit 1
fi
command -v curl >/dev/null
WEB='http://192.168.77.20:8080'
run_dir=$(mktemp -d /tmp/dg_web_depth.XXXXXX)
cleanup() {
  rm -f -- "$run_dir/cookies" "$run_dir/response"
  rmdir -- "$run_dir"
}
trap cleanup EXIT
probe() {
  local expected=$1 label=$2 actual
  shift 2
  actual=$(curl --noproxy '*' --connect-timeout 3 --max-time 10 -sS \
    -b "$run_dir/cookies" -c "$run_dir/cookies" -o "$run_dir/response" -w '%{http_code}' "$@")
  printf '%s: HTTP %s (expected %s)\n' "$label" "$actual" "$expected"
  [ "$actual" = "$expected" ]
}
touch "$run_dir/cookies"
probe 200 'Public landing' "$WEB/"
probe 401 'Anonymous protected report' "$WEB/download?file=customer_data.csv"
probe 200 'Synthetic login' --data-urlencode 'username=svc_portal' \
  --data-urlencode "password=${DG_PORTAL_PASSWORD:-DGLAB-Portal-4471}" "$WEB/login"
probe 200 'Authenticated dashboard' "$WEB/dashboard"
probe 200 'Form request observation' --data-urlencode 'q=quarterly report' "$WEB/search"
probe 200 'JSON request observation' -H 'Content-Type: application/json' \
  --data '{"q":"staff handbook"}' "$WEB/search"
probe 200 'Protected synthetic report' "$WEB/download?file=customer_data.csv"
probe 200 'Public bait response' "$WEB/.env"
probe 200 'Logout' --data '' "$WEB/logout"
probe 401 'Report denied after logout' "$WEB/download?file=customer_data.csv"
echo 'Inspect request/session/result evidence in the SOC; this probe does not assert detection scores or token attribution.'
