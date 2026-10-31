#!/usr/bin/env bash
# Owner: M2. Needs internet (phone hotspot) and Docker. Run BEFORE the event, never during a run.
# 1) pulls the Cowrie image  2) pins its digest in docker-compose.yml
# 3) checks every option in our cowrie.cfg exists in the image's cowrie.cfg.dist
# 4) prints the real in-container paths so the compose volume lines can be checked.
set -euo pipefail
cd "$(dirname "$0")"
TAG="${COWRIE_TAG:-cowrie/cowrie:latest}"
docker pull "$TAG"
DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$TAG")"   # cowrie/cowrie@sha256:...
echo "pinning $DIGEST"
sed -i -E "s#^(\s*image:\s*)cowrie/cowrie[^ ]*#\1${DIGEST}#" docker-compose.yml
grep -n 'image: cowrie' docker-compose.yml

echo; echo "== in-container layout =="
docker run --rm --entrypoint sh "$DIGEST" -c 'ls /cowrie/cowrie-git/etc /cowrie/cowrie-git/var/log 2>&1; find / -name fs.pickle -o -name cowrie.cfg.dist 2>/dev/null; id'

echo; echo "== our cowrie.cfg options vs the image's cowrie.cfg.dist =="
DIST="$(docker run --rm --entrypoint sh "$DIGEST" -c 'cat $(find / -name cowrie.cfg.dist 2>/dev/null | head -1)')"
section=""; bad=0
while IFS= read -r line; do
  case "$line" in
    \[*\]) section="$line";;
    ''|'#'*|';'*) ;;
    *=*) key="$(echo "${line%%=*}" | xargs)"
         if ! printf '%s\n' "$DIST" | awk -v s="$section" -v k="$key" '
              /^\[/ {cur=$0} (cur==s) && ($0 ~ "^#?[ ]*"k"[ ]*=") {f=1} END{exit !f}'; then
           echo "UNKNOWN option $section $key"; bad=1; fi;;
  esac
done < cowrie/cowrie.cfg
[ $bad -eq 0 ] && echo "all options known" || echo "FIX the options listed above before the event"
