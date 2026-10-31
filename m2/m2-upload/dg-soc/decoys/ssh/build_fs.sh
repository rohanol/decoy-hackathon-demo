#!/usr/bin/env bash
# Owner: M2. Needs Docker and the pinned image already pulled (deployment/pin_cowrie.sh).
# Builds decoys/ssh/fs.pickle = the image's own fake filesystem + /home/dg_demo/notes.txt.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="$(grep -E '^\s*image:\s*cowrie/' ../../deployment/docker-compose.yml | awk '{print $2}')"
[ -n "$IMAGE" ] || { echo "no cowrie image line in docker-compose.yml"; exit 1; }
SRC_IN_IMAGE="$(docker run --rm --entrypoint sh "$IMAGE" -c 'find / -name fs.pickle 2>/dev/null | head -1')"
[ -n "$SRC_IN_IMAGE" ] || { echo "fs.pickle not found in $IMAGE"; exit 1; }
echo "base filesystem: $SRC_IN_IMAGE"
CID="$(docker create "$IMAGE")"; trap 'docker rm -f "$CID" >/dev/null' EXIT
docker cp "$CID:$SRC_IN_IMAGE" base.pickle
python3 patch_fs.py base.pickle fs.pickle ../../deployment/cowrie/honeyfs/home/dg_demo/notes.txt
rm -f base.pickle
echo "built decoys/ssh/fs.pickle. Next: docker compose up, ssh dg_demo@192.168.77.20 -p 2222, run: ls; cat notes.txt"
