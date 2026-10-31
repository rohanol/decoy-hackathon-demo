#!/usr/bin/env bash
# Uses a stopped, previously pinned image; never starts the honeypot.
set -euo pipefail
exec python3 "$(dirname "$0")/../../deployment/cowrie_image.py" build
