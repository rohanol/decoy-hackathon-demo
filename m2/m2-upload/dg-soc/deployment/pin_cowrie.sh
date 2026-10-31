#!/usr/bin/env bash
# Preparation only: needs internet. No container shell is required.
set -euo pipefail
exec python3 "$(dirname "$0")/cowrie_image.py" pin
