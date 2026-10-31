"""Post contracts/examples/events_p3.json to a running backend (dev only, replay data).

Run from the repo root:  python -m backend.tools.load_fixtures
"""
import json
import sys
import urllib.request
from pathlib import Path

URL = "http://127.0.0.1:8000/api/ingest/events"
FIXTURE = Path(__file__).resolve().parents[2] / "contracts" / "examples" / "events_p3.json"


def main() -> int:
    events = json.loads(FIXTURE.read_text(encoding="utf-8"))["events"]
    req = urllib.request.Request(
        URL, data=json.dumps({"events": events}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(resp.status, resp.read().decode())
    except OSError as e:
        print(f"could not reach {URL}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
