import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from portal.app import create_app  # noqa: E402

KEY = "DGLAB-GWCTX-" + "ab" * 32
RUN = "run-test-01"


def schema():
    vendored = json.loads((ROOT / "tests/contract/telemetry.schema.json").read_text())
    merged = ROOT.parent / "contracts/telemetry.schema.json"
    if merged.exists():
        published = json.loads(merged.read_text())
        assert published == vendored, "vendored telemetry schema differs from contracts/: refresh tests/contract"
        return published
    return vendored


@pytest.fixture
def portal(tmp_path):
    log = tmp_path / "app.jsonl"
    app = create_app({"TESTING": True, "LAB_RUN_ID": RUN, "GATEWAY_CONTEXT_KEY": KEY, "TELEMETRY_PATH": str(log)})

    def records():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    return app, app.test_client(), records, log
