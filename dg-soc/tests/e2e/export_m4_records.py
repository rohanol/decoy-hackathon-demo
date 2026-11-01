"""Generate real producer output using local test clients, never physical traffic.

Run from dg-soc: python tests/e2e/export_m4_records.py --output /tmp/m4-web.jsonl
The .10 peer is supplied by the test client; it is not source-IP lab evidence.
Only synthetic credentials are submitted; cookie values are never exported.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoys.web.app import create_app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--schema-version", choices=["1.0", "1.1"], default="1.0")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new file")
    with tempfile.TemporaryDirectory(prefix="dg-m4-export-") as directory:
        temp = Path(directory)
        state, log = temp / "blocklist.json", temp / "web.jsonl"
        state.write_text('{"version":0,"entries":[]}', encoding="utf-8")
        app = create_app({"TESTING": True, "BLOCKLIST_PATH": str(state), "LOG_PATH": str(log),
                          "HONEYTOKENS_PATH": str(ROOT / "config/honeytokens.yaml"),
                          "LAB_RUN_ID": "m4-generated-local-clients", "WEB_EVENT_SCHEMA_VERSION": args.schema_version})
        peer = {"REMOTE_ADDR": "192.168.77.10"}
        for _ in range(2):
            client = app.test_client()
            client.get("/", environ_overrides=peer)
            client.post("/login", data={"username": "svc_portal", "password": "DGLAB-Portal-4471"}, environ_overrides=peer)
            client.post("/search", json={"q": "x' UNION SELECT name FROM users--"}, environ_overrides=peer)
            client.post("/search", data={"q": "quarterly report--"}, environ_overrides=peer)
            client.get("/download?file=customer_data.csv", environ_overrides=peer)
            client.get("/.env", environ_overrides=peer)
            client.post("/logout", environ_overrides=peer)
        data = log.read_bytes()
        rows = [json.loads(line) for line in data.splitlines()]
        with args.output.open("xb") as stream:
            stream.write(data)
        print(json.dumps({"output": str(args.output), "schema_version": args.schema_version,
                          "records": len(rows), "sessions": len({row["session_id"] for row in rows}),
                          "physical_lab_evidence": False}))


if __name__ == "__main__":
    main()
