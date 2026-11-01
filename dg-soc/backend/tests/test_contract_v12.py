"""Contract v1.2 (four honeypots, gateway and telemetry): schemas and provisional fixtures.

Schema-level only, so it holds before the runtime lands. Runtime ingest of the same fixtures
is in test_telemetry_v12.py.
"""
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"


def load(name):
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def validator(schema):
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


EVENT, EVENT_V11, TELEMETRY = (validator(load(n)) for n in
                               ("event.schema.json", "history/event.schema.v1.1.json", "telemetry.schema.json"))
FX = load("examples/telemetry_v1_2.json")
V11 = load("examples/events_v1_1.json")


def ok(v, doc):
    return not list(v.iter_errors(doc))


def test_fixtures_are_labelled_provisional():
    assert FX["provisional"] is True and FX["contract_version"] == "1.2"
    assert "PROVISIONAL" in FX["_note"] and "no" in FX["_note"].lower()


@pytest.mark.parametrize("ev", FX["events_valid"], ids=lambda e: e["source_record_id"])
def test_v12_events_validate(ev):
    assert ok(EVENT, ev), [e.message for e in EVENT.iter_errors(ev)]


@pytest.mark.parametrize("case", FX["events_invalid"], ids=lambda c: c["why"][:40])
def test_v12_invalid_events_rejected(case):
    assert not ok(EVENT, case["record"]), case["why"]


@pytest.mark.parametrize("rec", FX["telemetry_valid"], ids=lambda r: r["record_id"])
def test_telemetry_records_validate(rec):
    assert ok(TELEMETRY, rec), [e.message for e in TELEMETRY.iter_errors(rec)]


@pytest.mark.parametrize("case", FX["telemetry_invalid"], ids=lambda c: c["why"][:40])
def test_invalid_telemetry_rejected(case):
    assert not ok(TELEMETRY, case["record"]), case["why"]


def test_events_and_telemetry_never_cross():
    """A telemetry record is not an event, and an event is not a telemetry record."""
    assert not any(ok(EVENT, r) for r in FX["telemetry_valid"])
    assert not any(ok(TELEMETRY, e) for e in FX["events_valid"])


def _v11_examples():
    return [e for e in V11["events"] if e["schema_version"] == "1.1"]


@pytest.mark.parametrize("ev", _v11_examples(), ids=lambda e: e["source_record_id"])
def test_v11_events_judged_exactly_as_before(ev):
    assert ok(EVENT, ev) == ok(EVENT_V11, ev) is True


@pytest.mark.parametrize("case", V11["invalid"], ids=lambda c: c["_why"][:40])
def test_v11_rejections_unchanged(case):
    assert ok(EVENT, case["event"]) == ok(EVENT_V11, case["event"]) is False


@pytest.mark.parametrize("version", ["1.0", "1.1"])
@pytest.mark.parametrize("ev", [e for e in FX["events_valid"] if e["sensor_id"] in ("db-decoy-01", "file-decoy-01")
                                or e["event_type"] in ("db_request", "file_operation")][:3],
                         ids=lambda e: e["source_record_id"])
def test_new_sensors_need_v12(ev, version):
    old = dict(ev, schema_version=version)
    if version == "1.0":
        old["attributes"] = {k: v for k, v in ev["attributes"].items() if not isinstance(v, dict)}
    assert not ok(EVENT, old)


def test_web_with_ingress_is_v12_only_attribute_semantics():
    """1.1 lets unknown attributes through untyped; it must not be read as a verified gateway context."""
    ev = dict(FX["events_valid"][0], schema_version="1.1")
    ev["attributes"] = dict(ev["attributes"], ingress={"gateway_context": "absent", "gateway_request_id": "gw_00000000000009"})
    assert ok(EVENT, ev)  # unchanged 1.1 rules: unknown keys pass
    assert not ok(EVENT, dict(ev, schema_version="1.2"))  # 1.2 rules: an unverified context names no request


def test_source_registry_matches_schemas():
    reg = load("sources.json")
    honeypots = [s["source_id"] for s in reg["honeypots"]]
    sources = [s["source_id"] for s in reg["telemetry_sources"]]
    assert honeypots == load("event.schema.json")["properties"]["sensor_id"]["enum"]
    assert sources == load("telemetry.schema.json")["properties"]["source_id"]["enum"]
    assert len(honeypots) == 4 and not set(honeypots) & set(sources)
    support = {s["source_id"]: s["response"]["block"] for s in reg["honeypots"]}
    assert support == {"ssh-decoy-01": "unsupported", "web-decoy-01": "supported",
                       "db-decoy-01": "unsupported", "file-decoy-01": "unsupported"}
    for s in reg["honeypots"]:
        for et in s["event_types"]:
            assert et in load("event.schema.json")["properties"]["event_type"]["enum"]


def test_matrix_in_registry_matches_schema():
    reg = {s["source_id"]: s for s in load("sources.json")["honeypots"]}
    for sensor in ("db-decoy-01", "file-decoy-01"):
        allowed = set(reg[sensor]["event_types"])
        base = next(e for e in FX["events_valid"] if e["sensor_id"] == sensor)
        for et in load("event.schema.json")["properties"]["event_type"]["enum"]:
            probe = json.loads(json.dumps(base))
            probe["event_type"] = et
            if et not in allowed:
                assert not ok(EVENT, probe), (sensor, et)


def test_no_secret_values_in_fixtures():
    text = json.dumps(FX)
    assert not re.search(r"DGLAB-[A-Za-z0-9]", text)  # placeholders name the prefix, never a value
    for needle in ("DemoPass", "Set-Cookie", "Authorization"):
        assert needle not in text, needle
    # A challenge-response decoy never has a password hash; only the rejected example carries one.
    assert "password_sha256" not in json.dumps([FX["events_valid"], FX["telemetry_valid"], FX["expected_reads"]])


def test_archive_entries_are_inert_text():
    zips = [e for e in FX["events_valid"] if "archive" in e["attributes"]]
    assert zips
    for e in zips:
        a = e["attributes"]["archive"]
        assert a["contains_executable"] is False and a["auto_run"] is False
        assert all(x["name"].endswith((".txt", ".csv")) and "/" not in x["name"] for x in a["entries"])
        assert set(e["attributes"]["honeytoken_ids"]) == {t for x in a["entries"] for t in x.get("honeytoken_ids", [])}


def test_expected_reads_name_only_known_sources():
    exp = FX["expected_reads"]
    assert exp["sources_excerpt"]["honeypot_count"] == 4
    assert "gateway-01" not in exp["health_excerpt"]["sensor_health_keys"]
    assert exp["health_excerpt"]["telemetry_health_row"]["counted_as_honeypot"] is False
    assert "Missing records do not show" in exp["incident_routing_web_case"]["normal_app_contact"]["statement"]
