"""SQLite (WAL) storage. One writer behind a lock; one read connection per thread."""
import json
import os
import shutil
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from . import links as linking
from .config import Config, load_config
from .models import IngestEvent, evidence_role, observation_kind, to_rfc3339
from .rules import CREDENTIAL_RULES, SESSION_RULES, evaluate_incident, evaluate_investigation, r01
from .scoring import score_incident

DEFAULT_DB = Path(__file__).parent / "data" / "dg.db"

# A case (contract v1.1) is a row of `incidents`; the route name is kept. case_key makes
# assignment idempotent. Rows from before the case model stay as status 'superseded'.
INCIDENTS_TABLE = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id    TEXT PRIMARY KEY,
    src_ip         TEXT NOT NULL,
    lab_run_id     TEXT NOT NULL,
    score          INTEGER NOT NULL DEFAULT 0,
    severity       TEXT NOT NULL DEFAULT 'low',
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    event_count    INTEGER NOT NULL DEFAULT 0,
    case_kind      TEXT NOT NULL DEFAULT 'legacy_ip_run',
    grouping_basis TEXT NOT NULL DEFAULT 'ip_run_v1',
    sensor_id      TEXT,
    session_id     TEXT,
    capture_mode   TEXT NOT NULL DEFAULT 'live',
    username       TEXT,
    parent_id      TEXT,
    children       TEXT NOT NULL DEFAULT '[]',
    basis_link_ids TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'open',
    case_key       TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(src_ip, lab_run_id, capture_mode, case_kind);
"""

SCHEMA = INCIDENTS_TABLE + """
CREATE TABLE IF NOT EXISTS events (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT NOT NULL UNIQUE,
    sensor_id        TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    occurred_at      TEXT NOT NULL,
    ingested_at      TEXT NOT NULL,
    src_ip           TEXT NOT NULL,
    src_port         INTEGER,
    session_id       TEXT,
    lab_run_id       TEXT NOT NULL,
    capture_mode     TEXT NOT NULL,
    attributes       TEXT NOT NULL,
    incident_id      TEXT NOT NULL REFERENCES incidents(incident_id),
    schema_version   TEXT NOT NULL DEFAULT '1.0',
    ingest_namespace TEXT NOT NULL DEFAULT 'live',
    origin_record_id TEXT,
    observation_kind TEXT NOT NULL DEFAULT 'network_input',
    UNIQUE (ingest_namespace, sensor_id, source_record_id)
);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(lab_run_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(src_ip, lab_run_id, capture_mode, seq);
CREATE TABLE IF NOT EXISTS runs (
    lab_run_id       TEXT PRIMARY KEY,
    capture_mode     TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    last_ingested_at TEXT NOT NULL,
    events           INTEGER NOT NULL DEFAULT 0,
    legacy_mixed     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    rule_id     TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_incident ON findings(incident_id);
CREATE TABLE IF NOT EXISTS links (
    link_id          TEXT PRIMARY KEY,
    from_event_id    TEXT NOT NULL,
    to_event_id      TEXT NOT NULL,
    from_sensor      TEXT NOT NULL,
    to_sensor        TEXT NOT NULL,
    kind             TEXT NOT NULL,
    basis            TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open',
    decided_at       TEXT,
    rationale        TEXT,
    from_incident_id TEXT NOT NULL,
    to_incident_id   TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    attribution      TEXT,
    candidate_issuance_ids TEXT NOT NULL DEFAULT '[]'
);
-- Collector health (PR 5): the latest heartbeat per collector and sensor, never an event.
CREATE TABLE IF NOT EXISTS collector_heartbeats (
    collector_id TEXT NOT NULL,
    sensor_id    TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    body         TEXT NOT NULL,
    PRIMARY KEY (collector_id, sensor_id)
);
CREATE TABLE IF NOT EXISTS ingest_counters (
    sensor_id TEXT PRIMARY KEY,
    duplicate INTEGER NOT NULL DEFAULT 0
);
"""

# PRAGMA user_version: 0 = v1.0 layout, 1 = runs table + namespaced dedup (PR 2),
# 2 = session cases, credential cases and investigations (PR 3),
# 3 = token links carry attribution and candidate issuances (PR 4).
DB_VERSION = 3
LINK_COLUMNS_V3 = (("attribution", "TEXT"), ("candidate_issuance_ids", "TEXT NOT NULL DEFAULT '[]'"))
ACTIVE_RUN_MINUTES = 15
ELIGIBLE_MINUTES = 10           # M2 refuses a block on older web evidence (response/router.py)
HEARTBEAT_FRESH_SECONDS = 30    # adapter sends every 10 s
ACTIVITY_MINUTES = 5

# v0 -> v1. SQLite cannot drop the old UNIQUE(sensor_id, source_record_id) in place, so the
# events table is rebuilt once: every row is copied unchanged, seq included. Runs that already
# mixed live and replay before this migration are kept and flagged legacy_mixed.
MIGRATE_V0_V1 = """
BEGIN;
CREATE TABLE events_v1 (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT NOT NULL UNIQUE,
    sensor_id        TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    occurred_at      TEXT NOT NULL,
    ingested_at      TEXT NOT NULL,
    src_ip           TEXT NOT NULL,
    src_port         INTEGER,
    session_id       TEXT,
    lab_run_id       TEXT NOT NULL,
    capture_mode     TEXT NOT NULL,
    attributes       TEXT NOT NULL,
    incident_id      TEXT NOT NULL REFERENCES incidents(incident_id),
    schema_version   TEXT NOT NULL DEFAULT '1.0',
    ingest_namespace TEXT NOT NULL DEFAULT 'live',
    origin_record_id TEXT,
    observation_kind TEXT NOT NULL DEFAULT 'network_input',
    UNIQUE (ingest_namespace, sensor_id, source_record_id)
);
INSERT INTO events_v1 (seq, event_id, sensor_id, source_record_id, event_type, occurred_at, ingested_at,
                       src_ip, src_port, session_id, lab_run_id, capture_mode, attributes, incident_id,
                       schema_version, ingest_namespace, origin_record_id, observation_kind)
SELECT seq, event_id, sensor_id, source_record_id, event_type, occurred_at, ingested_at,
       src_ip, src_port, session_id, lab_run_id, capture_mode, attributes, incident_id,
       '1.0',
       CASE WHEN capture_mode = 'replay' THEN 'replay:' || lab_run_id ELSE 'live' END,
       NULL,
       CASE event_type WHEN 'command_input' THEN 'command_input'
                       WHEN 'synthetic_file_access' THEN 'emulated_result'
                       WHEN 'blocked_request' THEN 'policy_result'
                       ELSE 'network_input' END
FROM events ORDER BY seq;
DROP TABLE events;
ALTER TABLE events_v1 RENAME TO events;
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(lab_run_id, seq);
CREATE TABLE IF NOT EXISTS runs (
    lab_run_id       TEXT PRIMARY KEY,
    capture_mode     TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    last_ingested_at TEXT NOT NULL,
    events           INTEGER NOT NULL DEFAULT 0,
    legacy_mixed     INTEGER NOT NULL DEFAULT 0
);
INSERT INTO runs (lab_run_id, capture_mode, first_seen, last_seen, last_ingested_at, events, legacy_mixed)
SELECT e.lab_run_id,
       (SELECT f.capture_mode FROM events f WHERE f.lab_run_id = e.lab_run_id ORDER BY f.seq LIMIT 1),
       MIN(e.occurred_at), MAX(e.occurred_at), MAX(e.ingested_at), COUNT(*),
       COUNT(DISTINCT e.capture_mode) > 1
FROM events e GROUP BY e.lab_run_id;
PRAGMA user_version = 1;
COMMIT;
"""

# v1 -> v2, step 1 (SQL): the old UNIQUE(src_ip, lab_run_id) must go, so `incidents` is rebuilt.
# Old rows are kept, unchanged, as superseded legacy_ip_run cases with their findings. Step 2
# (Python, Database._migrate_v1_v2) moves each event to its derived case; the event's own
# fields are never touched.
MIGRATE_V1_V2_TABLE = INCIDENTS_TABLE.split(";")[0].replace(
    "CREATE TABLE IF NOT EXISTS incidents", "CREATE TABLE incidents_v2") + """;
INSERT INTO incidents_v2 (incident_id, src_ip, lab_run_id, score, severity, first_seen, last_seen, event_count,
                          capture_mode, status, case_key)
SELECT i.incident_id, i.src_ip, i.lab_run_id, i.score, i.severity, i.first_seen, i.last_seen, i.event_count,
       COALESCE((SELECT r.capture_mode FROM runs r WHERE r.lab_run_id = i.lab_run_id), 'live'),
       'superseded', 'legacy|' || i.incident_id
FROM incidents i ORDER BY i.rowid;
DROP TABLE incidents;
ALTER TABLE incidents_v2 RENAME TO incidents;
"""

SENSORS = ("ssh-decoy-01", "web-decoy-01")
SSH = "ssh-decoy-01"
SESSION_KINDS = ("ssh_session", "ssh_unsessioned", "web_session", "web_activity")
STAGE_ORDER = ["recon", "credential_attack", "exploit_attempt", "post_access", "lure_access", "data_access"]
LINK_FIELDS = ["link_id", "from_event_id", "to_event_id", "from_sensor", "to_sensor",
               "kind", "basis", "status", "decided_at", "rationale", "from_incident_id", "to_incident_id",
               "attribution", "candidate_issuance_ids"]
TRANSCRIPT_KINDS = {"auth_failure": "login_failed", "auth_success": "login_ok",
                    "command_input": "command", "connection_close": "close"}
PROFILE_NOTE = ("Everything seen from this address in this run. Several people can share one "
                "address (NAT); this is not a person.")


def _now() -> str:
    """Backend-issued timestamps (ingested_at, created_at, decided_at): UTC, milliseconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def case_kind_for(sensor_id: str, session_id: Optional[str]) -> tuple:
    """(case_kind, grouping_basis) for an event, per the table in contracts/API.md."""
    if sensor_id == SSH:
        return ("ssh_session", "sensor_session") if session_id else ("ssh_unsessioned", "inactivity_5min")
    return ("web_session", "sensor_session") if session_id else ("web_activity", "inactivity_5min")


class Database:
    """One writer connection (behind a lock) plus one read connection per thread.

    WAL lets readers run while a write is in progress, and a reader only ever sees
    committed data, so a GET can never return a half-written ingest."""

    def __init__(self, path: Optional[str] = None, cfg: Optional[Config] = None):
        self.cfg = cfg or load_config()
        self.path = path or os.environ.get("DG_DB_PATH") or str(DEFAULT_DB)
        if self.path == ":memory:":
            raise ValueError("use a file path: readers and the writer need to share one database")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._writer = self._connect()
        self._writer.execute("PRAGMA journal_mode=WAL")
        self._migrate()
        self._write_lock = threading.Lock()
        self._local = threading.local()
        self._readers: list[sqlite3.Connection] = []
        self._readers_lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        # isolation_level=None: autocommit for reads; the writer issues BEGIN/COMMIT itself.
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """Read connection for the calling thread."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
            with self._readers_lock:
                self._readers.append(conn)
        return conn

    def _backup(self, suffix: str) -> None:
        self._writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # the copy must hold everything
        backup = f"{self.path}.{suffix}.bak"
        if not os.path.exists(backup):
            shutil.copy2(self.path, backup)

    def _migrate(self) -> None:
        """Bring the file to DB_VERSION. Back up the file before each step."""
        c = self._writer
        has_events = c.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone() is not None
        version = c.execute("PRAGMA user_version").fetchone()[0]
        if has_events and version == 0:
            self._backup("v0")
            c.executescript(MIGRATE_V0_V1)
            version = 1
        if has_events and version in (1, 2):
            self._backup(f"v{version}")
            # Columns first: the v2 step re-derives links, which now carry attribution.
            have = {r["name"] for r in c.execute("PRAGMA table_info(links)")}
            for name, decl in LINK_COLUMNS_V3:
                if name not in have:
                    c.execute(f"ALTER TABLE links ADD COLUMN {name} {decl}")
            if version == 1:
                self._migrate_v1_v2()
            c.execute(f"PRAGMA user_version = {DB_VERSION}")
        c.executescript(SCHEMA)  # creates whatever is missing; no-op on an up-to-date file
        if not has_events:
            c.execute(f"PRAGMA user_version = {DB_VERSION}")

    def _migrate_v1_v2(self) -> None:
        c = self._writer
        c.execute("PRAGMA foreign_keys=OFF")  # events point at incidents while it is rebuilt
        c.execute("BEGIN IMMEDIATE")
        try:
            for stmt in MIGRATE_V1_V2_TABLE.split(";"):
                if stmt.strip():
                    c.execute(stmt)
            # executescript would commit, so the statements run one by one inside this transaction
            for stmt in SCHEMA.split(";"):
                if stmt.strip():
                    c.execute(stmt)
            cases, sources = set(), set()
            for r in c.execute("SELECT * FROM events ORDER BY seq").fetchall():
                inc = self._assign_case(c, r["sensor_id"], r["session_id"], r["src_ip"], r["lab_run_id"],
                                        r["capture_mode"], r["occurred_at"])
                c.execute("UPDATE events SET incident_id=? WHERE seq=?", (inc, r["seq"]))
                cases.add(inc)
                sources.add((r["src_ip"], r["lab_run_id"], r["capture_mode"]))
            c.execute("UPDATE links SET "
                      "from_incident_id=(SELECT incident_id FROM events WHERE event_id=links.from_event_id), "
                      "to_incident_id=(SELECT incident_id FROM events WHERE event_id=links.to_event_id)")
            cases |= self._refresh_credential_cases(c, sources)
            self._refresh_links(c, {inc: self._incident_events(c, inc) for inc in sorted(cases)}, sources,
                                {(run, mode) for _, run, mode in sources})
            for row in c.execute("SELECT * FROM links WHERE status='confirmed' ORDER BY decided_at, link_id").fetchall():
                cases |= self._apply_investigation(c, self._link_row(row))
            for inc in self._sync_order(c, cases):
                self._sync_incident(c, inc)
            c.execute(f"PRAGMA user_version = {DB_VERSION}")
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        finally:
            c.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        with self._readers_lock:
            for conn in self._readers:
                conn.close()
            self._readers.clear()
        self._writer.close()

    def _write(self, fn):
        """Run fn(conn) in one IMMEDIATE transaction under the single-writer lock."""
        with self._write_lock:
            c = self._writer
            c.execute("BEGIN IMMEDIATE")
            try:
                result = fn(c)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return result

    # ---- writes ----
    def ingest(self, events: list[IngestEvent]) -> dict:
        """Insert events, then links, rules and scores, all in ONE transaction.
        Returns {"outcomes": [("stored", event) | ("duplicate", None) | ("rejected", reason)],
        "links": [new links], "findings": [new or changed findings], "incidents": [touched ids]}.
        The caller broadcasts afterwards."""
        def work(c):
            touched: set[str] = set()
            sources: set[tuple] = set()
            outcomes = [self._insert_one(c, ev, touched, sources) for ev in events]
            stored = [payload for status, payload in outcomes if status == "stored"]
            # Load each touched case's events once; links and rules both use them.
            loaded = {inc: self._incident_events(c, inc) for inc in sorted(touched)}
            affected = set(touched) | self._refresh_credential_cases(c, sources)
            # A serving or bait-read request may arrive after the presentation it explains.
            token_runs = {(e["lab_run_id"], e["capture_mode"]) for e in stored
                          if e["event_type"] == "bait_served" or "requested_asset_id" in e["attributes"]}
            new_links = self._refresh_links(c, loaded, sources, token_runs)
            for l in new_links:
                affected.update((l["from_incident_id"], l["to_incident_id"]))
            affected |= self._parents(c, affected)  # an investigation re-scores when a child changes
            changed =[f for inc in self._sync_order(c, affected) for f in self._sync_incident(c, inc, loaded.get(inc))]
            ordered = self._sync_order(c, affected)
            return {"outcomes": outcomes, "links": new_links, "findings": changed,
                    "incidents": ordered if stored or new_links else []}
        return self._write(work)

    def decide_link(self, link_id: str, decision: str, rationale: str) -> Optional[dict]:
        """Analyst decision. Creates, extends or dissolves the investigation the link stands
        for, then re-runs rules and scores for the cases involved."""
        def work(c):
            row = c.execute("SELECT * FROM links WHERE link_id=?", (link_id,)).fetchone()
            if not row:
                return None
            status = "confirmed" if decision == "confirm" else "rejected"
            c.execute("UPDATE links SET status=?, decided_at=?, rationale=? WHERE link_id=?",
                      (status, _now(), rationale, link_id))
            link = self._link_row(c.execute("SELECT * FROM links WHERE link_id=?", (link_id,)).fetchone())
            affected = {link["from_incident_id"], link["to_incident_id"]} | self._apply_investigation(c, link)
            ordered = self._sync_order(c, affected)
            changed = [f for inc in ordered for f in self._sync_incident(c, inc)]
            return {"link": link, "findings": changed, "incidents": ordered}
        return self._write(work)

    def _insert_one(self, c: sqlite3.Connection, ev: IngestEvent, touched: set, sources: set) -> tuple:
        run = c.execute("SELECT capture_mode FROM runs WHERE lab_run_id=?", (ev.lab_run_id,)).fetchone()
        if run and run["capture_mode"] != ev.capture_mode:
            return ("rejected", f"lab_run_id: run {ev.lab_run_id} is {run['capture_mode']}; "
                                f"{ev.capture_mode} events need their own run")
        namespace = "live" if ev.capture_mode == "live" else f"replay:{ev.lab_run_id}"
        dup = c.execute(
            "SELECT 1 FROM events WHERE ingest_namespace=? AND sensor_id=? AND source_record_id=?",
            (namespace, ev.sensor_id, ev.source_record_id),
        ).fetchone()
        if dup:
            c.execute("INSERT INTO ingest_counters (sensor_id, duplicate) VALUES (?, 1) "
                      "ON CONFLICT(sensor_id) DO UPDATE SET duplicate=duplicate+1", (ev.sensor_id,))
            return ("duplicate", None)
        occurred = to_rfc3339(ev.occurred_at)
        ingested = _now()
        c.execute(
            "INSERT INTO runs (lab_run_id, capture_mode, first_seen, last_seen, last_ingested_at, events) "
            "VALUES (?,?,?,?,?,1) ON CONFLICT(lab_run_id) DO UPDATE SET "
            "first_seen=MIN(first_seen, excluded.first_seen), last_seen=MAX(last_seen, excluded.last_seen), "
            "last_ingested_at=excluded.last_ingested_at, events=events+1",
            (ev.lab_run_id, ev.capture_mode, occurred, occurred, ingested),
        )
        incident_id = self._assign_case(c, ev.sensor_id, ev.session_id, ev.src_ip, ev.lab_run_id,
                                        ev.capture_mode, occurred)
        touched.add(incident_id)
        sources.add((ev.src_ip, ev.lab_run_id, ev.capture_mode))
        event_id = "evt_" + uuid.uuid4().hex[:12]
        attrs = ev.attributes.model_dump(mode="json", exclude_none=True)
        cur = c.execute(
            "INSERT INTO events (event_id, sensor_id, source_record_id, event_type, occurred_at, ingested_at, "
            "src_ip, src_port, session_id, lab_run_id, capture_mode, attributes, incident_id, "
            "schema_version, ingest_namespace, origin_record_id, observation_kind) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, ev.sensor_id, ev.source_record_id, ev.event_type, occurred, ingested,
             ev.src_ip, ev.src_port, ev.session_id, ev.lab_run_id, ev.capture_mode,
             json.dumps(attrs), incident_id, ev.schema_version, namespace, ev.origin_record_id,
             observation_kind(ev.event_type, attrs)),
        )
        return ("stored", self._event_dict(c.execute("SELECT * FROM events WHERE seq=?", (cur.lastrowid,)).fetchone()))

    # ---- cases ----
    @staticmethod
    def _new_case(c, prefix: str, **fields) -> str:
        """Insert a case row and give it a readable id from its rowid (inc_07, inv_08)."""
        cols = ["incident_id"] + list(fields)
        cur = c.execute(f"INSERT INTO incidents ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                        ["pending"] + list(fields.values()))
        incident_id = f"{prefix}_{cur.lastrowid:02d}"
        c.execute("UPDATE incidents SET incident_id=? WHERE rowid=?", (incident_id, cur.lastrowid))
        return incident_id

    def _assign_case(self, c, sensor_id, session_id, src_ip, run, mode, occurred: str) -> str:
        """The case this event belongs to, created if needed; counts and times updated."""
        kind, basis = case_kind_for(sensor_id, session_id)
        row = None
        if session_id:
            # src_ip too: a session never changes address, so a reused id from another one is another case
            key = f"{kind}|{sensor_id}|{session_id}|{src_ip}|{run}|{mode}"
            row = c.execute("SELECT incident_id FROM incidents WHERE case_key=?", (key,)).fetchone()
        else:
            # Same source on the same sensor, within the inactivity gap of an existing bucket.
            gap = timedelta(seconds=self.cfg.windows.get("case_inactivity_seconds", 300))
            t = _ts(occurred)
            for r in c.execute(
                    "SELECT incident_id, first_seen, last_seen FROM incidents WHERE case_kind=? AND sensor_id=? "
                    "AND src_ip=? AND lab_run_id=? AND capture_mode=? ORDER BY last_seen DESC, rowid DESC",
                    (kind, sensor_id, src_ip, run, mode)):
                if _ts(r["first_seen"]) - gap <= t <= _ts(r["last_seen"]) + gap:
                    row = r
                    break
            key = f"{kind}|{sensor_id}|{src_ip}|{run}|{mode}|{occurred}|{uuid.uuid4().hex[:6]}"
        if row:
            c.execute("UPDATE incidents SET event_count=event_count+1, "
                      "first_seen=MIN(first_seen, ?), last_seen=MAX(last_seen, ?) WHERE incident_id=?",
                      (occurred, occurred, row["incident_id"]))
            return row["incident_id"]
        return self._new_case(c, "inc", src_ip=src_ip, lab_run_id=run, first_seen=occurred, last_seen=occurred,
                              event_count=1, case_kind=kind, grouping_basis=basis, sensor_id=sensor_id,
                              session_id=session_id, capture_mode=mode, case_key=key)

    def _source_auth_events(self, c, src_ip, run, mode) -> list[dict]:
        return [self._event_dict(r) for r in c.execute(
            "SELECT * FROM events WHERE src_ip=? AND lab_run_id=? AND capture_mode=? AND sensor_id=? "
            "AND event_type IN ('auth_failure', 'auth_success') ORDER BY seq", (src_ip, run, mode, SSH))]

    def _refresh_credential_cases(self, c, sources: set) -> set:
        """Password guessing across sessions (R01) gets its own credential_attempts case per
        source, user, run and mode. It cites the sessions' events but takes none of them."""
        out = set()
        for src_ip, run, mode in sorted(sources):
            pool = self._source_auth_events(c, src_ip, run, mode)
            if not pool:
                continue
            for f in r01.evaluate(pool, self.cfg):
                user = f["key"].removeprefix("user=")
                key = f"credential_attempts|{src_ip}|{run}|{mode}|{user}"
                row = c.execute("SELECT incident_id FROM incidents WHERE case_key=?", (key,)).fetchone()
                if row:
                    out.add(row["incident_id"])
                else:
                    first = min(e["occurred_at"] for e in pool)
                    out.add(self._new_case(c, "inc", src_ip=src_ip, lab_run_id=run, first_seen=first, last_seen=first,
                                           event_count=0, case_kind="credential_attempts",
                                           grouping_basis="credential_window", capture_mode=mode,
                                           username=user, case_key=key))
            # existing credential cases of this source re-run on the larger pool
            out |= {r["incident_id"] for r in c.execute(
                "SELECT incident_id FROM incidents WHERE case_kind='credential_attempts' AND src_ip=? "
                "AND lab_run_id=? AND capture_mode=?", (src_ip, run, mode))}
        return out

    def _apply_investigation(self, c, link: dict) -> set:
        """Keep the investigation for this link in step with its decision. Returns case ids to re-sync.
        An investigation exists only while at least one of its links is confirmed."""
        a, b = link["from_incident_id"], link["to_incident_id"]
        if a == b:
            return set()
        invs = [dict(r) for r in c.execute(
            "SELECT * FROM incidents WHERE case_kind='investigation' ORDER BY rowid")]
        home = next((i for i in invs if link["link_id"] in json.loads(i["basis_link_ids"])), None)
        if link["status"] == "confirmed" and home is None:
            home = next((i for i in invs if i["status"] == "open"
                         and {a, b} & set(json.loads(i["children"]))), None)
        if home is None:
            if link["status"] != "confirmed":
                return set()
            child = c.execute("SELECT src_ip, lab_run_id, capture_mode, first_seen FROM incidents "
                              "WHERE incident_id=?", (a,)).fetchone()
            inv_id = self._new_case(c, "inv", src_ip=child["src_ip"], lab_run_id=child["lab_run_id"],
                                    first_seen=child["first_seen"], last_seen=child["first_seen"],
                                    case_kind="investigation", grouping_basis="analyst_confirmed_link",
                                    capture_mode=child["capture_mode"], case_key=f"investigation|{link['link_id']}")
            home = dict(c.execute("SELECT * FROM incidents WHERE incident_id=?", (inv_id,)).fetchone())
        basis = json.loads(home["basis_link_ids"])
        if link["link_id"] not in basis:
            basis.append(link["link_id"])
        # Another open investigation that shares a child is merged into this one.
        if link["status"] == "confirmed":
            for other in invs:
                if other["incident_id"] != home["incident_id"] and other["status"] == "open" \
                        and {a, b} & set(json.loads(other["children"])):
                    basis += [l for l in json.loads(other["basis_link_ids"]) if l not in basis]
                    c.execute("UPDATE incidents SET status='dissolved', basis_link_ids='[]' WHERE incident_id=?",
                              (other["incident_id"],))
        confirmed = [self._link_row(r) for r in c.execute(
            f"SELECT * FROM links WHERE status='confirmed' AND link_id IN ({','.join('?' * len(basis))}) "
            "ORDER BY decided_at, link_id", basis)]
        old_children = json.loads(home["children"])
        children = list(dict.fromkeys(x for l in confirmed for x in (l["from_incident_id"], l["to_incident_id"])))
        status = "open" if confirmed else "dissolved"
        c.execute("UPDATE incidents SET parent_id=NULL WHERE parent_id=?", (home["incident_id"],))
        if confirmed:
            c.execute(f"UPDATE incidents SET parent_id=? WHERE incident_id IN ({','.join('?' * len(children))})",
                      [home["incident_id"]] + children)
        # A dissolved investigation keeps its last membership for the audit trail.
        c.execute("UPDATE incidents SET status=?, basis_link_ids=?, children=? WHERE incident_id=?",
                  (status, json.dumps(basis), json.dumps(children or old_children), home["incident_id"]))
        return {home["incident_id"], a, b} | set(old_children) | set(children)

    @staticmethod
    def _parents(c, ids) -> set:
        if not ids:
            return set()
        return {r[0] for r in c.execute(
            f"SELECT DISTINCT parent_id FROM incidents WHERE parent_id IS NOT NULL "
            f"AND incident_id IN ({','.join('?' * len(ids))})", list(ids))}

    @staticmethod
    def _sync_order(c, ids) -> list:
        """Children before investigations: an investigation's score reads its children's findings."""
        kinds = {r["incident_id"]: r["case_kind"] for r in c.execute(
            f"SELECT incident_id, case_kind FROM incidents WHERE incident_id IN ({','.join('?' * len(ids))})",
            list(ids))} if ids else {}
        return sorted(kinds, key=lambda i: (kinds[i] == "investigation", i))

    def _incident_events(self, c, incident_id: str) -> list[dict]:
        return [self._event_dict(r) for r in
                c.execute("SELECT * FROM events WHERE incident_id=? ORDER BY seq", (incident_id,))]

    def _source_events(self, c, src_ip, run, mode) -> list[dict]:
        return [self._event_dict(r) for r in c.execute(
            "SELECT * FROM events WHERE src_ip=? AND lab_run_id=? AND capture_mode=? ORDER BY seq",
            (src_ip, run, mode))]

    def _servings_for(self, c, tok: dict, use: dict) -> list[dict]:
        """Eligible issuances of a token for one presentation: bait_served records that list it, on the
        sensor where it was planted, in the same run and mode, not after the presentation, not expired."""
        out = []
        for r in c.execute(
                "SELECT * FROM events WHERE event_type='bait_served' AND sensor_id=? AND lab_run_id=? "
                "AND capture_mode=? AND occurred_at<=? ORDER BY occurred_at, seq",
                (tok["planted_on"], use["lab_run_id"], use["capture_mode"], use["occurred_at"])):
            s = self._event_dict(r)
            a = s["attributes"]
            expires = a.get("issued_expires_at")
            if tok["id"] in a.get("honeytoken_ids", []) and (not expires or _ts(expires) > _ts(use["occurred_at"])):
                out.append(s)
        return out

    def _request_for(self, c, tok: dict, use: dict) -> Optional[dict]:
        """Newest earlier bait-read command naming a registered asset that holds the token. A command
        is request evidence only; without the bait_assets registry there is nothing to match."""
        assets = {a["asset_id"] for a in self.cfg.bait_assets.values()
                  if tok["id"] in a.get("honeytoken_ids", []) and a.get("sensor_id") == tok["planted_on"]}
        if not assets:
            return None
        for r in c.execute(
                "SELECT * FROM events WHERE event_type='command_input' AND schema_version='1.1' AND sensor_id=? "
                "AND lab_run_id=? AND capture_mode=? AND occurred_at<=? ORDER BY occurred_at DESC, seq DESC",
                (tok["planted_on"], use["lab_run_id"], use["capture_mode"], use["occurred_at"])):
            e = self._event_dict(r)
            if e["attributes"].get("requested_asset_id") in assets:
                return e
        return None

    def _refresh_links(self, c, loaded: dict, sources: set, token_runs: set = frozenset()) -> list[dict]:
        """`loaded`: case id -> its events, for the cases this ingest touched;
        `sources`: (src_ip, run, mode) touched, for candidate links across cases;
        `token_runs`: (run, mode) that received a serving or a bait-read request, whose earlier
        token presentations are matched again. Returns new or changed links."""
        found = []
        for src_ip, run, mode in sorted(sources):
            logged_in = {r["incident_id"] for r in c.execute(
                "SELECT DISTINCT incident_id FROM events WHERE src_ip=? AND lab_run_id=? AND capture_mode=? "
                "AND sensor_id=? AND event_type='auth_success'", (src_ip, run, mode, SSH))}
            found += linking.candidate_links(self._source_events(c, src_ip, run, mode), self.cfg, logged_in)
        uses = {e["event_id"]: e for events in loaded.values() for e in linking.token_uses(events, self.cfg)}
        for run, mode in sorted(token_runs):
            rows = c.execute("SELECT * FROM events WHERE lab_run_id=? AND capture_mode=? "
                             "AND attributes LIKE '%\"honeytoken_id\"%' ORDER BY seq", (run, mode))
            uses.update({e["event_id"]: e for e in linking.token_uses([self._event_dict(r) for r in rows], self.cfg)})
        found += linking.token_links(list(uses.values()), self.cfg,
                                     lambda tok, use: self._servings_for(c, tok, use),
                                     lambda tok, use: self._request_for(c, tok, use))
        new = []
        for l in found:
            issuances = json.dumps(l["candidate_issuance_ids"])
            if l["attribution"]:
                # Token links are re-derived: a later serving can turn unique into ambiguous.
                old = c.execute("SELECT * FROM links WHERE link_id=?", (l["link_id"],)).fetchone()
                if old and (old["from_event_id"], old["basis"], old["attribution"], old["candidate_issuance_ids"]) \
                        == (l["from_event_id"], l["basis"], l["attribution"], issuances):
                    continue
                c.execute(
                    "INSERT INTO links (link_id, from_event_id, to_event_id, from_sensor, to_sensor, kind, basis, "
                    "from_incident_id, to_incident_id, attribution, candidate_issuance_ids, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(link_id) DO UPDATE SET "
                    "from_event_id=excluded.from_event_id, basis=excluded.basis, attribution=excluded.attribution, "
                    "candidate_issuance_ids=excluded.candidate_issuance_ids",
                    (l["link_id"], l["from_event_id"], l["to_event_id"], l["from_sensor"], l["to_sensor"], l["kind"],
                     l["basis"], l["from_incident_id"], l["to_incident_id"], l["attribution"], issuances, _now()))
                new.append(self._link_row(c.execute("SELECT * FROM links WHERE link_id=?", (l["link_id"],)).fetchone()))
                continue
            if c.execute("SELECT 1 FROM links WHERE kind=? AND from_event_id=? AND to_event_id=?",
                         (l["kind"], l["from_event_id"], l["to_event_id"])).fetchone():
                continue  # same evidence already linked (a pre-migration link keeps its id and decision)
            if c.execute(
                    "SELECT 1 FROM links WHERE kind='candidate' AND attribution IS NULL "
                    "AND ((from_incident_id=? AND to_incident_id=?) OR (from_incident_id=? AND to_incident_id=?))",
                    (l["from_incident_id"], l["to_incident_id"], l["to_incident_id"], l["from_incident_id"])).fetchone():
                continue  # one IP/time candidate per pair of cases, whichever key found it first
            cur = c.execute(
                "INSERT OR IGNORE INTO links (link_id, from_event_id, to_event_id, from_sensor, to_sensor, "
                "kind, basis, from_incident_id, to_incident_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (l["link_id"], l["from_event_id"], l["to_event_id"], l["from_sensor"], l["to_sensor"],
                 l["kind"], l["basis"], l["from_incident_id"], l["to_incident_id"], _now()),
            )
            if cur.rowcount:
                new.append(self._link_row(c.execute("SELECT * FROM links WHERE link_id=?", (l["link_id"],)).fetchone()))
        return new

    @staticmethod
    def _link_row(r) -> dict:
        link = dict(r)
        link["candidate_issuance_ids"] = json.loads(link.get("candidate_issuance_ids") or "[]")
        return link

    def _links_for(self, c, incident_id: str) -> list[dict]:
        return [self._link_row(r) for r in c.execute(
            "SELECT * FROM links WHERE from_incident_id=? OR to_incident_id=? ORDER BY created_at, link_id",
            (incident_id, incident_id))]

    def _links_among(self, c, ids: list) -> list[dict]:
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        return [self._link_row(r) for r in c.execute(
            f"SELECT * FROM links WHERE from_incident_id IN ({marks}) AND to_incident_id IN ({marks}) "
            "ORDER BY created_at, link_id", list(ids) + list(ids))]

    @staticmethod
    def _stored_findings(c, ids: list) -> list[dict]:
        out = []
        for i in ids:
            out += [json.loads(r["data"]) for r in c.execute(
                "SELECT data FROM findings WHERE incident_id=? ORDER BY rowid", (i,))]
        return out

    def _sync_incident(self, c, incident_id: str, events: Optional[list] = None) -> list[dict]:
        """Re-run rules and scoring for one case; store and return what changed."""
        case = dict(c.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone())
        kind = case["case_kind"]
        if kind == "legacy_ip_run":
            return []  # superseded rows are kept as they were
        inherited: list = []
        if kind == "investigation":
            children = json.loads(case["children"]) if case["status"] == "open" else []
            links = self._links_among(c, children)
            basis = set(json.loads(case["basis_link_ids"]))
            fresh = evaluate_investigation(case, [l for l in links if l["link_id"] in basis])
            inherited = sorted(self._stored_findings(c, children), key=lambda f: (f["created_at"], f["finding_id"]))
            if children:
                bounds = c.execute(
                    f"SELECT MIN(first_seen), MAX(last_seen), SUM(event_count) FROM incidents "
                    f"WHERE incident_id IN ({','.join('?' * len(children))})", children).fetchone()
                c.execute("UPDATE incidents SET first_seen=?, last_seen=?, event_count=? WHERE incident_id=?",
                          (bounds[0], bounds[1], bounds[2] or 0, incident_id))
        elif kind == "credential_attempts":
            links = []
            pool = [e for e in self._source_auth_events(c, case["src_ip"], case["lab_run_id"], case["capture_mode"])
                    if e["attributes"].get("username", "") == case["username"]]
            fresh = evaluate_incident(case, pool, self.cfg, CREDENTIAL_RULES)
            cited = {i for f in fresh for i in f["evidence_event_ids"]}
            times = [e["occurred_at"] for e in pool if e["event_id"] in cited]
            if times:
                c.execute("UPDATE incidents SET first_seen=?, last_seen=? WHERE incident_id=?",
                          (min(times), max(times), incident_id))
        else:
            links = self._links_for(c, incident_id)
            if events is None:
                events = self._incident_events(c, incident_id)
            fresh = evaluate_incident(case, events, self.cfg, SESSION_RULES, links)
        # rowid = order first recorded; scoring walks findings in that order (new ones last).
        existing = {r["finding_id"]: json.loads(r["data"]) for r in c.execute(
            "SELECT finding_id, data FROM findings WHERE incident_id=? ORDER BY rowid", (incident_id,))}
        rank = {fid: i for i, fid in enumerate(existing)}
        fresh.sort(key=lambda f: rank.get(f["finding_id"], len(rank)))  # stable: new ones keep rule order
        for f in fresh:
            f["created_at"] = existing[f["finding_id"]]["created_at"] if f["finding_id"] in existing else _now()
        scored = score_incident(inherited + fresh, links, self.cfg)
        changed = []
        for f in fresh:
            f["points"], f["pending_confirmation"] = scored["points"][f["finding_id"]]
            if existing.get(f["finding_id"]) == f:
                continue
            c.execute(
                "INSERT INTO findings (finding_id, incident_id, rule_id, data, created_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET data=excluded.data",
                (f["finding_id"], incident_id, f["rule_id"], json.dumps(f), f["created_at"]),
            )
            changed.append(f)
        stale = set(existing) - {f["finding_id"] for f in fresh}  # e.g. R05 after a link is rejected
        for fid in stale:
            c.execute("DELETE FROM findings WHERE finding_id=?", (fid,))
        c.execute("UPDATE incidents SET score=?, severity=? WHERE incident_id=?",
                  (scored["score"], scored["severity"], incident_id))
        return changed

    # ---- reads ----
    @staticmethod
    def _event_dict(r: sqlite3.Row) -> dict:
        attributes = json.loads(r["attributes"])
        return {
            "schema_version": r["schema_version"],
            "event_id": r["event_id"],
            "seq": r["seq"],
            "ingested_at": r["ingested_at"],
            "incident_id": r["incident_id"],
            "source_record_id": r["source_record_id"],
            "sensor_id": r["sensor_id"],
            "event_type": r["event_type"],
            "occurred_at": r["occurred_at"],
            "src_ip": r["src_ip"],
            "src_port": r["src_port"],
            "session_id": r["session_id"],
            "lab_run_id": r["lab_run_id"],
            "capture_mode": r["capture_mode"],
            "ingest_namespace": r["ingest_namespace"],
            "origin_record_id": r["origin_record_id"],
            "observation_kind": r["observation_kind"],
            "evidence_role": evidence_role(r["event_type"], attributes),
            "attributes": attributes,
        }

    @staticmethod
    def public_link(link: dict) -> dict:
        return {k: link[k] for k in LINK_FIELDS}

    def list_events(self, incident_id=None, sensor_id=None, since_seq=0, limit=200,
                    lab_run_id=None, capture_mode=None) -> dict:
        sql, args = "SELECT * FROM events WHERE seq > ?", [since_seq]
        if lab_run_id:
            sql += " AND lab_run_id=?"
            args.append(lab_run_id)
        if capture_mode:
            sql += " AND capture_mode=?"
            args.append(capture_mode)
        if incident_id:
            ids = self._case_event_owners(incident_id)
            sql += f" AND incident_id IN ({','.join('?' * len(ids))})"
            args += ids
        if sensor_id:
            sql += " AND sensor_id=?"
            args.append(sensor_id)
        sql += " ORDER BY seq ASC LIMIT ?"
        args.append(limit)
        items = [self._event_dict(r) for r in self.conn.execute(sql, args)]
        return {"items": items, "next_seq": items[-1]["seq"] if items else since_seq}

    def _case_event_owners(self, incident_id: str) -> list:
        """Cases whose events make up this one: itself, or an open investigation's children."""
        r = self.conn.execute("SELECT case_kind, children, status FROM incidents WHERE incident_id=?",
                              (incident_id,)).fetchone()
        if r and r["case_kind"] == "investigation":
            return json.loads(r["children"]) if r["status"] == "open" else []
        return [incident_id]

    def max_seq(self) -> int:
        return self.conn.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()[0]

    def list_runs(self) -> list[dict]:
        """Every run, newest first. `active` marks at most one live run: the one that received
        the newest live event, if that arrived less than ACTIVE_RUN_MINUTES ago (backend clock).
        "Newest" is by event seq, so runs filled in the same millisecond still order correctly."""
        rows = [dict(r) for r in self.conn.execute(
            "SELECT r.*, (SELECT MAX(e.seq) FROM events e WHERE e.lab_run_id = r.lab_run_id) AS last_seq "
            "FROM runs r ORDER BY last_seq DESC")]
        newest_live = next((r for r in rows if r["capture_mode"] == "live"), None)
        now = datetime.now(timezone.utc)
        for r in rows:
            r["active"] = bool(
                r is newest_live
                and (now - _ts(r["last_ingested_at"])).total_seconds() < ACTIVE_RUN_MINUTES * 60)
            r["legacy_mixed"] = bool(r["legacy_mixed"])
            del r["last_seq"]
        return rows

    def run_mode(self, lab_run_id: str) -> Optional[str]:
        r = self.conn.execute("SELECT capture_mode FROM runs WHERE lab_run_id=?", (lab_run_id,)).fetchone()
        return r["capture_mode"] if r else None

    def incident_exists(self, incident_id: str) -> bool:
        return self.conn.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is not None

    def _case_findings(self, r) -> list[dict]:
        """Findings that make up a case: its own, plus an open investigation's children's."""
        own = self.list_findings(r["incident_id"])
        if r["case_kind"] != "investigation" or r["status"] != "open":
            return own
        children = sorted(self._stored_findings(self.conn, json.loads(r["children"])),
                          key=lambda f: (f["created_at"], f["finding_id"]))
        return children + own

    def incident_summary(self, incident_id: str) -> dict:
        r = self.conn.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        findings = self._case_findings(r)
        seen = {f["stage"] for f in findings}
        return {
            "incident_id": r["incident_id"], "src_ip": r["src_ip"], "lab_run_id": r["lab_run_id"],
            "score": r["score"], "severity": r["severity"],
            "capture_mode": r["capture_mode"],
            "stages_observed": [s for s in STAGE_ORDER if s in seen],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"], "event_count": r["event_count"],
            "case_kind": r["case_kind"], "grouping_basis": r["grouping_basis"],
            "sensor_id": r["sensor_id"], "session_id": r["session_id"],
            "parent_id": r["parent_id"],
            "children": json.loads(r["children"]) if r["case_kind"] == "investigation" else [],
            "status": r["status"],
            "quiet": r["case_kind"] in SESSION_KINDS and not findings,
        }

    @contextmanager
    def snapshot(self):
        """Several reads that must agree with each other see one committed state."""
        c = self.conn
        if c.in_transaction:
            yield
            return
        c.execute("BEGIN")
        try:
            yield
        finally:
            c.execute("COMMIT")

    def list_incidents(self, include_quiet: bool = True) -> list[dict]:
        with self.snapshot():
            ids = [r[0] for r in self.conn.execute(
                "SELECT incident_id FROM incidents WHERE status != 'superseded' ORDER BY last_seen DESC, rowid DESC")]
            items = [self.incident_summary(i) for i in ids]
            return items if include_quiet else [i for i in items if not i["quiet"]]

    def list_findings(self, incident_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT data FROM findings WHERE incident_id=? ORDER BY rowid", (incident_id,))
        return [json.loads(r["data"]) for r in rows]

    def list_links(self, incident_id: Optional[str] = None) -> list[dict]:
        if incident_id:
            rows = self._links_for(self.conn, incident_id)
        else:
            rows = [self._link_row(r) for r in self.conn.execute("SELECT * FROM links ORDER BY created_at, link_id")]
        return [self.public_link(r) for r in rows]

    def sessions(self, incident_id: str) -> list[dict]:
        ids = self._case_event_owners(incident_id)
        if not ids:
            return []
        rows = self.conn.execute(
            "SELECT session_id, sensor_id, MIN(occurred_at) AS started_at, "
            "SUM(event_type='command_input') AS commands FROM events "
            f"WHERE incident_id IN ({','.join('?' * len(ids))}) AND session_id IS NOT NULL "
            "GROUP BY sensor_id, session_id ORDER BY started_at, session_id", ids)
        return [dict(r) for r in rows]

    def incident_detail(self, incident_id: str) -> dict:
        """Incident minus `summary` and `active_block`, which main.py adds."""
        with self.snapshot():
            r = self.conn.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            findings = self._case_findings(r)
            if r["case_kind"] == "investigation":
                links = self._links_among(self.conn, json.loads(r["children"]) if r["status"] == "open" else [])
            else:
                links = self._links_for(self.conn, incident_id)
            out = self.incident_summary(incident_id)
            out.update({
                "findings": findings,
                "score_breakdown": score_incident(findings, links, self.cfg)["breakdown"],
                "links": [self.public_link(l) for l in links],
                "sessions": self.sessions(incident_id),
            })
            return out

    def transcript(self, incident_id: str, session_id: Optional[str]) -> Optional[dict]:
        ids = self._case_event_owners(incident_id) or ["-"]
        owners = f"incident_id IN ({','.join('?' * len(ids))})"
        if not session_id:
            # Default: the first session that logged in, else the first session at all.
            r = self.conn.execute(
                f"SELECT session_id FROM events WHERE {owners} AND sensor_id='ssh-decoy-01' "
                "AND session_id IS NOT NULL ORDER BY (event_type='auth_success') DESC, occurred_at, seq LIMIT 1",
                ids).fetchone()
            if not r:
                return {"session_id": None, "lines": []}
            session_id = r["session_id"]
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE {owners} AND sensor_id='ssh-decoy-01' AND session_id=? "
            "ORDER BY occurred_at, seq", ids + [session_id]).fetchall()
        if not rows:
            return None
        lines = []
        for r in rows:
            kind = TRANSCRIPT_KINDS.get(r["event_type"])
            if not kind:
                continue
            a = json.loads(r["attributes"])
            user = a.get("username", "")
            text = {
                "login_failed": f"login failed for user '{user}'",
                "login_ok": f"login accepted for user '{user}'",
                "command": a.get("command", ""),
                "close": "session closed",
            }[kind]
            lines.append({"event_id": r["event_id"], "occurred_at": r["occurred_at"], "kind": kind, "text": text})
        return {"session_id": session_id, "lines": lines}

    def stats(self) -> dict:
        c = self.conn
        live = "status = 'open' AND case_kind != 'investigation'"
        with self.snapshot():
            by_rule = {r["rule_id"]: r["n"] for r in c.execute(
                "SELECT f.rule_id, COUNT(*) AS n FROM findings f JOIN incidents i USING (incident_id) "
                "WHERE i.status != 'superseded' GROUP BY f.rule_id ORDER BY f.rule_id")}
            first = c.execute(
                "SELECT f.incident_id, f.created_at FROM findings f JOIN incidents i USING (incident_id) "
                "WHERE i.status != 'superseded' AND i.event_count > 0 ORDER BY f.created_at LIMIT 1").fetchone()
            first_alert = None
            if first:
                # From the backend receiving that case's first event to its first finding.
                start = c.execute("SELECT MIN(ingested_at) FROM events WHERE incident_id=?",
                                  (first["incident_id"],)).fetchone()[0]
                first_alert = round(max(0.0, (_ts(first["created_at"]) - _ts(start)).total_seconds()), 3)
            return {
                "raw_events": c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "incidents": c.execute(f"SELECT COUNT(*) FROM incidents WHERE {live}").fetchone()[0],
                "low_priority_incidents": c.execute(f"SELECT COUNT(*) FROM incidents WHERE {live} AND score < ?",
                                                    (self.cfg.low_priority_below,)).fetchone()[0],
                "findings_by_rule": by_rule,
                "first_alert_seconds": first_alert,
            }

    def export_events(self, incident_id: str) -> list[dict]:
        """Case events for export with password hashes removed."""
        out = []
        for e in self.list_events(incident_id=incident_id, limit=1_000_000)["items"]:
            e["attributes"] = {k: v for k, v in e["attributes"].items() if k != "password_sha256"}
            out.append(e)
        return out

    def sensor_last_seen(self) -> dict:
        out = {s: None for s in SENSORS}
        for r in self.conn.execute("SELECT sensor_id, MAX(occurred_at) AS t FROM events GROUP BY sensor_id"):
            out[r["sensor_id"]] = r["t"]
        return out

    # ---- response eligibility (PR 5; M2's preview and apply call this) ----
    def response_eligibility(self, incident_id: str) -> Optional[dict]:
        """Authoritative answer for a live block on this case's address. Every key is always
        present; `reasons` lists every failed check. M2 refuses on anything but eligible + []."""
        with self.snapshot():
            r = self.conn.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if r is None:
                return None
            run, mode, target = r["lab_run_id"], r["capture_mode"], r["src_ip"]
            reasons = []
            if mode != "live":
                reasons.append({"code": "replay_data", "message": "case is replay evidence"})
            active = next((x for x in self.list_runs() if x["active"]), None)
            if active is None or active["lab_run_id"] != run:
                reasons.append({"code": "no_live_run", "message": f"run {run} is not the active live run"})
            if r["status"] == "dissolved":
                reasons.append({"code": "case_dissolved", "message": "the investigation was dissolved"})
            elif r["status"] == "superseded":
                reasons.append({"code": "case_superseded",
                                "message": "pre-migration case; use the session case that replaced it"})
            # The observation time is the sensor's clock, capped at when the backend received it,
            # so a sensor clock running ahead can never make old traffic look fresh.
            web = self.conn.execute(
                "SELECT occurred_at, ingested_at FROM events WHERE sensor_id='web-decoy-01' AND src_ip=? "
                "AND lab_run_id=? AND capture_mode=? ORDER BY seq DESC LIMIT 1", (target, run, mode)).fetchone()
            observed = None
            if web:
                observed = to_rfc3339(min(_ts(web["occurred_at"]), _ts(web["ingested_at"])))
            if observed is None or datetime.now(timezone.utc) - _ts(observed) >= timedelta(minutes=ELIGIBLE_MINUTES):
                reasons.append({"code": "stale_observation",
                                "message": f"no web-decoy-01 event from this address in the last {ELIGIBLE_MINUTES} minutes"})
            return {"incident_id": incident_id, "eligible": not reasons, "target_ip": target, "lab_run_id": run,
                    "capture_mode": mode, "reasons": reasons, "last_web_observation_at": observed,
                    "checked_at": _now()}

    # ---- collector health (PR 5) ----
    def record_heartbeat(self, hb) -> None:
        body = hb.model_dump(mode="json")
        self._write(lambda c: c.execute(
            "INSERT INTO collector_heartbeats (collector_id, sensor_id, received_at, body) VALUES (?,?,?,?) "
            "ON CONFLICT(collector_id, sensor_id) DO UPDATE SET received_at=excluded.received_at, body=excluded.body",
            (hb.collector_id, hb.sensor_id, _now(), json.dumps(body))))

    def sensor_health(self) -> dict:
        """Per sensor: service, collection and activity, plus the latest heartbeat translated to
        M1's CollectorHealth names (contracts/API.md, Health). Activity is never health."""
        now = datetime.now(timezone.utc)
        out = {}
        with self.snapshot():
            for sensor in SENSORS:
                hb = self.conn.execute("SELECT * FROM collector_heartbeats WHERE sensor_id=? "
                                       "ORDER BY received_at DESC LIMIT 1", (sensor,)).fetchone()
                last = self.conn.execute("SELECT MAX(occurred_at) AS occ, MAX(ingested_at) AS ing FROM events "
                                         "WHERE sensor_id=?", (sensor,)).fetchone()
                counts = self.conn.execute("SELECT COUNT(*) FROM events WHERE sensor_id=?", (sensor,)).fetchone()[0]
                dup = self.conn.execute("SELECT duplicate FROM ingest_counters WHERE sensor_id=?", (sensor,)).fetchone()
                if last["ing"] is None:
                    activity = "none"
                else:
                    recent = now - _ts(last["ing"]) < timedelta(minutes=ACTIVITY_MINUTES)
                    activity = "recent" if recent else "quiet"
                row = {"service": "unknown", "collection": "never", "activity": activity, "collector_id": None,
                       "heartbeat_at": None, "process_state": None, "last_read_at": None, "last_ingest_at": None,
                       "backlog_records": None, "oldest_backlog_age_s": None, "error_count": None, "ingest": None,
                       "clock_skew_s": None, "last_event_at": last["occ"]}
                if hb:
                    b = json.loads(hb["body"])
                    received = _ts(hb["received_at"])
                    fresh = (now - received).total_seconds() < HEARTBEAT_FRESH_SECONDS
                    state = {"up": "running", "down": "stopped"}.get(b["sensor_process"], "unknown")
                    row.update({
                        "service": {"running": "up", "stopped": "down"}.get(state, "unknown") if fresh else "unknown",
                        "collection": "ok" if fresh else "stale",
                        "collector_id": hb["collector_id"], "heartbeat_at": hb["received_at"],
                        "process_state": state, "last_read_at": b["last_read_at"],
                        "last_ingest_at": b["last_ingest_ok_at"], "backlog_records": b["backlog_lines"],
                        "oldest_backlog_age_s": b["oldest_backlog_age_s"], "error_count": b["errors_total"],
                        "ingest": {"accepted": counts, "duplicate": dup["duplicate"] if dup else 0,
                                   "rejected": b["rejected_total"], "quarantined": b["quarantined_total"],
                                   "retry": None},
                        "clock_skew_s": round((_ts(b["sent_at"]) - received).total_seconds(), 3),
                    })
                out[sensor] = row
        return out

    # ---- source profiles (a view; never scored) ----
    def list_profiles(self, lab_run_id: Optional[str] = None) -> list[dict]:
        sql, args = "SELECT DISTINCT src_ip, lab_run_id, capture_mode FROM events", []
        if lab_run_id:
            sql += " WHERE lab_run_id=?"
            args.append(lab_run_id)
        with self.snapshot():
            keys = [tuple(r) for r in self.conn.execute(sql, args)]
            items = [self._profile(*k) for k in keys]
        return sorted(items, key=lambda p: p["last_seen"], reverse=True)

    def profile(self, src_ip: str, lab_run_id: str) -> Optional[dict]:
        r = self.conn.execute("SELECT capture_mode FROM events WHERE src_ip=? AND lab_run_id=? LIMIT 1",
                              (src_ip, lab_run_id)).fetchone()
        if not r:
            return None
        with self.snapshot():
            return self._profile(src_ip, lab_run_id, r["capture_mode"])

    def _profile(self, src_ip: str, run: str, mode: str) -> dict:
        c = self.conn
        span = c.execute("SELECT MIN(occurred_at), MAX(occurred_at) FROM events WHERE src_ip=? AND lab_run_id=? "
                         "AND capture_mode=?", (src_ip, run, mode)).fetchone()
        sensors = {r["sensor_id"]: {"cases": r["cases"], "events": r["events"]} for r in c.execute(
            "SELECT sensor_id, COUNT(DISTINCT incident_id) AS cases, COUNT(*) AS events FROM events "
            "WHERE src_ip=? AND lab_run_id=? AND capture_mode=? GROUP BY sensor_id ORDER BY sensor_id",
            (src_ip, run, mode))}
        users, claims = set(), []
        for r in c.execute("SELECT sensor_id, event_type, attributes FROM events WHERE src_ip=? AND lab_run_id=? "
                           "AND capture_mode=? ORDER BY seq", (src_ip, run, mode)):
            a = json.loads(r["attributes"])
            if r["event_type"] in ("auth_failure", "auth_success") and a.get("username"):
                users.add(a["username"][:64])
            for field in ("client_version", "user_agent"):
                if a.get(field):
                    claim = {"sensor_id": r["sensor_id"], field: a[field][:128]}
                    if claim not in claims and len(claims) < 20:
                        claims.append(claim)
        case_ids = [r["incident_id"] for r in c.execute(
            "SELECT incident_id FROM incidents WHERE src_ip=? AND lab_run_id=? AND capture_mode=? "
            "AND status != 'superseded' AND case_kind != 'investigation' ORDER BY rowid", (src_ip, run, mode))]
        return {"src_ip": src_ip, "lab_run_id": run, "capture_mode": mode,
                "first_seen": span[0], "last_seen": span[1], "sensors": sensors,
                "attempted_usernames": sorted(users)[:50], "client_claims": claims,
                "case_ids": case_ids, "note": PROFILE_NOTE}
