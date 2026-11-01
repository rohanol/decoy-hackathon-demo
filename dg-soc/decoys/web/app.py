"""Stateful synthetic portal; no attacker-selected execution, query or fetch."""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from flask import Flask, Response, g, request

from .observation import RequestObservation, decode
from .policy_bridge import resolve_enforcer
from .sessions import SessionStore

ROOT = Path(__file__).resolve().parents[2]
ASSET = Path(__file__).parent / "assets/customer_data.csv"
BAIT_TOKEN = "DGLAB-Bkp-2210"
SQL_BAIT = re.compile(r"union\s+select|'\s*(?:or|and)\b|;\s*(?:drop|insert|update|delete)\b|(?:sleep|benchmark|pg_sleep)\s*\(", re.I)
COOKIE = "dg_lab_session"
PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Files / Internal Operations</title><style>
body{{font:16px system-ui;background:#edf0f3;color:#253345;max-width:850px;margin:55px auto}}
header,main{{background:white;padding:28px;margin:12px;border:1px solid #cdd3db}}
a{{color:#235e91;margin-right:20px}}input,button{{padding:10px;margin:8px}}
small{{color:#697789}}pre{{white-space:pre-wrap}}</style>
<header><small>FILES-SRV-02 · ISOLATED LAB DECOY · SYNTHETIC DATA</small><h1>Operations Portal</h1>
<a href="/">Home</a><a href="/login">Login</a><a href="/dashboard">Dashboard</a>
<a href="/search">Search</a><a href="/download?file=customer_data.csv">Customer export</a>
<a href="/upload">Submit report</a></header><main>{}</main></html>"""


def create_app(config=None, *, policy_check=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(
        MAX_CONTENT_LENGTH=16384, MAX_FORM_PARTS=32, MAX_FORM_MEMORY_SIZE=16384,
        LOG_PATH=os.environ.get("LOG_PATH", str(ROOT / "deployment/state/web-log/web.json")),
        BLOCKLIST_PATH=os.environ.get("BLOCKLIST_PATH", str(ROOT / "deployment/state/blocklist.json")),
        HONEYTOKENS_PATH=os.environ.get("HONEYTOKENS_PATH", str(ROOT / "config/honeytokens.yaml")),
        LAB_RUN_ID=os.environ.get("LAB_RUN_ID", "run-01"),
        ATTACKER_IPS=os.environ.get("ATTACKER_IPS", "192.168.77.10"),
        DECOY_SESSION_TTL=900, DECOY_SESSION_CAPACITY=512, UPLOAD_FILE_LIMIT=8192,
        WEB_EVENT_SCHEMA_VERSION=os.environ.get("WEB_EVENT_SCHEMA_VERSION", "1.0"),
    )
    app.config.update(config or {})
    tokens = yaml.safe_load(Path(app.config["HONEYTOKENS_PATH"]).read_text())["tokens"]
    if app.config["WEB_EVENT_SCHEMA_VERSION"] not in {"1.0", "1.1"}:
        raise ValueError("Unsupported web event schema version")
    checker = policy_check or resolve_enforcer(
        app.config["BLOCKLIST_PATH"], app.config["ATTACKER_IPS"].replace(",", " ").split()
    )
    session_args = {"ttl": app.config["DECOY_SESSION_TTL"], "capacity": app.config["DECOY_SESSION_CAPACITY"]}
    if "SESSION_CLOCK" in app.config:
        session_args["clock"] = app.config["SESSION_CLOCK"]
    sessions = SessionStore(**session_args)
    app.extensions["decoy_sessions"] = sessions
    lock = threading.Lock()

    def page(body, status=200):
        return Response(PAGE.format(body), status=status, mimetype="text/html")

    def semantic(kind, **attrs):
        g.semantic_type = kind
        g.semantic_attrs.update(attrs)

    def protected():
        if not g.session or not g.session.authenticated:
            g.semantic_attrs.update(outcome="denied", access_state="authentication_required")
            return page('<h2>Staff login required</h2><a href="/login">Sign in</a>', 401)
        return None

    def replace_session(authenticated=False):
        old = g.session.reference if g.session else None
        sessions.revoke(request.cookies.get(COOKIE))
        # An anonymous session may have just been created on this request.
        sessions.revoke(g.cookie)
        g.cookie, g.session = sessions.create(app.config["LAB_RUN_ID"], authenticated=authenticated)
        if old:
            g.semantic_attrs["previous_session_id"] = old

    @app.before_request
    def policy_first():
        g.request_id = "req_" + uuid.uuid4().hex
        g.semantic_type, g.semantic_attrs = None, {}
        g.response_class, g.cookie = "normal", None
        g.src_ip = request.remote_addr
        g.observation = RequestObservation(request, seeded_secrets=(BAIT_TOKEN,))
        g.session = sessions.get(request.cookies.get(COOKIE), app.config["LAB_RUN_ID"])
        try:
            ipaddress.IPv4Address(g.src_ip)
        except (ipaddress.AddressValueError, TypeError):
            return page("<h2>IPv4 lab connection required</h2>", 400)
        try:
            enforcement = checker(g.src_ip)
            action_id, revision = enforcement if isinstance(enforcement, tuple) else (enforcement, None)
        except (OSError, ValueError, KeyError, TypeError):
            return page("<h2>Portal temporarily unavailable</h2>", 503)
        if action_id:
            g.response_class = "blocked"
            semantic("blocked_request", block_action_id=action_id, outcome="denied")
            if type(revision) is int:
                g.semantic_attrs["policy_revision"] = revision
            return page("<h2>Access denied</h2>", 403)
        if not g.session:
            g.cookie, g.session = sessions.create(app.config["LAB_RUN_ID"])
        g.observation.capture()
        if g.observation.body_status == "oversized":
            return page("<h2>Request unavailable</h2>", 413)
        if g.observation.body_status in {"invalid_json", "invalid_body"}:
            return page("<h2>Request unavailable</h2>", 400)

    @app.after_request
    def record(response):
        if not hasattr(g, "observation"):
            return response
        # Policy runs before handlers; blocked requests still get bounded input
        # redaction, but never an authentication or file-success observation.
        if not g.observation.captured:
            g.observation.capture()
        metadata = g.observation.attributes()
        metadata.update(
            method=request.method, status_code=response.status_code,
            response_class=g.response_class, request_id=g.request_id,
            observation_kind="network_input",
            evidence_role="request",
            session_state="authenticated" if g.session and g.session.authenticated else "anonymous",
        )
        if response.status_code >= 400 and not g.semantic_type:
            metadata["outcome"] = "denied"
        if not g.semantic_type:
            metadata.update(g.semantic_attrs)
        # Existing backend rules deliberately exclude blocked_request. Do not
        # reintroduce blocked traffic into scoring through an HTTP companion.
        observations = [] if g.semantic_type == "blocked_request" else [("http_request", metadata)]
        if g.semantic_type:
            attrs = dict(metadata)
            attrs.update(g.semantic_attrs)
            if "username" in attrs:
                attrs["username"] = g.observation.clean(attrs["username"], 128)
            attrs["observation_kind"] = ("policy_result" if g.semantic_type == "blocked_request" else
                                         "network_input" if g.semantic_type in {"auth_success", "auth_failure"} else "emulated_result")
            attrs["evidence_role"] = ("request" if g.semantic_type in {"auth_success", "auth_failure"} else
                                      "bait" if g.semantic_type == "bait_served" else "result")
            observations.append((g.semantic_type, attrs))
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        rows = []
        for kind, attrs in observations:
            rows.append({
                "schema_version": app.config["WEB_EVENT_SCHEMA_VERSION"], "source_record_id": str(uuid.uuid4()),
                "sensor_id": "web-decoy-01", "event_type": kind, "occurred_at": timestamp,
                "src_ip": g.src_ip or "0.0.0.0", "session_id": g.session.reference if g.session else None,
                "lab_run_id": app.config["LAB_RUN_ID"], "capture_mode": "live", "attributes": attrs,
            })
            try:
                ipaddress.IPv4Address(rows[-1]["src_ip"])
            except (ipaddress.AddressValueError, TypeError):
                rows[-1]["src_ip"] = "0.0.0.0"
        # v1 event types and envelope are preserved; proposed context is inside
        # bounded attributes until M3 coordinates the next shared contract.
        payload = "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows).encode()
        try:
            with lock:
                with open(app.config["LOG_PATH"], "ab") as stream:
                    stream.write(payload)
        except OSError:
            sessions.revoke(g.cookie or request.cookies.get(COOKIE))
            response = page("<h2>Portal temporarily unavailable</h2>", 503)
            app.logger.error("Sensor log write failed; check LOG_PATH permissions")
        else:
            if g.cookie:
                response.set_cookie(COOKIE, g.cookie, max_age=app.config["DECOY_SESSION_TTL"],
                                    httponly=True, samesite="Lax", secure=False, path="/")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
        response.headers["X-Request-ID"] = g.request_id
        return response

    @app.get("/")
    def home():
        return page("<h2>Staff resources</h2><p>Quarterly customer export is ready. Please use the portal login.</p><small>Maintenance ticket #1042 still open.</small>")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page('<h2>Staff login</h2><form method="post"><input name="username" placeholder="Username" maxlength="128"><input name="password" type="password" placeholder="Password"><button>Sign in</button></form>')
        if request.mimetype != "application/x-www-form-urlencoded":
            return page("<h2>Form login required</h2>", 415)
        password, username = request.form.get("password", ""), request.form.get("username", "")
        digest = hashlib.sha256(password.encode()).hexdigest()
        matched = next((token for token in tokens if hmac.compare_digest(token["value_sha256"], digest)), None)
        valid = bool(matched and username == "svc_portal" and matched["username"] == username and matched["valid_on"] == "web-decoy-01")
        replace_session(authenticated=valid)
        semantic("auth_success" if valid else "auth_failure", username=username, password_sha256=digest)
        if matched:
            g.semantic_attrs["honeytoken_id"] = matched["id"]
        if valid:
            return dashboard_page()
        return page("<h2>Invalid credentials</h2>", 401)

    def dashboard_page():
        return page('<h2>Staff dashboard</h2><p>Signed in to the synthetic internal portal.</p><a href="/download?file=customer_data.csv">Download customer export</a><form action="/logout" method="post"><button>Logout</button></form>')

    @app.get("/dashboard")
    def dashboard():
        return protected() or dashboard_page()

    @app.post("/logout")
    def logout():
        replace_session()
        g.semantic_attrs.update(session_transition="logout", observation_kind="emulated_result")
        return page('<h2>Signed out</h2><a href="/login">Sign in</a>')

    @app.route("/search", methods=["GET", "POST"])
    def search():
        if request.method == "POST":
            if request.is_json:
                data = g.observation.json_data
                if not isinstance(data, dict) or not isinstance(data.get("q", ""), str):
                    return page("<h2>Search object required</h2>", 400)
                query = data.get("q", "")
            elif request.mimetype == "application/x-www-form-urlencoded":
                query = request.form.get("q", "")
            else:
                return page("<h2>Form or JSON search required</h2>", 415)
        else:
            query = request.args.get("q", "")
        if SQL_BAIT.search(decode(query)):
            g.response_class = "fake_error"
            return page("<h2>Database error</h2><pre>SQLSTATE[42000]: syntax error near customer_directory. Contact the administrator.</pre>", 500)
        return page('<h2>Search directory</h2><form><input name="q" placeholder="Search"><button>Search</button></form><p>Quarterly report · Customer export · Staff handbook</p>')

    @app.get("/download")
    def download():
        if request.args.get("file") != "customer_data.csv":
            return page("<h2>File not found</h2>", 404)
        denied = protected()
        if denied:
            return denied
        data = ASSET.read_bytes()
        if request.method == "GET":
            g.response_class = "fake_data"
            semantic("synthetic_file_access", asset_id="customer_data.csv", size_bytes=len(data),
                     sha256=hashlib.sha256(data).hexdigest(), outcome="served",
                     fixture_version="1", digest_scope="full_asset", evidence_kind="asset_served")
        return Response(data, mimetype="text/csv", headers={"Content-Disposition": 'attachment; filename="customer_data.csv"'})

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        denied = protected()
        if denied:
            return denied
        if request.method == "GET":
            return page('<h2>Synthetic text report</h2><p>Text only, at most 8 KiB. Content is discarded.</p><form method="post" enctype="multipart/form-data"><input type="file" name="report" accept=".txt,text/plain"><button>Submit</button></form>')
        file = request.files.get("report")
        if file is None or file.mimetype != "text/plain":
            g.semantic_attrs.update(upload_outcome="rejected_type")
            return page("<h2>A plain text report is required</h2>", 415)
        data = file.stream.read(app.config["UPLOAD_FILE_LIMIT"] + 1)
        if len(data) > app.config["UPLOAD_FILE_LIMIT"]:
            g.semantic_attrs.update(upload_outcome="rejected_size")
            return page("<h2>Report too large</h2>", 413)
        try:
            text = data.decode("utf-8")
            if "\x00" in text:
                raise ValueError("binary")
        except (UnicodeDecodeError, ValueError):
            g.semantic_attrs.update(upload_outcome="rejected_encoding")
            return page("<h2>UTF-8 text required</h2>", 415)
        # No uploaded bytes are saved, reflected, executed, unpacked or served.
        g.semantic_attrs.update(upload_outcome="accepted_discarded", asset_id="submitted_text_report",
                                size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                digest_scope="full_asset", observation_kind="emulated_result", evidence_role="result")
        return page("<h2>Report received</h2><p>Lab metadata recorded; content discarded.</p>")

    @app.get("/ping")
    def ping():
        return page("<h2>Connectivity tool</h2><pre>PING files-srv-02 (192.168.77.20): 56 data bytes\n64 bytes: icmp_seq=1 ttl=64 time=0.4 ms\n1 packet transmitted, 1 received</pre>")

    @app.get("/.env")
    def env_bait():
        data = f"APP_ENV=internal\nBACKUP_SSH_USER=backup\nBACKUP_SSH_PASS={BAIT_TOKEN}\n".encode()
        if request.method == "GET":
            kind = "bait_served" if app.config["WEB_EVENT_SCHEMA_VERSION"] == "1.1" else "synthetic_file_access"
            semantic(kind, asset_id="web:/.env", fixture_version="1",
                     honeytoken_ids=["tok_backup_01"], issuance_id="issue_" + uuid.uuid4().hex,
                     evidence_basis="sensor_response",
                     evidence_kind="bait_served", outcome="served", size_bytes=len(data),
                     sha256=hashlib.sha256(data).hexdigest(), digest_scope="full_asset")
        return Response(data, mimetype="text/plain")

    @app.get("/.git/HEAD")
    def git_bait():
        return Response("ref: refs/heads/main\n", mimetype="text/plain")

    @app.get("/admin")
    def admin():
        return page("<h2>Administrator authentication required</h2>", 401)

    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    def canned_error(error):
        return page("<h2>Request unavailable</h2>", error.code)

    return app
