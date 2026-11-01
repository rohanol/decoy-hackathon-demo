"""DeceptionGraph Research Portal: the normal synthetic demo app (source id demo-app-01).

Runtime contract: README.md. Behind gateway-01 only; never a honeypot. It holds no
bait, no honeytokens and no gateway controls. /backup/backup.zip is an ordinary 404
here: only the gateway routes that path, and only to web-decoy-01.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from functools import wraps
from typing import Optional

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

from . import content
from .context import HEADER, verify
from .telemetry import TelemetryWriter, redact_query, redact_text

ROUTE_CLASS_DEFAULT = "page"


def _password_ok(username: str, password: str) -> Optional[dict]:
    account = content.ACCOUNTS.get(username)
    if not account:
        # Same work either way, so timing does not reveal which usernames exist.
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, 120000)
        return None
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(account["salt"]), 120000).hex()
    return account if hmac.compare_digest(digest, account["hash"]) else None


def create_app(config: Optional[dict] = None) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(
        LAB_RUN_ID=os.environ.get("LAB_RUN_ID", "run-01"),
        CAPTURE_MODE=os.environ.get("CAPTURE_MODE", "live"),
        GATEWAY_CONTEXT_KEY=os.environ.get("DG_GATEWAY_CONTEXT_KEY", ""),
        TELEMETRY_PATH=os.environ.get("PORTAL_TELEMETRY_PATH", "state/demo-app/app.jsonl"),
        # Signs the portal's own session cookie. Random per process unless set:
        # a restart signs everyone out, which is fine for a lab.
        SECRET_KEY=os.environ.get("PORTAL_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_NAME="portal_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    app.config.update(config or {})
    writer = TelemetryWriter(app.config["TELEMETRY_PATH"], app.config["LAB_RUN_ID"], app.config["CAPTURE_MODE"])
    app.extensions["portal_telemetry"] = writer

    def route_class(value: str):
        def decorate(view):
            view.route_class = value
            return view
        return decorate

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    @app.before_request
    def gateway_context():
        g.context = verify(request.headers.get(HEADER), app.config["GATEWAY_CONTEXT_KEY"], app.config["LAB_RUN_ID"])
        g.login = None

    @app.after_request
    def record(response):
        if request.path == "/readyz":
            return response  # readiness probes are not participant traffic
        view = app.view_functions.get(request.endpoint) if request.endpoint else None
        if response.status_code == 404:
            cls = "not_found"
        elif response.status_code >= 500:
            cls = "error"
        elif request.endpoint == "static":
            cls = "static"
        else:
            cls = getattr(view, "route_class", ROUTE_CLASS_DEFAULT)
        ctx = g.get("context")
        attributes = {
            "app_request_id": "app-req-" + secrets.token_hex(6),
            "gateway_context": ctx.status if ctx else "absent",
            # Only a verified context may name the client; otherwise the TCP peer.
            "src_ip": ctx.client_ip if ctx and ctx.status == "verified" else (request.remote_addr or "0.0.0.0"),
            "method": request.method[:16],
            # Path only, redacted; '?' and '#' re-escaped so it stays a path.
            "path": redact_text(request.path, 2040).replace("?", "%3F").replace("#", "%23")
            if request.path.startswith("/") else "/",
            "status_code": response.status_code,
            "route_class": cls,
        }
        if request.args:
            attributes["query_redacted"] = redact_query(request.args.items(multi=True))
        if ctx and ctx.status == "verified":
            attributes["gateway_request_id"] = ctx.gateway_request_id
            attributes["gateway_session_ref"] = ctx.gateway_session_ref
        elif ctx and ctx.status == "invalid":
            attributes["invalid_reason"] = ctx.invalid_reason
        if g.get("login"):
            attributes["login"] = g.login
        writer.app_request(attributes)
        return response

    @app.context_processor
    def globals_for_templates():
        return {"org": content.ORG, "user": session.get("user")}

    @app.get("/readyz")
    @route_class("api")
    def readyz():
        return jsonify({"ok": True, "source_id": "demo-app-01", "lab_run_id": app.config["LAB_RUN_ID"]})

    @app.get("/")
    def home():
        return render_template("home.html", announcements=content.ANNOUNCEMENTS, reports=content.REPORTS[:3])

    @app.route("/login", methods=["GET", "POST"])
    @route_class("login")
    def login():
        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip().lower()[:64]
            password = request.form.get("password") or ""
            account = _password_ok(username, password)
            g.login = {"username": redact_text(username, 64), "outcome": "emulated_success" if account else "failed"}
            if account:
                session.clear()
                session["user"] = {"email": username, "name": account["name"], "role": account["role"]}
                target = request.args.get("next") or "/dashboard"
                return redirect(target if target.startswith("/") and not target.startswith("//") else "/dashboard")
            error = "The email or password is incorrect."
        return render_template("login.html", error=error), (401 if error else 200)

    @app.post("/logout")
    @route_class("login")
    def logout():
        session.clear()
        return redirect("/")

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", tasks=content.TASKS, reports=content.REPORTS, datasets=content.DATASETS)

    @app.get("/search")
    def search():
        query = (request.args.get("q") or "")[:200]
        return render_template("search.html", query=query, results=content.search(query))

    @app.get("/reports")
    def reports():
        return render_template("reports.html", reports=content.REPORTS)

    @app.get("/reports/<slug>")
    def report(slug: str):
        found = next((item for item in content.REPORTS if item["slug"] == slug), None)
        if not found:
            return render_template("not_found.html"), 404
        return render_template("report.html", report=found)

    @app.get("/resources")
    def resources():
        return render_template("resources.html", datasets=content.DATASETS)

    @app.errorhandler(404)
    @app.errorhandler(405)
    def not_found(_error):
        return render_template("not_found.html"), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("not_found.html"), 413

    return app
