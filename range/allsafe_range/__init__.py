"""
Allsafe Range — application factory
===================================
!! INTENTIONALLY VULNERABLE SOFTWARE. See README-WARNING.md before running. !!

This package wires together the plumbing (logging, storage, request hooks) and
mounts one blueprint per OWASP Top 10:2025 category. The plumbing itself is NOT
vulnerable — every deliberate weakness lives in allsafe_range/vulns/.
"""

import time
import traceback
import uuid

from flask import Flask, g, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

from . import db, logging_setup
from .config import Config

MODULES = [
    # key,   title,                                       blueprint module
    ("a01", "Broken Access Control",                      "a01_access_control"),
    ("a02", "Security Misconfiguration",                  "a02_misconfiguration"),
    ("a03", "Software Supply Chain Failures",             "a03_supply_chain"),
    ("a04", "Cryptographic Failures",                     "a04_crypto"),
    ("a05", "Injection",                                  "a05_injection"),
    ("a06", "Insecure Design",                            "a06_insecure_design"),
    ("a07", "Authentication Failures",                    "a07_auth_failures"),
    ("a08", "Software or Data Integrity Failures",        "a08_integrity"),
    ("a09", "Security Logging & Alerting Failures",       "a09_logging_failures"),
    ("a10", "Mishandling of Exceptional Conditions",      "a10_exceptional"),
]


def client_ip(req, trust_proxy: bool) -> str:
    """Source address, taking the left-most XFF hop when behind Apache."""
    if trust_proxy:
        forwarded = req.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real = req.headers.get("X-Real-IP")
        if real:
            return real.strip()
    return req.remote_addr or "-"


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    logging_setup.configure(app)
    app.teardown_appcontext(db.close_db)

    enabled = {k: v for k, v in app.config["MODULES"].items() if v}

    # ---------------------------------------------------------- blueprints --
    from importlib import import_module

    registered = []
    for key, title, module_name in MODULES:
        if not app.config["MODULES"].get(key):
            continue
        mod = import_module(f".vulns.{module_name}", __package__)
        app.register_blueprint(mod.bp)
        registered.append({"key": key, "title": title, "meta": mod.META})
    app.extensions["range_modules"] = registered

    logging_setup.app_event(
        app, "info", "startup",
        version=app.config["APP_VERSION"],
        modules_enabled=sorted(enabled),
        log_dir=app.config["LOG_DIR"],
        db_path=app.config["DB_PATH"],
    )

    # ------------------------------------------------------ request hooks --
    @app.before_request
    def _start_timer():
        g.started = time.perf_counter()
        # Correlation id so an app.log event can be tied to its access.log line.
        g.request_id = uuid.uuid4().hex[:16]

    @app.after_request
    def _access_log(response):
        """
        REQUIREMENT: every request is logged, no exceptions. Modules never get
        to opt out of this. The A09 blind spot is an app.log gap, not an
        access.log gap — see vulns/a09_logging_failures.py.
        """
        redact = app.config["REDACT_SECRETS"]
        duration = (time.perf_counter() - getattr(g, "started", time.perf_counter())) * 1000

        args = logging_setup.scrub(request.args, redact)
        form = logging_setup.scrub(request.form, redact) if request.form else {}

        record = {
            "request_id": getattr(g, "request_id", "-"),
            "src_ip": client_ip(request, app.config["TRUST_PROXY_HEADERS"]),
            "remote_addr": request.remote_addr or "-",
            "forwarded_for": request.headers.get("X-Forwarded-For", ""),
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string.decode("utf-8", "replace")[:1024],
            "args": args,
            "form": form,
            "status": response.status_code,
            "bytes": response.calculate_content_length() or 0,
            "duration_ms": round(duration, 2),
            "user_agent": request.headers.get("User-Agent", "-"),
            "referer": request.headers.get("Referer", ""),
            "host": request.headers.get("Host", ""),
            "module": request.blueprint or "core",
            "session_user": session.get("username"),
        }

        hits = logging_setup.suspicious(record["query_string"], form, request.path)
        if hits:
            record["suspected"] = hits

        app.extensions["range_access_log"].info(
            "http_request", extra={"event": "http_request", "fields": record}
        )
        return response

    # ------------------------------------------------------ error handling --
    @app.errorhandler(Exception)
    def _unhandled(exc):
        """
        Unhandled exceptions are always logged with the full traceback. Whether
        the traceback is also SHOWN to the client is A02's business, not this
        handler's — see vulns/a02_misconfiguration.py.

        HTTP errors (404, 405, ...) are deliberate control flow, not crashes —
        let Werkzeug render them normally rather than dressing them as a 500.
        """
        if isinstance(exc, HTTPException):
            return exc
        tb = traceback.format_exc()
        logging_setup.app_event(
            app, "error", "unhandled_exception",
            request_id=getattr(g, "request_id", "-"),
            src_ip=client_ip(request, app.config["TRUST_PROXY_HEADERS"]),
            path=request.path,
            method=request.method,
            exception=type(exc).__name__,
            detail=str(exc)[:500],
            traceback=tb[-4000:],
        )
        if request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json":
            return jsonify(error="internal_error", detail=str(exc)), 500
        return render_template("error.html", exc=exc, traceback_text=tb), 500

    # -------------------------------------------------------------- routes --
    @app.route("/")
    def index():
        return render_template(
            "index.html",
            modules=app.extensions["range_modules"],
            all_modules=MODULES,
            enabled=app.config["MODULES"],
            version=app.config["APP_VERSION"],
        )

    @app.route("/healthz")
    def healthz():
        return jsonify(status="ok", version=app.config["APP_VERSION"],
                       modules=sorted(enabled))

    @app.cli.command("init-db")
    def init_db_command():
        """Drop and rebuild the SQLite database with fresh seed data."""
        db.init_db(app.config["DB_PATH"])
        print(f"[allsafe-range] database rebuilt at {app.config['DB_PATH']}")

    return app
