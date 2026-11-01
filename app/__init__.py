"""Cloud hygiene and compliance scanner: reads an AWS account and reports what needs attention."""
import hmac
import logging
import os
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, session, url_for

from .checks import CATEGORIES, SEVERITIES
from .scanner import ScanStore, run_scan

PUBLIC_ENDPOINTS = {"health", "version", "static"}


def create_app(scan_fn=None, config=None) -> Flask:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", ""),
        SCANNER_USER=os.environ.get("SCANNER_USER", "admin"),
        SCANNER_PASSWORD=os.environ.get("SCANNER_PASSWORD", ""),
        SCANNER_AUTH=os.environ.get("SCANNER_AUTH", "on"),
        APP_COMMIT=os.environ.get("APP_COMMIT", "dev"),
        APP_BUILD_TIME=os.environ.get("APP_BUILD_TIME", "unknown"),
        DISPLAY_UTC_OFFSET=float(os.environ.get("DISPLAY_UTC_OFFSET", "3")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    )
    if config:
        app.config.update(config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY is not set")
    if app.config["SCANNER_AUTH"] != "off" and not app.config["SCANNER_PASSWORD"]:
        raise RuntimeError("SCANNER_PASSWORD is not set (use SCANNER_AUTH=off only for a local demo)")

    store = ScanStore()
    app.extensions["scan_store"] = store
    scan = scan_fn or run_scan

    # ---------------------------------------------------------------- helpers
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    @app.template_filter("localtime")
    def localtime(value: str) -> str:
        if not value:
            return "-"
        offset = timezone(timedelta(hours=app.config["DISPLAY_UTC_OFFSET"]))
        return datetime.fromisoformat(value).astimezone(offset).strftime("%d %b %Y %H:%M")

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token, "commit": app.config["APP_COMMIT"][:8],
                "build_time": app.config["APP_BUILD_TIME"]}

    # ---------------------------------------------------------------- access control
    @app.before_request
    def require_login():
        if request.endpoint in PUBLIC_ENDPOINTS or app.config["SCANNER_AUTH"] == "off":
            return None
        auth = request.authorization
        expected_user = app.config["SCANNER_USER"].encode()
        expected_password = app.config["SCANNER_PASSWORD"].encode()
        if (auth and auth.type == "basic"
                and hmac.compare_digest((auth.username or "").encode(), expected_user)
                and hmac.compare_digest((auth.password or "").encode(), expected_password)):
            return None
        return Response("Sign in required.", 401, {"WWW-Authenticate": 'Basic realm="Cloud hygiene scanner"'})

    @app.after_request
    def headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---------------------------------------------------------------- public routes
    @app.route("/health")
    def health():
        return "OK", 200

    @app.route("/version")
    def version():
        return jsonify(commit=app.config["APP_COMMIT"], built=app.config["APP_BUILD_TIME"])

    # ---------------------------------------------------------------- the dashboard
    @app.route("/")
    def dashboard():
        result = store.latest()
        severity = request.args.get("severity", "")
        category = request.args.get("category", "")
        findings = result.findings if result else []
        by_severity = Counter(f.severity for f in findings)
        by_category = Counter(f.category for f in findings)
        shown = [f for f in findings
                 if (severity not in SEVERITIES or f.severity == severity)
                 and (category not in CATEGORIES or f.category == category)]
        return render_template(
            "dashboard.html", result=result, findings=shown, total=len(findings),
            by_severity=by_severity, by_category=by_category, severities=SEVERITIES, categories=CATEGORIES,
            severity=severity if severity in SEVERITIES else "",
            category=category if category in CATEGORIES else "",
        )

    @app.route("/scan", methods=["POST"])
    def run_now():
        sent = request.form.get("csrf_token", "").encode()
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "").encode()):
            abort(400)
        store.save(scan())
        return redirect(url_for("dashboard"))

    @app.route("/api/findings")
    def api_findings():
        result = store.latest()
        if result is None:
            return jsonify(scan=None, findings=[]), 200
        return jsonify(result.to_dict())

    @app.errorhandler(400)
    def bad_request(_error):
        return Response("The request could not be verified. Go back, reload the page and try again.", 400)

    return app
