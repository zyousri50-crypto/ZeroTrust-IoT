from datetime import timedelta, datetime, timezone
from pathlib import Path
from secrets import compare_digest, token_urlsafe

from flask import (
    jsonify, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash

INSTANCE_DIR = Path(__file__).resolve().parent / "instance"
SECRET_FILE = INSTANCE_DIR / "secret_key"
PASSWORD_FILE = INSTANCE_DIR / "admin_password.hash"

def configure_security(app):
    if not SECRET_FILE.is_file():
        raise RuntimeError("Missing dashboard/instance/secret_key")
    if not PASSWORD_FILE.is_file():
        raise RuntimeError("Missing dashboard/instance/admin_password.hash")

    app.config.update(
        SECRET_KEY=SECRET_FILE.read_text(encoding="utf-8").strip(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )
    # Secure=False is only for local HTTP on 127.0.0.1.
    # HTTPS deployment must use Secure=True.

    @app.before_request
    def protect_requests():
        endpoint = request.endpoint
        if endpoint == "static":
            return None

        if endpoint == "login":
            if request.method == "POST":
                expected = session.get("login_csrf_token", "")
                supplied = request.form.get("csrf_token", "")
                if not expected or not compare_digest(expected, supplied):
                    return jsonify({
                        "success": False, "error": "Invalid CSRF token"
                    }), 403
            return None

        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False, "error": "Authentication required"
                }), 401
            return redirect(url_for("login"))

        now = datetime.now(timezone.utc).timestamp()
        last_active = session.get("last_active", now)
        if now - last_active > 1800:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False, "error": "Session expired"
                }), 401
            return redirect(url_for("login"))

        session["last_active"] = now
        session.permanent = True
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected = session.get("csrf_token", "")
            supplied = request.headers.get("X-CSRF-Token", "")
            if not expected or not compare_digest(expected, supplied):
                return jsonify({
                    "success": False, "error": "Invalid CSRF token"
                }), 403
        return None

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path in ("/", "/login") or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if session.get("authenticated"):
                return redirect(url_for("home"))
            csrf_token = token_urlsafe(32)
            session["login_csrf_token"] = csrf_token
            return render_template("login.html", error=None, csrf_token=csrf_token)

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = PASSWORD_FILE.read_text(encoding="utf-8").strip()
        if username != "admin" or not check_password_hash(password_hash, password):
            return render_template(
                "login.html",
                error="Invalid username or password",
                csrf_token=session.get("login_csrf_token", ""),
            ), 401

        session.clear()
        session["authenticated"] = True
        session["csrf_token"] = token_urlsafe(32)
        session["last_active"] = datetime.now(timezone.utc).timestamp()
        session.permanent = True
        return redirect(url_for("home"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/api/auth/session")
    def auth_session():
        return jsonify({
            "authenticated": True,
            "username": "admin",
            "csrf_token": session["csrf_token"]
        })
