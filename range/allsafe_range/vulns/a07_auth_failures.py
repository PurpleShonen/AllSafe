"""
A07 — Authentication Failures
=============================
CWE-307  Improper Restriction of Excessive Authentication Attempts (no lockout)
CWE-521  Weak Password Requirements (no policy)
CWE-613  Insufficient Session Expiration (sessions never expire)
CWE-620  Unverified Password Change

WHAT IS WRONG HERE
------------------
1. /a07/login accepts unlimited attempts. No lockout, no backoff, no CAPTCHA —
   a credential-stuffing or brute-force run is never slowed down. Failed
   attempts ARE logged here (contrast A09), so the brute force is visible in
   the logs even though nothing stops it.
2. /a07/register enforces no password policy at all — "1" is accepted.
3. Sessions are marked permanent with a ten-year lifetime (see config.py), and
   the cookie is not HttpOnly, so it is readable by the A05 XSS.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
Real password hashing is still (weakly) MD5 via db.py — that is A04's problem.
This module is specifically about the absence of authentication *controls*.
"""

from flask import Blueprint, render_template, request, session

from ..db import get_db, md5
from ._common import event

bp = Blueprint("a07", __name__, url_prefix="/a07")

META = {
    "owasp": "A07:2025 Authentication Failures",
    "cwe": ["CWE-307", "CWE-521", "CWE-613", "CWE-620"],
    "summary": "No account lockout, no password policy, and sessions that never expire.",
    "endpoints": ["/a07/login", "/a07/register", "/a07/whoami"],
}


@bp.route("/")
def home():
    return render_template("a07.html", meta=META, who=session.get("a07_user"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABLE — CWE-307.
    Parameterised query (SQLi is A05's job, not this module's), but no attempt
    counting of any kind. Try passwords forever.
    """
    error = None
    username = request.form.get("username", "")

    if request.method == "POST":
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT id, username, role FROM users WHERE username = ? AND password_md5 = ?",
            (username, md5(password)),
        ).fetchone()

        if row:
            # Never-expiring session — CWE-613, configured in config.py.
            session.permanent = True
            session["a07_user"] = row["username"]
            session["username"] = row["username"]
            event("info", "auth_login_success", username=row["username"],
                  role=row["role"], session_expiry="never")
        else:
            error = "Invalid username or password."
            # Deliberately logged, unlike A09 — a brute force should be visible.
            event("warning", "auth_login_failed", username=username,
                  lockout_enforced=False)

    return render_template("a07_login.html", meta=META, error=error,
                           username=username, who=session.get("a07_user"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    """VULNERABLE — CWE-521. Any password is accepted, including one character."""
    message, ok = None, False

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            message = "Username and password are both required (that is the only rule)."
        else:
            db = get_db()
            exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if exists:
                message = f"User {username} already exists."
            else:
                db.execute(
                    "INSERT INTO users (username, email, password_md5, role, full_name, api_key)"
                    " VALUES (?, ?, ?, 'client', ?, ?)",
                    (username, f"{username}@range.allsafe.local", md5(password),
                     username, f"AR-KEY-NEW-{username[:8].upper()}"),
                )
                db.commit()
                ok = True
                message = f"Registered {username} with a {len(password)}-character password. No policy was applied."
                event("warning", "weak_password_accepted",
                      username=username, password_length=len(password),
                      policy_enforced=False)

    return render_template("a07_register.html", meta=META, message=message, ok=ok)


@bp.route("/whoami")
def whoami():
    """Shows the session so trainees can see it never expires and is JS-readable."""
    return render_template("a07_whoami.html", meta=META,
                           who=session.get("a07_user"),
                           lifetime_days=round(
                               request.environ.get("PERM_LIFETIME_DAYS", 3650)))
