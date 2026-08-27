"""
A04 — Cryptographic Failures
============================
CWE-916  Use of Password Hash With Insufficient Computational Effort
CWE-759  Use of a One-Way Hash Without a Salt
CWE-798  Use of Hard-coded Credentials (the app's signing key)
CWE-330  Use of Insufficiently Random Values (the reset token)
CWE-319  Cleartext Transmission of Sensitive Information

WHAT IS WRONG HERE
------------------
1. Passwords are stored as unsalted MD5 (see db.py). /a04/export hands the
   whole table over, so the hashes can be cracked offline in seconds.
2. Password reset tokens are md5(email + current minute). Anyone who knows a
   user's email can compute the token themselves.
3. The reset link is issued over plain HTTP and the token is echoed in the
   response body and the query string — so it lands in every proxy log on the
   path (CWE-319).
4. The Flask signing key is hardcoded in config.py, so session cookies can be
   forged by anyone with the source.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
Nothing here is executed. The module hands out hashes and tokens; cracking them
happens on the trainee's own machine.
"""

import hashlib
import time

from flask import Blueprint, current_app, jsonify, render_template, request

from ..db import get_db, md5
from ._common import event

bp = Blueprint("a04", __name__, url_prefix="/a04")

META = {
    "owasp": "A04:2025 Cryptographic Failures",
    "cwe": ["CWE-916", "CWE-759", "CWE-798", "CWE-330", "CWE-319"],
    "summary": "Unsalted MD5 password storage, a predictable reset token sent in the clear, and a hardcoded signing key.",
    "endpoints": ["/a04/export", "/a04/reset", "/a04/reset/confirm"],
}


def weak_token(email: str) -> str:
    """
    VULNERABLE — CWE-330.
    Two inputs, both knowable: the target's email and the current minute. There
    is no secret and no entropy. A correct implementation uses
    secrets.token_urlsafe(32) and stores a hash of it with a short expiry.
    """
    minute = int(time.time() // 60)
    return hashlib.md5(f"{email}:{minute}".encode("utf-8")).hexdigest()


@bp.route("/")
def home():
    return render_template("a04.html", meta=META,
                           secret_key=current_app.config["SECRET_KEY"])


@bp.route("/export")
def export():
    """
    VULNERABLE — CWE-916 / CWE-759.
    A "user export" that includes the password column. Unsalted MD5 means every
    row falls to a wordlist, and identical passwords produce identical hashes.
    """
    rows = get_db().execute(
        "SELECT id, username, email, role, password_md5, api_key FROM users"
    ).fetchall()
    event("critical", "credential_material_exported",
          rows=len(rows), algorithm="md5-unsalted", endpoint="/a04/export")
    return jsonify({
        "note": "Unsalted MD5. Identical passwords produce identical hashes.",
        "users": [dict(row) for row in rows],
    })


@bp.route("/reset", methods=["GET", "POST"])
def reset():
    """
    VULNERABLE — CWE-330 / CWE-319.
    Issues a predictable token and returns it in the response instead of
    emailing it. Over HTTP, that token is visible to anything on the path.
    """
    token = None
    email = (request.values.get("email") or "").strip()
    error = None

    if email:
        db = get_db()
        user = db.execute(
            "SELECT id, username FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user is None:
            # Note the disclosure: the app tells you whether the address exists.
            error = f"No account for {email}."
            event("info", "password_reset_unknown_email", email=email)
        else:
            token = weak_token(email)
            db.execute(
                "INSERT OR REPLACE INTO reset_tokens (token, user_id, used) VALUES (?, ?, 0)",
                (token, user["id"]),
            )
            db.commit()
            event("warning", "password_reset_token_issued",
                  email=email, user_id=user["id"], token=token,
                  transport="http-plaintext", token_scheme="md5(email+minute)")

    return render_template("a04_reset.html", meta=META, token=token,
                           email=email, error=error, scheme_hint="md5(email + unix_minute)")


@bp.route("/reset/confirm", methods=["GET", "POST"])
def reset_confirm():
    """
    VULNERABLE — the token is the only thing checked, and it is guessable.
    No rate limit, no single-use enforcement worth the name, no re-auth.
    """
    token = (request.values.get("token") or "").strip()
    new_password = request.values.get("new_password") or ""
    message = None
    ok = False

    if token and new_password:
        db = get_db()
        row = db.execute(
            "SELECT user_id FROM reset_tokens WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            message = "Unknown or expired token."
            event("warning", "password_reset_bad_token", token=token)
        else:
            db.execute("UPDATE users SET password_md5 = ? WHERE id = ?",
                       (md5(new_password), row["user_id"]))
            db.execute("UPDATE reset_tokens SET used = 1 WHERE token = ?", (token,))
            db.commit()
            ok = True
            message = f"Password for user id {row['user_id']} has been changed."
            event("critical", "password_reset_completed",
                  user_id=row["user_id"], token=token,
                  hash_algorithm="md5-unsalted")

    return render_template("a04_reset_confirm.html", meta=META, token=token,
                           message=message, ok=ok)
