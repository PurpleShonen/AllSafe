"""
A05 — Injection
===============
CWE-89   SQL Injection
CWE-79   Cross-site Scripting (both reflected and stored)

WHAT IS WRONG HERE
------------------
1. /a05/search builds a SQL statement by string concatenation. The search term
   goes straight into the WHERE clause. Classic UNION-based extraction and
   boolean/`OR 1=1` bypasses both work.
2. /a05/login authenticates with the same concatenated-SQL pattern, so
   `' OR '1'='1' -- ` logs you in as the first user.
3. /a05/greet reflects a `name` parameter into the page without escaping
   (reflected XSS).
4. /a05/feedback stores messages and renders them with |safe, so a stored
   payload fires for the next visitor (stored XSS).

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
The XSS runs in the victim's browser only. There is no server-side template
injection here and no code execution on the host.
"""

from flask import Blueprint, render_template, request
from markupsafe import Markup

from ..db import get_db
from ._common import event, suspicious

bp = Blueprint("a05", __name__, url_prefix="/a05")

META = {
    "owasp": "A05:2025 Injection",
    "cwe": ["CWE-89", "CWE-79"],
    "summary": "String-concatenated SQL in search and login, plus reflected and stored XSS.",
    "endpoints": ["/a05/search", "/a05/login", "/a05/greet", "/a05/feedback"],
}


@bp.route("/")
def home():
    return render_template("a05.html", meta=META)


@bp.route("/search")
def search():
    """
    VULNERABLE — CWE-89.
    The query is assembled with an f-string. The parameterised version is one
    line away and commented below; that contrast is the teaching point.
    """
    term = request.args.get("q", "")
    rows, error, executed = [], None, None

    if term:
        # ---- The bug -------------------------------------------------------
        sql = ("SELECT id, client_name, contract_ref, monthly_value "
               f"FROM accounts WHERE client_name LIKE '%{term}%'")
        executed = sql
        # ---- The fix would be -----------------------------------------------
        # sql = "SELECT ... WHERE client_name LIKE ?"
        # rows = db.execute(sql, (f"%{term}%",)).fetchall()

        tags = suspicious(term)
        event("warning" if tags else "info", "account_search",
              term=term, sql=sql, suspected=tags or None)

        try:
            # executescript-style multi-statement is left off; a single query is
            # enough for UNION extraction and keeps accidental writes out.
            rows = get_db().execute(sql).fetchall()
        except Exception as exc:  # noqa: BLE001 — surfacing the DB error is A05+A02
            error = f"{type(exc).__name__}: {exc}"
            event("warning", "sql_error", term=term, sql=sql, detail=str(exc)[:300])

    return render_template("a05_search.html", meta=META, term=term, rows=rows,
                           error=error, executed=executed)


@bp.route("/login", methods=["GET", "POST"])
def login():
    """VULNERABLE — CWE-89 in an auth context. `' OR '1'='1' -- ` bypasses it."""
    result, executed = None, None
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if request.method == "POST":
        sql = ("SELECT id, username, role FROM users "
               f"WHERE username = '{username}' AND password_md5 = '{_md5_inline(password)}'")
        executed = sql
        tags = suspicious(username, password)
        event("warning" if tags else "info", "sql_login_attempt",
              username=username, sql=sql, suspected=tags or None)
        try:
            row = get_db().execute(sql).fetchone()
            if row:
                result = dict(row)
                event("critical", "sql_login_success",
                      username=username, matched_user=row["username"],
                      matched_role=row["role"], via="sql_injection" if tags else "credentials")
            else:
                event("info", "sql_login_denied", username=username)
        except Exception as exc:  # noqa: BLE001
            executed = f"{sql}\n\n-- {type(exc).__name__}: {exc}"

    return render_template("a05_login.html", meta=META, result=result,
                           executed=executed, username=username)


def _md5_inline(value: str) -> str:
    """
    md5 of the supplied password, injected into the SQL string unquoted-safe.
    Kept tiny so the injection point stays in the username field where it is
    easiest to demonstrate.
    """
    import hashlib
    return hashlib.md5(value.encode("utf-8")).hexdigest()


@bp.route("/greet")
def greet():
    """VULNERABLE — CWE-79 reflected. `name` is echoed without escaping."""
    name = request.args.get("name", "")
    tags = suspicious(name)
    if tags:
        event("warning", "reflected_xss_payload", name=name, suspected=tags)
    # Markup() suppresses auto-escaping on purpose. Never do this with input.
    reflected = Markup(name) if name else Markup("")
    return render_template("a05_greet.html", meta=META, reflected=reflected, raw=name)


@bp.route("/feedback", methods=["GET", "POST"])
def feedback():
    """VULNERABLE — CWE-79 stored. Messages render with |safe for later visitors."""
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous")[:80]
        message = request.form.get("message", "")
        db.execute("INSERT INTO feedback (author, message) VALUES (?, ?)",
                   (author, message))
        db.commit()
        tags = suspicious(author, message)
        event("warning" if tags else "info", "feedback_stored",
              author=author, length=len(message), suspected=tags or None)

    rows = db.execute(
        "SELECT author, message, created_at FROM feedback ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return render_template("a05_feedback.html", meta=META, rows=rows)
