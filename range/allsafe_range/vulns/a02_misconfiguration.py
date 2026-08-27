"""
A02 — Security Misconfiguration
===============================
CWE-1392  Use of Default Credentials
CWE-209   Generation of Error Message Containing Sensitive Information
CWE-497   Exposure of Sensitive System Information to an Unauthorized Sphere
CWE-548   Exposure of Information Through Directory Listing

WHAT IS WRONG HERE
------------------
1. /a02/admin is an administrative panel whose credentials are admin/admin and
   have never been changed. It also advertises them on the login page, which is
   less realistic but makes the module self-teaching.
2. /a02/crash raises an unhandled exception; the global error handler renders
   the full traceback to the client (see templates/error.html).
3. /a02/files/ is an open directory index over a folder containing exactly the
   sort of thing that gets left behind — a .env, a SQL dump, a key backup.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
Werkzeug's interactive debugger is never switched on. The traceback is text.
File serving goes through send_from_directory, so this module demonstrates
directory listing, not path traversal.
"""

import os

from flask import (Blueprint, abort, render_template, request, send_from_directory,
                   session)

from ._common import event

bp = Blueprint("a02", __name__, url_prefix="/a02")

META = {
    "owasp": "A02:2025 Security Misconfiguration",
    "cwe": ["CWE-1392", "CWE-209", "CWE-497", "CWE-548"],
    "summary": "Admin panel on default credentials, tracebacks rendered to the client, and an open directory index.",
    "endpoints": ["/a02/admin", "/a02/crash", "/a02/files/"],
}

# VULNERABLE — CWE-1392. Shipped defaults, never rotated.
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"

FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "sample_files")


@bp.route("/")
def home():
    return render_template("a02.html", meta=META)


@bp.route("/admin", methods=["GET", "POST"])
def admin():
    """VULNERABLE — CWE-1392. Default credentials, and they still work."""
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEFAULT_ADMIN_USER and password == DEFAULT_ADMIN_PASS:
            session["a02_admin"] = True
            event("critical", "default_credential_login_success",
                  username=username, panel="a02_admin")
        else:
            error = "Invalid credentials."
            # Failed admin logins ARE logged here. Contrast with A09.
            event("warning", "admin_login_failed", username=username,
                  panel="a02_admin")

    if session.get("a02_admin"):
        env_dump = {
            key: value for key, value in sorted(os.environ.items())
            if key.startswith(("RANGE_", "FLASK_", "PATH", "HOSTNAME", "PWD", "USER"))
        }
        return render_template("a02_admin.html", meta=META, env=env_dump)

    return render_template("a02_admin_login.html", meta=META, error=error,
                           default_user=DEFAULT_ADMIN_USER,
                           default_pass=DEFAULT_ADMIN_PASS)


@bp.route("/admin/logout")
def admin_logout():
    session.pop("a02_admin", None)
    event("info", "admin_logout", panel="a02_admin")
    return render_template("a02_admin_login.html", meta=META, error=None,
                           default_user=DEFAULT_ADMIN_USER,
                           default_pass=DEFAULT_ADMIN_PASS)


@bp.route("/crash")
def crash():
    """
    VULNERABLE — CWE-209 / CWE-497.
    Raises on purpose. The app-wide 500 handler renders the traceback, exposing
    file paths, framework versions, and local variable names in the frames.
    """
    divisor = request.args.get("divisor", "0")
    event("warning", "deliberate_exception_requested", divisor=divisor)
    connection_string = "postgres://range_app:Sup3rSecret-Staging!@db.internal:5432/range"  # noqa: F841
    return str(100 / int(divisor))


@bp.route("/files/")
def files_index():
    """VULNERABLE — CWE-548. An open index over a folder of leftovers."""
    try:
        names = sorted(os.listdir(FILES_DIR))
    except OSError:
        names = []
    entries = []
    for name in names:
        full = os.path.join(FILES_DIR, name)
        entries.append({"name": name, "size": os.path.getsize(full)})
    event("warning", "directory_listing_served", entry_count=len(entries),
          directory="sample_files")
    return render_template("a02_files.html", meta=META, entries=entries)


@bp.route("/files/<path:name>")
def files_get(name):
    """
    Serves a listed file. send_from_directory refuses paths that escape the
    folder — this module is about the listing being on, not about traversal.
    """
    target = os.path.join(FILES_DIR, name)
    if not os.path.isfile(target):
        event("info", "file_fetch_miss", requested=name)
        abort(404)
    event("warning", "sensitive_file_served", requested=name,
          size_bytes=os.path.getsize(target))
    return send_from_directory(FILES_DIR, name, mimetype="text/plain",
                               as_attachment=False)
