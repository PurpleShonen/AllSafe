"""
A01 — Broken Access Control
===========================
CWE-639  Authorization Bypass Through User-Controlled Key (IDOR)
CWE-284  Improper Access Control (client-supplied role)
CWE-918  Server-Side Request Forgery (SSRF now sits under A01 in the 2025 list)

WHAT IS WRONG HERE
------------------
1. /a01/account reads an account id straight out of the query string and
   returns whatever row matches. Ownership is never checked.
2. /a01/reports trusts a `role` query parameter to decide what the caller may
   see. The client asserts its own privilege level.
3. /a01/fetch retrieves any URL the caller supplies, with no allow-list, no
   scheme restriction, and no destination checks.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
The response body is never executed or evaluated. /a01/fetch reads bytes and
shows them; it does not follow anything into a shell.
"""

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

from flask import Blueprint, current_app, render_template, request, session

from ..db import get_db
from ._common import event

bp = Blueprint("a01", __name__, url_prefix="/a01")

META = {
    "owasp": "A01:2025 Broken Access Control",
    "cwe": ["CWE-639", "CWE-284", "CWE-918"],
    "summary": "IDOR on account records, a client-supplied role parameter, and an unrestricted URL fetcher.",
    "endpoints": ["/a01/account?id=", "/a01/reports?role=", "/a01/fetch?url="],
}

# Link-local metadata addresses. See Config.SSRF_ALLOW_METADATA for why this one
# narrow exception exists in an otherwise unrestricted fetcher.
_METADATA_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fd00:ec2::/32"),
]


@bp.route("/")
def home():
    # There is no login here. The "session" is whatever id we hand out, which
    # is itself part of the lesson: the app has no idea who you are.
    session.setdefault("user_id", 2)
    session.setdefault("username", "j.ellis")
    db = get_db()
    mine = db.execute(
        "SELECT * FROM accounts WHERE owner_user_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("a01.html", meta=META, mine=mine,
                           me=session.get("username"), my_id=session.get("user_id"))


@bp.route("/account")
def account():
    """
    VULNERABLE — CWE-639.
    The id comes from the caller. No check that the row belongs to them.
    A fixed version would read the owner from the session and filter on it:
        WHERE id = ? AND owner_user_id = ?
    """
    account_id = request.args.get("id", "")
    db = get_db()
    row = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()

    if row is None:
        event("info", "idor_lookup_miss", account_id=account_id)
        return render_template("a01_account.html", meta=META, row=None,
                               account_id=account_id), 404

    # This is the line a detection engineer cares about: the requested owner
    # versus the session owner. The app logs the mismatch but does not act on it.
    owner_mismatch = str(row["owner_user_id"]) != str(session.get("user_id"))
    event(
        "warning" if owner_mismatch else "info",
        "account_access",
        account_id=account_id,
        record_owner=row["owner_user_id"],
        session_user_id=session.get("user_id"),
        cross_tenant=owner_mismatch,
    )
    return render_template("a01_account.html", meta=META, row=row,
                           account_id=account_id, mismatch=owner_mismatch)


@bp.route("/reports")
def reports():
    """
    VULNERABLE — CWE-284.
    Privilege is taken from a query parameter. ?role=admin returns everything,
    classification markings included.
    """
    role = request.args.get("role", "client")
    db = get_db()

    if role in ("admin", "analyst"):
        rows = db.execute("SELECT * FROM reports").fetchall()
        event("warning", "privileged_view_via_parameter", claimed_role=role,
              session_user_id=session.get("user_id"), rows_returned=len(rows))
    else:
        rows = db.execute(
            "SELECT * FROM reports WHERE owner_user_id = ?",
            (session.get("user_id", 2),),
        ).fetchall()
        event("info", "report_list", claimed_role=role, rows_returned=len(rows))

    return render_template("a01_reports.html", meta=META, rows=rows, role=role)


def _is_metadata_target(host: str) -> bool:
    """Resolve a hostname and test it against the link-local metadata ranges."""
    candidates = []
    try:
        candidates.append(ipaddress.ip_address(host))
    except ValueError:
        try:
            for info in socket.getaddrinfo(host, None):
                candidates.append(ipaddress.ip_address(info[4][0]))
        except (socket.gaierror, ValueError):
            return False
    return any(
        any(addr in net for net in _METADATA_NETS if addr.version == net.version)
        for addr in candidates
    )


@bp.route("/fetch", methods=["GET", "POST"])
def fetch():
    """
    VULNERABLE — CWE-918.
    A "check a client's status page for us" feature. Any scheme urllib
    understands works, including file:// and http:// to internal addresses.
    There is no allow-list, which is the entire point.

    The single carve-out is the cloud metadata range, which is refused unless
    RANGE_SSRF_ALLOW_METADATA=1. On a public droplet that endpoint hands out
    real provider credentials — blast radius outside the lab rather than a
    training outcome. Internal-network SSRF still works exactly as expected.
    """
    url = (request.values.get("url") or "").strip()
    body = None
    error = None
    meta_info = {}

    if url:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        event("warning", "ssrf_fetch_requested", target_url=url[:512],
              scheme=parsed.scheme, target_host=host)

        if (not current_app.config["SSRF_ALLOW_METADATA"]
                and host and _is_metadata_target(host)):
            error = ("Refused: cloud metadata range. This is the one guard rail "
                     "in this endpoint — see RANGE_SSRF_ALLOW_METADATA.")
            event("critical", "ssrf_metadata_blocked", target_url=url[:512],
                  target_host=host)
        else:
            try:
                request_obj = urllib.request.Request(
                    url, headers={"User-Agent": "allsafe-range-fetcher/1.0"}
                )
                with urllib.request.urlopen(
                    request_obj, timeout=current_app.config["SSRF_TIMEOUT"]
                ) as response:
                    raw = response.read(current_app.config["SSRF_MAX_BYTES"])
                    meta_info = {
                        "status": getattr(response, "status", "-"),
                        "content_type": response.headers.get("Content-Type", "-"),
                        "bytes": len(raw),
                    }
                body = raw.decode("utf-8", "replace")
                event("warning", "ssrf_fetch_succeeded", target_url=url[:512],
                      target_host=host, **meta_info)
            except (urllib.error.URLError, ValueError, OSError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                event("info", "ssrf_fetch_failed", target_url=url[:512],
                      target_host=host, detail=str(exc)[:300])

    return render_template("a01_fetch.html", meta=META, url=url, body=body,
                           error=error, info=meta_info)
