"""
A10 — Mishandling of Exceptional Conditions
===========================================
CWE-703  Improper Check or Handling of Exceptional Conditions
CWE-636  Not Failing Securely ('Failing Open')
CWE-755  Improper Handling of Exceptional Conditions

WHAT IS WRONG HERE
------------------
/a10/download runs an authorization check that can throw. The try/except wraps
the check and, in its except branch, GRANTS access — it fails open. Feed it
input that makes the check raise, and denial turns into permission.

The authorization decision depends on parsing a `clearance` token. A malformed
token raises inside the parser; the except branch treats "we could not decide"
as "allow". Correct behaviour is to deny by default when the check cannot be
completed.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
The "document" returned is a canned string. Nothing is executed, and the thrown
exception is caught within this handler (the app-wide 500 handler is not
involved here — that path is A02's).
"""

from flask import Blueprint, render_template, request

from ._common import event

bp = Blueprint("a10", __name__, url_prefix="/a10")

META = {
    "owasp": "A10:2025 Mishandling of Exceptional Conditions",
    "cwe": ["CWE-703", "CWE-636", "CWE-755"],
    "summary": "An authorization check that fails open — when the clearance check throws, access is granted instead of denied.",
    "endpoints": ["/a10/download"],
}

# The protected content and the clearance level each requires.
DOCUMENTS = {
    "public-brief": {"required_level": 0, "body": "Public brief: Allsafe range overview."},
    "client-report": {"required_level": 2, "body": "Client report: contract values and findings."},
    "board-minutes": {"required_level": 4,
                      "body": "Board minutes: ALLSAFE{f4il_0p3n_gr4nts_4ccess}"},
}


def parse_clearance(token: str) -> int:
    """
    Turn a clearance token into a numeric level.

    Valid tokens look like "level:2". This parser raises on anything else — and
    the caller's except branch is what mishandles that.
    """
    # int() on a non-numeric part raises ValueError; missing part raises
    # IndexError. Either way, an exception escapes.
    prefix, value = token.split(":", 1)
    if prefix != "level":
        raise ValueError(f"unrecognised clearance prefix: {prefix!r}")
    return int(value)


@bp.route("/")
def home():
    return render_template("a10.html", meta=META, documents=DOCUMENTS)


@bp.route("/download")
def download():
    """
    VULNERABLE — CWE-636 / CWE-703.
    The authorization check is inside a try. Its except branch grants access.
    """
    doc_id = request.args.get("doc", "public-brief")
    token = request.args.get("clearance", "level:0")
    document = DOCUMENTS.get(doc_id)

    if document is None:
        return render_template("a10.html", meta=META, documents=DOCUMENTS,
                               error=f"No document {doc_id!r}."), 404

    granted = False
    reason = ""
    failed_open = False

    try:
        level = parse_clearance(token)
        granted = level >= document["required_level"]
        reason = (f"clearance level {level} vs required {document['required_level']}"
                  f" -> {'granted' if granted else 'denied'}")
        event("info", "authz_decision", doc=doc_id, clearance_token=token,
              level=level, required=document["required_level"], granted=granted)
    except Exception as exc:  # noqa: BLE001 — the bug is precisely this broad catch
        # >>> FAILS OPEN <<<
        # The secure behaviour is `granted = False` here. Instead the handler
        # assumes a thrown check means "let them through".
        granted = True
        failed_open = True
        reason = (f"clearance check raised {type(exc).__name__}; "
                  f"granting access by default (this is the bug)")
        event("critical", "authz_failed_open", doc=doc_id, clearance_token=token,
              exception=type(exc).__name__, detail=str(exc)[:200],
              required=document["required_level"], granted=True)

    body = document["body"] if granted else None
    return render_template("a10_download.html", meta=META, doc_id=doc_id,
                           token=token, granted=granted, failed_open=failed_open,
                           reason=reason, body=body,
                           required=document["required_level"])
