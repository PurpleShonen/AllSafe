"""
A09 — Security Logging & Alerting Failures
==========================================
CWE-778  Insufficient Logging
CWE-223  Omission of Security-relevant Information

THE BLIND SPOT (documented, because this is a training range)
------------------------------------------------------------
Every other module in this app logs its failed/suspicious attempts to app.log.
This one does NOT — on purpose.

    /a09/vault  is a PIN-protected "secret vault". FAILED PIN ATTEMPTS ARE
                NEVER WRITTEN TO app.log. A brute force against it leaves no
                application-level trace at all.

A defender watching only app.log will see the A02/A07 brute forces light up and
conclude their coverage is fine — while an identical attack here is invisible.
Finding that gap is the exercise.

IMPORTANT NUANCE
----------------
access.log still records the HTTP requests (the after_request hook in
__init__.py logs every request and cannot be opted out of — that is by design).
So the raw POSTs to /a09/vault exist in access.log, but with:
  - no app.log security event,
  - no failure/attempt counter,
  - no `suspected` enrichment beyond what the generic signature scan happens to
    catch.
The lesson is that HTTP-log presence is not the same as security-event
coverage, and that a control gap can hide behind "well, it's in the logs
somewhere". The successful unlock and the app's other events log normally,
which makes the silence on failures the thing to notice.

For contrast, /a09/vault-fixed is the SAME endpoint WITH proper logging, so a
trainee can diff the two in app.log.
"""

from flask import Blueprint, render_template, request

from ..db import get_db
from ._common import event

bp = Blueprint("a09", __name__, url_prefix="/a09")

META = {
    "owasp": "A09:2025 Security Logging & Alerting Failures",
    "cwe": ["CWE-778", "CWE-223"],
    "summary": "A PIN-protected vault whose FAILED attempts are deliberately never logged to app.log — the blind spot to find.",
    "endpoints": ["/a09/vault", "/a09/vault-fixed"],
    "blind_spot": "Failed PIN attempts on /a09/vault are not logged to app.log. Compare with /a09/vault-fixed.",
}


@bp.route("/")
def home():
    return render_template("a09.html", meta=META)


@bp.route("/vault", methods=["GET", "POST"])
def vault():
    """
    VULNERABLE — CWE-778.
    On a WRONG pin: nothing is written to app.log. No event, no counter, no
    alert. This silence is the vulnerability.
    """
    unlocked = None
    item_id = request.values.get("item", "1")
    attempted = False

    if request.method == "POST":
        attempted = True
        pin = request.form.get("pin", "")
        row = get_db().execute(
            "SELECT id, label, secret, pin FROM vault_items WHERE id = ?", (item_id,)
        ).fetchone()

        if row and pin == row["pin"]:
            unlocked = {"label": row["label"], "secret": row["secret"]}
            # Successful unlocks ARE logged. Only failures are dropped, which is
            # what makes the gap subtle rather than an obviously dead endpoint.
            event("info", "vault_unlocked", item=item_id, label=row["label"])
        else:
            # >>> THE DELIBERATE BLIND SPOT <<<
            # A wrong PIN produces no app.log event. A real fix would emit a
            # WARNING here, exactly like /a09/vault-fixed does. Do not "helpfully"
            # add logging to this branch — the missing line is the whole point.
            pass

    return render_template("a09_vault.html", meta=META, unlocked=unlocked,
                           item_id=item_id, attempted=attempted, logged=False)


@bp.route("/vault-fixed", methods=["GET", "POST"])
def vault_fixed():
    """The remediated twin — identical logic, but failures are logged."""
    unlocked = None
    item_id = request.values.get("item", "1")
    attempted = False

    if request.method == "POST":
        attempted = True
        pin = request.form.get("pin", "")
        row = get_db().execute(
            "SELECT id, label, secret, pin FROM vault_items WHERE id = ?", (item_id,)
        ).fetchone()

        if row and pin == row["pin"]:
            unlocked = {"label": row["label"], "secret": row["secret"]}
            event("info", "vault_unlocked", item=item_id, label=row["label"],
                  variant="fixed")
        else:
            # The line the vulnerable twin is missing.
            event("warning", "vault_unlock_failed", item=item_id,
                  pin_length=len(pin), variant="fixed")

    return render_template("a09_vault.html", meta=META, unlocked=unlocked,
                           item_id=item_id, attempted=attempted, logged=True)
