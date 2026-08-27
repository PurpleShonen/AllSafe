"""
A06 — Insecure Design
=====================
CWE-841  Improper Enforcement of Behavioral Workflow
CWE-799  Improper Control of Interaction Frequency (no rate limiting)
CWE-770  Allocation of Resources Without Limits or Throttling

WHAT IS WRONG HERE
------------------
The flaw is not a missing check that someone forgot to add — it is a design
with no business-logic limit in the first place.

1. /a06/coupon "validates" a coupon and applies the discount every time it is
   called. `max_uses` exists in the schema and is never consulted. A script can
   stack the same code to a 100% discount.
2. /a06/transfer moves "credit" between accounts with no balance check, so the
   balance goes negative without complaint.

There is no rate limiting anywhere, which is the same category of failure.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
No money and no real value moves. The "credit" is a number in a dict, reset on
restart.
"""

from flask import Blueprint, jsonify, render_template, request, session

from ..db import get_db
from ._common import event

bp = Blueprint("a06", __name__, url_prefix="/a06")

META = {
    "owasp": "A06:2025 Insecure Design",
    "cwe": ["CWE-841", "CWE-799", "CWE-770"],
    "summary": "A coupon endpoint with no use limit and a transfer with no balance check — missing business-logic controls, not a missing patch.",
    "endpoints": ["/a06/coupon", "/a06/transfer"],
}

# In-memory demo ledger. Not persisted; that is fine for a design lesson.
_LEDGER = {"me": 100, "vault": 0}


@bp.route("/")
def home():
    return render_template("a06.html", meta=META, ledger=dict(_LEDGER),
                           applied=session.get("a06_discount", 0))


@bp.route("/coupon", methods=["GET", "POST"])
@bp.route("/coupon.json", methods=["GET", "POST"])
def coupon():
    """
    VULNERABLE — CWE-841 / CWE-799.
    Every call re-applies the discount. `times_used` is incremented and logged,
    but `max_uses` is never enforced, and there is no per-caller throttle.
    """
    code = (request.values.get("code") or "").strip().upper()
    result = None

    if code:
        db = get_db()
        row = db.execute("SELECT * FROM coupons WHERE code = ?", (code,)).fetchone()
        if row is None:
            result = {"ok": False, "message": f"Unknown coupon {code}."}
            event("info", "coupon_unknown", code=code)
        else:
            # The bug: we bump the counter and apply the discount unconditionally.
            db.execute("UPDATE coupons SET times_used = times_used + 1 WHERE code = ?",
                       (code,))
            db.commit()
            times_used = row["times_used"] + 1
            stacked = session.get("a06_discount", 0) + row["percent_off"]
            session["a06_discount"] = stacked
            result = {
                "ok": True,
                "code": code,
                "percent_off": row["percent_off"],
                "times_used": times_used,
                "max_uses": row["max_uses"],
                "stacked_discount": stacked,
                "message": (f"Applied {row['percent_off']}%. "
                            f"Used {times_used} time(s); limit is {row['max_uses']} "
                            f"and is not enforced. Stacked discount now {stacked}%."),
            }
            level = "warning" if (times_used > row["max_uses"] or stacked > 100) else "info"
            event(level, "coupon_applied", code=code, times_used=times_used,
                  max_uses=row["max_uses"], stacked_discount=stacked,
                  over_limit=times_used > row["max_uses"])

    if request.path.endswith(".json") or request.accept_mimetypes.best == "application/json":
        return jsonify(result or {"ok": False, "message": "no code"})
    return render_template("a06_coupon.html", meta=META, result=result,
                           applied=session.get("a06_discount", 0))


@bp.route("/transfer", methods=["POST"])
def transfer():
    """VULNERABLE — CWE-841. No balance check; the source can go negative."""
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        amount = 0
    src = request.form.get("from", "me")
    dst = request.form.get("to", "vault")

    _LEDGER.setdefault(src, 0)
    _LEDGER.setdefault(dst, 0)
    _LEDGER[src] -= amount
    _LEDGER[dst] += amount

    negative = _LEDGER[src] < 0
    event("warning" if negative else "info", "credit_transfer",
          src=src, dst=dst, amount=amount,
          src_balance=_LEDGER[src], overdrawn=negative)

    return render_template("a06.html", meta=META, ledger=dict(_LEDGER),
                           applied=session.get("a06_discount", 0),
                           note=f"Moved {amount} from {src} to {dst}. "
                                f"{src} balance is now {_LEDGER[src]}.")
