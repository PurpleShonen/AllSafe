"""
A08 — Software or Data Integrity Failures
=========================================
CWE-345  Insufficient Verification of Data Authenticity
CWE-353  Missing Support for Integrity Check
CWE-494  Download of Code Without Integrity Check

WHAT IS WRONG HERE
------------------
/a08/upload accepts a file plus a *claimed* SHA-256 and stores it. It records
the claim and computes the real hash, but it never compares them and never
rejects a mismatch. The uploader asserts the integrity of their own artifact
and the server takes their word for it — which is the whole category.

There is also an "auto-update" manifest at /a08/update that describes a package
to fetch and "apply" by version string alone, with no signature.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
Uploaded files are stored and hashed. They are NEVER executed, imported,
unpacked, or interpreted. The "update" is a metadata record; nothing is fetched
or run. This module demonstrates the missing integrity check, not code
execution — running attacker-supplied code is out of scope for this range.
"""

import hashlib
import os
import uuid

from flask import Blueprint, jsonify, render_template, request

from ..db import get_db
from ._common import event

bp = Blueprint("a08", __name__, url_prefix="/a08")

META = {
    "owasp": "A08:2025 Software or Data Integrity Failures",
    "cwe": ["CWE-345", "CWE-353", "CWE-494"],
    "summary": "An upload endpoint that records a claimed hash but never verifies it, and an unsigned update manifest.",
    "endpoints": ["/a08/upload", "/a08/update"],
}

# A pretend update feed. No signature, no pinned hash — just a version string.
UPDATE_MANIFEST = {
    "product": "allsafe-range-agent",
    "current": "1.0.0",
    "latest": "1.4.2",
    "package_url": "http://updates.range.allsafe.local/agent-1.4.2.tar.gz",
    "signature": None,          # CWE-494: nothing signs this
    "sha256": None,             # CWE-353: no integrity value published either
    "apply_by": "version-string-comparison-only",
}


@bp.route("/")
def home():
    uploads = get_db().execute(
        "SELECT * FROM uploads ORDER BY id DESC LIMIT 25"
    ).fetchall()
    return render_template("a08.html", meta=META, uploads=uploads,
                           manifest=UPDATE_MANIFEST)


@bp.route("/upload", methods=["POST"])
def upload():
    """
    VULNERABLE — CWE-345 / CWE-353.
    Stores the file, records the claimed hash, computes the actual hash, and
    does NOT compare them. A tampered artifact with a truthful-looking claim is
    accepted exactly like a genuine one.
    """
    uploaded = request.files.get("artifact")
    claimed = (request.form.get("sha256") or "").strip().lower() or None

    if uploaded is None or uploaded.filename == "":
        return render_template("a08.html", meta=META,
                               uploads=_recent(), manifest=UPDATE_MANIFEST,
                               error="No file supplied."), 400

    from flask import current_app
    upload_dir = current_app.config["UPLOAD_DIR"]
    os.makedirs(upload_dir, exist_ok=True)

    stored_as = f"{uuid.uuid4().hex}_{os.path.basename(uploaded.filename)}"
    dest = os.path.join(upload_dir, stored_as)

    digest = hashlib.sha256()
    size = 0
    with open(dest, "wb") as fh:
        while True:
            chunk = uploaded.stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            fh.write(chunk)
    actual = digest.hexdigest()

    # The critical non-check: we KNOW whether it matches, and store it anyway.
    integrity_ok = (claimed is None) or (claimed == actual)

    db = get_db()
    db.execute(
        "INSERT INTO uploads (filename, stored_as, claimed_sha256, actual_sha256,"
        " size_bytes, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)",
        (uploaded.filename, stored_as, claimed, actual, size,
         request.remote_addr or "-"),
    )
    db.commit()

    event(
        "warning" if (claimed and not integrity_ok) else "info",
        "artifact_accepted_without_verification",
        filename=uploaded.filename, size_bytes=size,
        claimed_sha256=claimed, actual_sha256=actual,
        hash_matches=integrity_ok, verification_enforced=False,
    )

    return render_template("a08_result.html", meta=META, filename=uploaded.filename,
                           claimed=claimed, actual=actual, size=size,
                           integrity_ok=integrity_ok)


@bp.route("/update")
def update():
    """VULNERABLE — CWE-494. An update manifest with no signature and no hash."""
    event("warning", "unsigned_update_manifest_served",
          latest=UPDATE_MANIFEST["latest"], signed=False,
          integrity_value_present=False)
    return jsonify(UPDATE_MANIFEST)


def _recent():
    return get_db().execute(
        "SELECT * FROM uploads ORDER BY id DESC LIMIT 25"
    ).fetchall()
