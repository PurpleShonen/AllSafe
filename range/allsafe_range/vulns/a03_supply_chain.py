"""
A03 — Software Supply Chain Failures
====================================
CWE-1104  Use of Unmaintained Third Party Components
CWE-1395  Dependency on Vulnerable Third-Party Component
CWE-502   Deserialization of Untrusted Data (the class of bug in the pinned CVE)

WHAT IS WRONG HERE
------------------
`requirements-outdated.txt` pins PyYAML 5.3.1, which carries CVE-2020-14343 —
`yaml.full_load()` on attacker-controlled input allows arbitrary code
execution. Installing it puts a known-vulnerable component in the dependency
tree, which is what this category is about.

WHAT IS DELIBERATELY *NOT* WRONG
--------------------------------
Nothing in this application ever passes user input to a YAML parser. The
vulnerable component is *present and reported*, not *reachable*. Running a
real deserialization RCE gadget is out of scope for this range — the goal is
realistic logs and a findable SBOM finding, not code execution.

The pin lives in a separate requirements file so a default install stays
current. See README.md for how to install it deliberately.
"""

import json

from flask import Blueprint, jsonify, render_template

from ._common import event

try:  # Python 3.8+
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore

bp = Blueprint("a03", __name__, url_prefix="/a03")

META = {
    "owasp": "A03:2025 Software Supply Chain Failures",
    "cwe": ["CWE-1104", "CWE-1395", "CWE-502"],
    "summary": "A pinned, known-vulnerable dependency reported through a live SBOM endpoint.",
    "endpoints": ["/a03/sbom", "/a03/sbom.json"],
}

# Deliberately small, hand-maintained advisory table. A real programme would use
# an actual vulnerability database; this is enough to make the exercise concrete.
ADVISORIES = {
    "pyyaml": [
        {
            "id": "CVE-2020-14343",
            "affected": "< 5.4",
            "severity": "critical",
            "cwe": "CWE-502",
            "summary": "yaml.full_load() permits arbitrary code execution on untrusted input.",
            "fixed_in": "5.4",
            "reachable_here": False,
            "note": "Pinned on purpose in requirements-outdated.txt. This app never "
                    "parses user-supplied YAML, so the vulnerable path is not reachable.",
        }
    ],
    "jinja2": [
        {
            "id": "CVE-2020-28493",
            "affected": "< 2.11.3",
            "severity": "medium",
            "cwe": "CWE-400",
            "summary": "Regular expression denial of service in the urlize filter.",
            "fixed_in": "2.11.3",
            "reachable_here": False,
            "note": "Included so the SBOM view has a package that is normally clean.",
        }
    ],
    "werkzeug": [
        {
            "id": "CVE-2023-25577",
            "affected": "< 2.2.3",
            "severity": "high",
            "cwe": "CWE-400",
            "summary": "Multipart form parsing can be driven into resource exhaustion.",
            "fixed_in": "2.2.3",
            "reachable_here": False,
            "note": "Relevant to the A08 upload endpoint if an old Werkzeug is installed.",
        }
    ],
}

WATCHED = ["flask", "werkzeug", "jinja2", "click", "itsdangerous", "markupsafe", "pyyaml"]


def _version_lt(version: str, ceiling: str) -> bool:
    """Naive numeric version compare — good enough for the pins we care about."""
    def parts(value):
        out = []
        for chunk in value.split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            out.append(int(digits) if digits else 0)
        return out
    left, right = parts(version), parts(ceiling)
    left += [0] * (len(right) - len(left))
    right += [0] * (len(left) - len(right))
    return left < right


def build_sbom() -> list:
    """Inspect what is actually installed and match it against ADVISORIES."""
    rows = []
    for name in WATCHED:
        try:
            version = importlib_metadata.version(name)
        except importlib_metadata.PackageNotFoundError:
            rows.append({"package": name, "version": None, "status": "not installed",
                         "findings": []})
            continue

        findings = []
        for advisory in ADVISORIES.get(name.lower(), []):
            ceiling = advisory["affected"].lstrip("< ").strip()
            if _version_lt(version, ceiling):
                findings.append(advisory)

        rows.append({
            "package": name,
            "version": version,
            "status": "VULNERABLE" if findings else "ok",
            "findings": findings,
        })
    return rows


@bp.route("/")
def home():
    return render_template("a03.html", meta=META, rows=build_sbom())


@bp.route("/sbom")
def sbom():
    rows = build_sbom()
    vulnerable = [r for r in rows if r["status"] == "VULNERABLE"]
    event("warning" if vulnerable else "info", "sbom_generated",
          packages=len(rows), vulnerable_packages=[r["package"] for r in vulnerable])
    return render_template("a03.html", meta=META, rows=rows)


@bp.route("/sbom.json")
def sbom_json():
    """Machine-readable SBOM. Point a scanner at it, or diff it between builds."""
    rows = build_sbom()
    vulnerable = [r["package"] for r in rows if r["status"] == "VULNERABLE"]
    event("warning" if vulnerable else "info", "sbom_exported",
          packages=len(rows), vulnerable_packages=vulnerable, format="json")
    return jsonify({
        "application": "allsafe-range",
        "components": rows,
        "vulnerable_components": vulnerable,
        "note": json.dumps(
            "Vulnerable components here are present, not reachable. "
            "No untrusted input reaches a YAML parser in this application."
        ),
    })
