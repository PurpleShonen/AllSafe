"""
Allsafe Range — configuration
=============================
Everything tunable lives here. Values come from environment variables so a
container, a systemd unit, and a laptop can all differ without editing source.

Each vulnerable module has its own on/off switch (RANGE_MODULE_A01 ... A10) so
a training session can enable one category at a time.
"""

import os


def _flag(name: str, default: bool = True) -> bool:
    """Read a boolean environment flag."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # ---------------------------------------------------------------- app ---
    # INTENTIONALLY VULNERABLE — A04 Cryptographic Failures (CWE-798).
    # A hardcoded secret in source. Anyone with the repo can forge a session
    # cookie. A real deployment would read this from the environment or a
    # systemd credential; this one does not, on purpose.
    SECRET_KEY = "allsafe-range-dev-key-do-not-use-anywhere-else"

    # Sessions that never expire — A07 Authentication Failures (CWE-613).
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 3650  # ten years
    SESSION_COOKIE_HTTPONLY = False   # readable from JS, pairs with the A05 XSS
    SESSION_COOKIE_SAMESITE = None
    SESSION_COOKIE_SECURE = False

    # Werkzeug's interactive debugger is NEVER enabled. It provides a live
    # Python console, which would be real RCE — out of scope for this range.
    # A02 demonstrates verbose stack traces by rendering the traceback text
    # itself instead.
    DEBUG = False
    TESTING = False

    # ------------------------------------------------------------ storage ---
    DB_PATH = os.environ.get("RANGE_DB_PATH", "/var/lib/allsafe-range/range.db")
    UPLOAD_DIR = os.environ.get("RANGE_UPLOAD_DIR", "/var/lib/allsafe-range/uploads")
    MAX_CONTENT_LENGTH = int(os.environ.get("RANGE_MAX_UPLOAD", 2 * 1024 * 1024))

    # ------------------------------------------------------------ logging ---
    LOG_DIR = os.environ.get("RANGE_LOG_DIR", "/var/log/allsafe-range")
    # Log the presence of a password parameter but not its value. Set to 0 if
    # you specifically want captured credentials in the training data.
    REDACT_SECRETS = _flag("RANGE_REDACT_SECRETS", True)
    # Trust X-Forwarded-For from Apache. Turn off if the app is exposed directly.
    TRUST_PROXY_HEADERS = _flag("RANGE_TRUST_PROXY", True)

    # ------------------------------------------------- module enable flags ---
    MODULES = {
        "a01": _flag("RANGE_MODULE_A01"),
        "a02": _flag("RANGE_MODULE_A02"),
        "a03": _flag("RANGE_MODULE_A03"),
        "a04": _flag("RANGE_MODULE_A04"),
        "a05": _flag("RANGE_MODULE_A05"),
        "a06": _flag("RANGE_MODULE_A06"),
        "a07": _flag("RANGE_MODULE_A07"),
        "a08": _flag("RANGE_MODULE_A08"),
        "a09": _flag("RANGE_MODULE_A09"),
        "a10": _flag("RANGE_MODULE_A10"),
    }

    # ----------------------------------------------- A01 SSRF guard rails ---
    # The SSRF endpoint has no allow-list, by design. The one exception is the
    # cloud link-local metadata range (169.254.169.254 / fd00:ec2::254). On a
    # public droplet that address hands out real provider credentials, which is
    # blast radius outside the lab rather than a training outcome. Set
    # RANGE_SSRF_ALLOW_METADATA=1 if you are on a VM with no metadata service
    # and want the unrestricted behaviour.
    SSRF_ALLOW_METADATA = _flag("RANGE_SSRF_ALLOW_METADATA", False)
    SSRF_TIMEOUT = float(os.environ.get("RANGE_SSRF_TIMEOUT", 5.0))
    SSRF_MAX_BYTES = int(os.environ.get("RANGE_SSRF_MAX_BYTES", 64 * 1024))

    # ------------------------------------------------------------ banners ---
    APP_NAME = "Allsafe Range"
    APP_VERSION = "1.0.0"
