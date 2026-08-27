"""
Allsafe Range — structured logging
==================================
Two log files, both newline-delimited JSON (one object per line), which is what
Wazuh's `json` decoder and Filebeat's `json.keys_under_root` both expect:

  /var/log/allsafe-range/access.log   every HTTP request, one line each
  /var/log/allsafe-range/app.log      application events worth alerting on

Nothing here is intentionally vulnerable. The logging is the point of the
exercise — the vulnerabilities exist to generate traffic worth reading.

Files rotate at 20 MB with 5 generations kept, so a scanning bot cannot fill the
disk during an unattended session.
"""

import datetime as _dt
import json
import logging
import logging.handlers
import os
import re
import socket
import sys

HOSTNAME = socket.gethostname()

# Parameter names whose values are replaced with "[redacted]" when
# Config.REDACT_SECRETS is on.
SECRET_PARAM = re.compile(
    r"pass|pwd|secret|token|otp|auth|session|cookie|key", re.IGNORECASE
)

# Cheap signature set used to tag suspicious-looking parameters at write time.
# This is NOT a WAF — nothing is blocked. It only adds a `suspected` field so a
# SIEM rule has something obvious to match while trainees learn the log shape.
SIGNATURES = (
    ("sqli", re.compile(r"(\bunion\b.{0,40}\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|--\s|\bsleep\s*\(|\bbenchmark\s*\(|;\s*drop\b)", re.I)),
    ("xss", re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+src\s*=|<svg)", re.I)),
    ("traversal", re.compile(r"(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|\\windows\\)", re.I)),
    ("ssrf", re.compile(r"(169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost|\bfile://|\bgopher://|\bdict://)", re.I)),
    ("cmdi", re.compile(r"(;\s*(cat|ls|id|whoami|curl|wget)\b|\$\(|`|\|\s*(sh|bash)\b)", re.I)),
)


class JsonLineFormatter(logging.Formatter):
    """Render a LogRecord as a single JSON object on one line."""

    def __init__(self, channel: str):
        super().__init__()
        self.channel = channel

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            # RFC3339 / ISO8601 UTC — Wazuh and Filebeat both parse this shape.
            "timestamp": _dt.datetime.fromtimestamp(
                record.created, _dt.timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "host": HOSTNAME,
            "app": "allsafe-range",
            "channel": self.channel,
            "level": record.levelname,
            "event": getattr(record, "event", record.name),
        }

        # Anything attached via logger.info(..., extra={...}) lands here.
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)

        message = record.getMessage()
        if message and message != payload["event"]:
            payload["message"] = message

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def _handler(path: str, channel: str) -> logging.Handler:
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(JsonLineFormatter(channel))
    return handler


def configure(app) -> None:
    """Attach the two JSON log channels to the Flask app."""
    log_dir = app.config["LOG_DIR"]

    try:
        os.makedirs(log_dir, exist_ok=True)
        probe = os.path.join(log_dir, ".writetest")
        with open(probe, "a"):
            pass
        os.unlink(probe)
    except OSError as exc:
        # Fall back to ./logs so a developer without root can still run this.
        fallback = os.path.abspath("logs")
        os.makedirs(fallback, exist_ok=True)
        print(
            f"[allsafe-range] cannot write to {log_dir} ({exc}); "
            f"logging to {fallback} instead",
            file=sys.stderr,
        )
        log_dir = fallback
        app.config["LOG_DIR"] = log_dir

    access = logging.getLogger("allsafe_range.access")
    access.setLevel(logging.INFO)
    access.propagate = False
    access.handlers.clear()
    access.addHandler(_handler(os.path.join(log_dir, "access.log"), "access"))

    appl = logging.getLogger("allsafe_range.app")
    appl.setLevel(logging.INFO)
    appl.propagate = False
    appl.handlers.clear()
    appl.addHandler(_handler(os.path.join(log_dir, "app.log"), "app"))

    # Mirror app events to stdout so `journalctl -u allsafe-range` and
    # `docker logs` are useful too.
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(JsonLineFormatter("app"))
    appl.addHandler(console)

    app.extensions["range_access_log"] = access
    app.extensions["range_app_log"] = appl


# ---------------------------------------------------------------------------
# Helpers used by the request hooks and the vulnerable modules
# ---------------------------------------------------------------------------

def scrub(mapping, redact: bool) -> dict:
    """Flatten a request MultiDict, optionally masking secret-looking values."""
    out = {}
    for key in mapping:
        values = mapping.getlist(key) if hasattr(mapping, "getlist") else [mapping[key]]
        value = values[0] if len(values) == 1 else values
        if redact and SECRET_PARAM.search(key):
            out[key] = "[redacted]"
        else:
            out[key] = value if len(str(value)) <= 512 else str(value)[:512] + "…[truncated]"
    return out


def suspicious(*blobs) -> list:
    """Return the names of any attack signatures present in the given strings."""
    hay = " ".join(str(b) for b in blobs if b)
    if not hay:
        return []
    return [name for name, pattern in SIGNATURES if pattern.search(hay)]


def app_event(app, severity: str, event_name: str, **fields) -> None:
    """Write one structured line to app.log.

    Parameters are named severity/event_name (not level/event) so callers can
    pass log fields literally called `level` or `event` without a collision.
    """
    logger = app.extensions.get("range_app_log")
    if logger is None:
        return
    logger.log(getattr(logging, severity.upper(), logging.INFO), event_name,
               extra={"event": event_name, "fields": fields})
