"""Small helpers shared by the vulnerable modules. Nothing weak lives here."""

from flask import current_app, g, request

from ..logging_setup import app_event, suspicious  # noqa: F401  (re-exported)


def ip() -> str:
    """Source address for logging, honouring X-Forwarded-For behind Apache."""
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "-"


def event(severity: str, event_name: str, **fields) -> None:
    """Write a structured line to app.log, tagged with the current module.

    Note the odd parameter names (severity/event_name rather than level/event):
    modules legitimately log fields called `level` and `event`, so the helper
    must not reserve those names as positional parameters.
    """
    fields.setdefault("module", request.blueprint or "core")
    fields.setdefault("src_ip", ip())
    fields.setdefault("request_id", getattr(g, "request_id", "-"))
    fields.setdefault("path", request.path)
    app_event(current_app, severity, event_name, **fields)
