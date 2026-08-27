"""
Allsafe Range — vulnerable modules
==================================
One module per OWASP Top 10:2025 category. Every module exposes:

    bp    : a Flask Blueprint, url_prefix "/aNN", with a `home` endpoint
    META  : dict describing the category, CWEs, and what the logs should show

Nothing outside this package is intentionally weak.
"""
