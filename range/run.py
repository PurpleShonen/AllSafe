#!/usr/bin/env python3
"""
Allsafe Range — WSGI entrypoint
===============================
    flask --app run init-db          # build/rebuild the SQLite database
    flask --app run run --port 8080  # dev server (debug OFF, always)
    gunicorn -c deploy/gunicorn.conf.py run:app   # production-ish

Never runs with the interactive debugger. See README-WARNING.md.
"""
from allsafe_range import create_app

app = create_app()

if __name__ == "__main__":
    # Bind loopback only by default — Apache reverse-proxies to it. Debug is
    # forced off regardless of environment; this is intentionally vulnerable
    # software and must not also expose a live Python console.
    app.run(host="127.0.0.1", port=8080, debug=False)
