#!/usr/bin/env python3
"""
Allsafe Client Portal — authentication STUB
===========================================
A deliberately minimal CGI script standing in for real authentication so the
portal can be demonstrated end to end. It is wired in by the VirtualHost:

    ScriptAlias /portal/login /var/www/allsafe/portal/login.cgi

WHAT THIS IS NOT
----------------
This is not an authentication system. Credentials are hardcoded below, there is
no session issuance, no lockout, and no rate limiting. It exists to return a
well-formed verdict so the front end can be exercised.

REPLACING IT
------------
The front end only knows the contract in auth-config.js: POST JSON credentials,
receive {"status": "...", "message": "..."}. To move to real LDAP auth against
allsafe.local, do one of:

  a) Point the ScriptAlias at a Flask/Node service that performs an ldap3 /
     ldapjs bind against dc01.allsafe.local and returns the same JSON, or
  b) Protect a Location with mod_authnz_ldap and change `endpoint` in
     auth-config.js to that path — portal.js already falls back to the HTTP
     status when the response is not JSON.

Either way, nothing outside this folder changes.
"""

import hmac
import json
import os
import sys

# --- Stub credential set (demo only — replace with a directory bind) ---------
STUB_USERS = {
    "j.ellis": "Northgate!2026",
    "p.mistry": "Meridian!2026",
    "demo.client": "AllsafeDemo!1",
}

MAX_BODY = 4096  # bytes; anything larger is rejected outright


def respond(http_status: str, payload: dict) -> None:
    """Emit a CGI response. Cache headers keep verdicts out of any proxy."""
    body = json.dumps(payload)
    sys.stdout.write(f"Status: {http_status}\r\n")
    sys.stdout.write("Content-Type: application/json; charset=utf-8\r\n")
    sys.stdout.write(f"Content-Length: {len(body.encode('utf-8'))}\r\n")
    sys.stdout.write("Cache-Control: no-store\r\n")
    sys.stdout.write("X-Content-Type-Options: nosniff\r\n")
    sys.stdout.write("\r\n")
    sys.stdout.write(body)


def main() -> None:
    if os.environ.get("REQUEST_METHOD", "GET").upper() != "POST":
        respond("405 Method Not Allowed",
                {"status": "denied", "message": "Send credentials with POST."})
        return

    try:
        length = int(os.environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0

    if length <= 0 or length > MAX_BODY:
        respond("400 Bad Request",
                {"status": "denied", "message": "Malformed sign-in request."})
        return

    raw = sys.stdin.read(length)

    try:
        data = json.loads(raw)
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
    except (ValueError, AttributeError):
        respond("400 Bad Request",
                {"status": "denied", "message": "Malformed sign-in request."})
        return

    expected = STUB_USERS.get(username.lower())

    # compare_digest on a dummy value too, so a bad username and a bad password
    # take the same path. Habit worth keeping even in a stub.
    if expected is not None and hmac.compare_digest(expected, password):
        respond("200 OK", {
            "status": "granted",
            "message": "Signed in as %s. This build has no authenticated area yet." % username,
        })
    else:
        hmac.compare_digest("x" * 16, password[:16] or "y" * 16)
        respond("401 Unauthorized", {
            "status": "denied",
            "message": "Username or password not recognised.",
        })


if __name__ == "__main__":
    main()
