# ⚠️ STOP — READ THIS FIRST ⚠️

# THIS IS INTENTIONALLY VULNERABLE SOFTWARE

**Allsafe Range** deliberately contains security vulnerabilities. It exists so
that a SOC lab can generate realistic attack traffic and study the resulting
logs. Every "bug" in this application is there **on purpose**.

---

## Non-negotiable rules

1. **Isolated network only.** Run this on a throwaway VM or an isolated lab
   segment. Never on a machine, network, or account that touches anything you
   care about.

2. **Never any real or production data.** The seed data is fictional. Do not
   load real users, credentials, customer data, or anything sensitive into it —
   the app will happily leak all of it.

3. **Treat every instance as disposable.** Snapshot the VM, run a session, then
   roll back or rebuild. `docker compose down -v` or re-running `flask --app run
   init-db` wipes it back to a clean seed.

4. **Assume it will be compromised.** That is the point. The host it runs on
   should be one you are prepared to destroy. Do not reuse SSH keys, passwords,
   or cloud credentials from anywhere else on it.

5. **Do not "fix" the vulnerabilities and leave it running as if safe.** If you
   patch a module for a lesson, it is still surrounded by nine other live ones.

---

## What this app will do if reached by an attacker

- Hand over its entire user table, including (weakly hashed) passwords
- Return other tenants' records via trivial ID manipulation
- Fetch arbitrary URLs on its behalf (SSRF into whatever network it can see)
- Accept default admin credentials and print its own environment
- Serve files left in an open directory (including a planted `.env`)
- Let a login be bypassed with SQL injection
- Store and replay cross-site scripting payloads to other visitors

It does **not** contain a real remote-code-execution payload handler, a
reverse-shell listener, or anything designed to attack third parties. The goal
is realistic **logs**, not a functioning attack platform. See `README.md` →
"Scope and safety" for exactly where that line is drawn.

---

## The one guard rail that is ON by default

The SSRF endpoint (A01) refuses the cloud metadata address
`169.254.169.254` unless you set `RANGE_SSRF_ALLOW_METADATA=1`. On a public
cloud VM that address dispenses real provider credentials — that is blast radius
outside the lab, not a training outcome. Internal-network SSRF still works fully.
Leave the guard rail on unless you understand exactly why you are turning it off.

If you have read and accept all of the above, continue to `README.md`.
