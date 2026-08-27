# Allsafe Range

A deliberately vulnerable Flask application for SOC / blue-team training. One
endpoint group per **OWASP Top 10:2025** category, each individually
enable/disable-able, each emitting structured JSON logs designed for Splunk
ingestion.

> ⚠️ **Read [`README-WARNING.md`](README-WARNING.md) before running anything.**
> This is intentionally vulnerable software for isolated lab use only.

**The logs are the point.** The vulnerabilities exist to generate traffic worth
reading. The real exercise is: exploit something, then open `access.log` and
`app.log` and work out what a detection rule for it would look like — and find
the one module that deliberately does *not* log its failures.

---

## Stack

- **Python + Flask**, chosen over Node because the per-request structured
  logging and the app-level event log come out cleaner (one JSON object per
  line, no interleaving) — and clean logs are the whole deliverable here.
- **SQLite** storage, rebuilt from seed on demand.
- Runs as its **own systemd service in its own venv**, isolated from the
  marketing site's process, fronted by Apache as a reverse proxy.

---

## Quick start (local, no Apache)

```bash
cd range
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Rebuild the SQLite DB from seed data (destructive, that's intended)
RANGE_DB_PATH=./data/range.db RANGE_LOG_DIR=./logs RANGE_UPLOAD_DIR=./data/uploads \
  .venv/bin/flask --app run init-db

# Run (debugger is forced OFF regardless of env — see "Scope and safety")
RANGE_DB_PATH=./data/range.db RANGE_LOG_DIR=./logs RANGE_UPLOAD_DIR=./data/uploads \
  .venv/bin/python run.py
# -> http://127.0.0.1:8080
```

Or with Docker (disposable):

```bash
docker compose up --build         # http://127.0.0.1:8080
docker compose down -v            # wipe everything, incl. volumes
```

Run the smoke tests (assert every vuln behaves + the logging contract holds):

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests_smoke.py -q
```

---

## Enabling / disabling modules

Every category is a separate blueprint gated by an environment flag. All are on
by default. Turn any off:

```bash
RANGE_MODULE_A03=0 RANGE_MODULE_A09=0 .venv/bin/python run.py
```

In the systemd unit, add `Environment=RANGE_MODULE_A0n=0` lines.

---

## Layout

```
range/
├── run.py                     WSGI entrypoint (debug always off)
├── requirements.txt           current, patched deps (default install)
├── requirements-outdated.txt  the A03 vulnerable pin (install deliberately)
├── tests_smoke.py             pytest suite covering every module + logging
├── Dockerfile / docker-compose.yml
├── allsafe_range/
│   ├── __init__.py            app factory, request-logging hook, error handler
│   ├── config.py              all tunables + module flags + the hardcoded key (A04)
│   ├── db.py                  schema + seed data (unsalted MD5 on purpose, A04)
│   ├── logging_setup.py       two JSON log channels + signature tagging
│   ├── sample_files/          the "left behind" files for A02's open index
│   ├── static/range.css
│   ├── templates/
│   └── vulns/
│       ├── a01_access_control.py   IDOR, role param, SSRF
│       ├── a02_misconfiguration.py default creds, tracebacks, dir listing
│       ├── a03_supply_chain.py     live SBOM vs a known-vulnerable pin
│       ├── a04_crypto.py           MD5, predictable/plaintext reset token, hardcoded key
│       ├── a05_injection.py        SQLi (search + login), reflected + stored XSS
│       ├── a06_insecure_design.py  unlimited coupon, no-balance transfer
│       ├── a07_auth_failures.py    no lockout, no password policy, eternal sessions
│       ├── a08_integrity.py        upload with unverified hash, unsigned update
│       ├── a09_logging_failures.py the deliberate logging blind spot
│       └── a10_exceptional.py      auth check that fails open
└── deploy/
    ├── range.allsafe.local.conf    Apache reverse-proxy vhost (separate file!)
    ├── allsafe-range.service       systemd unit
    ├── gunicorn.conf.py
    ├── splunk-inputs.conf          ship app + Apache logs to SPLUNK01 (default)
    ├── filebeat-allsafe-range.yml  alternative shipper: Elastic/OpenSearch/Wazuh
    └── rsyslog-allsafe-range.conf  rsyslog alternative
```

---

## The endpoint → OWASP → CWE → "what a SOC analyst should see" map

Log channels referenced below:
- **access.log** — every HTTP request, one JSON line (method, path, params,
  `src_ip`, user-agent, status, `suspected` signature tags).
- **app.log** — application security events (the interesting stuff).

| Endpoint | OWASP 2025 | CWE | Exploit in one line | What shows in the logs |
|---|---|---|---|---|
| `GET /a01/account?id=` | A01 Broken Access Control | CWE-639 | Increment the `id` to read another tenant's account | access.log: sequential `id=` from one IP · app.log: `account_access` with `cross_tenant:true` |
| `GET /a01/reports?role=admin` | A01 | CWE-284 | Assert your own privilege via a query param | app.log: `privileged_view_via_parameter` `claimed_role:admin` |
| `POST /a01/fetch?url=` | A01 | CWE-918 | Point it at `file://` or an internal host | app.log: `ssrf_fetch_requested` / `ssrf_fetch_succeeded` / `ssrf_metadata_blocked` |
| `POST /a02/admin` | A02 Security Misconfiguration | CWE-1392 | Log in with `admin`/`admin` | app.log: `admin_login_failed`* then `default_credential_login_success` (CRITICAL) |
| `GET /a02/crash` | A02 | CWE-209 / 497 | Trigger a 500, read the traceback | HTTP 500 with traceback body · app.log: `unhandled_exception` + traceback |
| `GET /a02/files/` | A02 | CWE-548 | Browse the open index, grab `.env` | app.log: `directory_listing_served`, `sensitive_file_served` · access.log: `GET /a02/files/.env` = 200 |
| `GET /a03/sbom.json` | A03 Supply Chain | CWE-1104/1395 | Scan the SBOM; find the vulnerable pin | app.log: `sbom_exported` with `vulnerable_components` |
| `GET /a04/export` | A04 Cryptographic Failures | CWE-916/759 | Dump the user table, crack unsalted MD5 offline | app.log: `credential_material_exported` (CRITICAL) |
| `POST /a04/reset` | A04 | CWE-330 / 319 | Compute the token yourself (`md5(email+minute)`) | app.log: `password_reset_token_issued` (token in the clear), then `password_reset_completed` |
| `GET /a05/search?q=` | A05 Injection | CWE-89 | `x' UNION SELECT ... FROM users --` | access.log: `suspected:["sqli"]` · app.log: `account_search` with the exact SQL |
| `POST /a05/login` | A05 | CWE-89 | `' OR '1'='1' -- ` in username | app.log: `sql_login_success` `via:sql_injection` (CRITICAL) |
| `GET /a05/greet?name=` | A05 | CWE-79 | Reflected `<script>` | app.log: `reflected_xss_payload` with `suspected:["xss"]` |
| `POST /a05/feedback` | A05 | CWE-79 | Stored `<script>` fires for the next visitor | app.log: `feedback_stored` with payload + `suspected` |
| `POST /a06/coupon` | A06 Insecure Design | CWE-841/799 | Replay the coupon; stack the discount | access.log: many POSTs, one IP, short window · app.log: `coupon_applied` `over_limit:true` |
| `POST /a06/transfer` | A06 | CWE-841 | Overdraw past zero | app.log: `credit_transfer` `overdrawn:true` |
| `POST /a07/login` | A07 Auth Failures | CWE-307 | Brute force — nothing throttles you | app.log: burst of `auth_login_failed`, then `auth_login_success` |
| `POST /a07/register` | A07 | CWE-521 | Register with a 1-char password | app.log: `weak_password_accepted` `password_length:1` |
| `POST /a08/upload` | A08 Integrity Failures | CWE-345/353 | Upload with a lying `sha256` | app.log: `artifact_accepted_without_verification` `hash_matches:false` |
| `GET /a08/update` | A08 | CWE-494 | Read the unsigned update manifest | app.log: `unsigned_update_manifest_served` `signed:false` |
| `POST /a09/vault` | **A09 Logging Failures** | **CWE-778** | Brute-force the PIN | **access.log: the POSTs appear — but app.log logs NOTHING on failure. That silence is the finding.** |
| `POST /a09/vault-fixed` | (contrast) | — | Same endpoint, done right | app.log: `vault_unlock_failed` on every wrong PIN — diff it against `/a09/vault` |
| `GET /a10/download?clearance=` | A10 Exceptional Conditions | CWE-636/703 | Send a malformed `clearance`; the check throws and grants | app.log: `authz_failed_open` (CRITICAL) with the exception type |

\* Failed admin logins in A02 *are* logged — so an analyst can see the guessing.
Contrast that with A09, where failures are deliberately dropped.

### The A09 blind spot, spelled out

`/a09/vault` is the documented logging gap. **Failed** PIN attempts there are
never written to `app.log` — no event, no counter, no alert. Successful unlocks
*are* logged, and the raw HTTP POSTs still land in `access.log` (the
request-logging hook in `__init__.py` cannot be opted out of). So an analyst who
watches only `app.log` sees the A02 and A07 brute forces light up, assumes their
coverage is complete, and misses an identical attack here entirely.

`/a09/vault-fixed` is the same logic with the missing `WARNING` line restored.
Brute-force both, diff `app.log`, and the gap is obvious. The lesson: **presence
in the HTTP log is not the same as security-event coverage.**

---

## Where the logs land

| File | What | Splunk should ingest? |
|---|---|---|
| `/var/log/allsafe-range/access.log` | Every request as JSON | ✅ (app view: parsed params, `suspected` tags) |
| `/var/log/allsafe-range/app.log` | Security events as JSON | ✅ (the interesting events) |
| `/var/log/apache2/range_access.log` | Apache combined log for the vhost | ✅ (edge view: TLS, raw bytes, malformed reqs) |
| `/var/log/apache2/range_error.log` | Apache errors for the vhost | ✅ |

You want **both** the app logs and Apache's own logs: the app logs give you
parsed parameters and security events; Apache's give you the view from the edge,
including requests malformed enough that the app never parses them. See
[`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md) for the full pipeline.

Both app files are newline-delimited JSON, rotated at 20 MB × 5, so an unattended
scan cannot fill the disk.

---

## Scope and safety — where the line is drawn

This app demonstrates each CWE **only as far as needed to produce a realistic
log signal.** Specifically:

- **No arbitrary code execution.** Werkzeug's interactive debugger is never
  enabled (that is a live Python console = real RCE). A02 shows a *rendered*
  traceback instead.
- **A03** ships a known-vulnerable dependency that is *present but not
  reachable* — no untrusted input ever reaches a YAML parser. The finding is the
  SBOM entry, not exploitation.
- **A08** stores and hashes uploads but never executes, unpacks, or interprets
  them. The "update" is a metadata record; nothing is fetched or run.
- **No reverse-shell handlers, no outbound C2, nothing designed to attack third
  parties.** The SSRF fetcher reads bytes and shows them; it does not pipe
  anything into a shell.
- The **cloud-metadata guard rail** (A01) is on by default so a public-VM
  deployment can't be turned into a credential-theft pivot with one request.

The goal is realistic logs, not a functioning botnet node.

---

## Deployment

See [`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md) for the full walkthrough:
systemd + gunicorn behind Apache on WEB01, firewalling the VM down to 80/443,
and forwarding logs to SPLUNK01 with the Splunk Universal Forwarder.
