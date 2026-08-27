<div align="center">

# 🛡️ AllSafe

**A home-lab SOC target environment for the `allsafe.local` domain.**

Two companion apps: a polished (fictional) security-vendor marketing site, and an
intentionally vulnerable training app that produces realistic attack logs for Wazuh.

<!-- Original design inspired by — not reproducing — the "Allsafe" firm from *Mr. Robot*. -->

![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/Vanilla_JS-F7DF1E?logo=javascript&logoColor=black)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-D22128?logo=apache&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)

![OWASP Top 10: 2025](https://img.shields.io/badge/OWASP-Top_10%3A2025-000000?logo=owasp&logoColor=white)
![Tests](https://img.shields.io/badge/tests-16_passing-2e7d5b)
![Status](https://img.shields.io/badge/status-lab_ready-4ea3e0)
![Intentionally Vulnerable](https://img.shields.io/badge/range-⚠️_intentionally_vulnerable-b3403a)

</div>

---

## What is this?

**AllSafe** is one piece of a home security-operations lab. It gives a SOC/blue-team
environment two realistic things to work with on the `allsafe.local` Active Directory
domain:

| | [`site/`](site/) — **Allsafe Cybersecurity** | [`range/`](range/) — **Allsafe Range** |
|---|---|---|
| **What** | Enterprise security-vendor marketing site | Deliberately vulnerable training app |
| **Stack** | HTML5 · CSS3 · vanilla JS (no build) | Flask · SQLite · gunicorn |
| **Purpose** | A believable target surface + a portal ready for LDAP auth | Generate realistic attack logs for Wazuh |
| **Exposure** | Safe to serve anywhere | **Isolated / disposable VM only** |
| **VirtualHost** | `allsafe.conf` | `range.allsafe.local.conf` *(separate)* |

The two are kept in **completely separate directories** with **separate Apache
VirtualHosts** so they can be deployed, enabled, and disabled independently.

> [!WARNING]
> **`range/` is intentionally vulnerable software.** Run it only on an isolated,
> disposable VM — never on a machine, network, or account you care about, and never
> with real data. Read **[`range/README-WARNING.md`](range/README-WARNING.md)** before
> starting it.

---

## Repository layout

```
AllSafe/
├── site/                     APP 1 — Allsafe Cybersecurity (static, safe)
│   ├── index.html            Home · Services · About · Careers · Contact
│   ├── assets/               single CSS file, vanilla JS, inline-SVG favicon
│   ├── portal/               isolated Client Portal + swappable auth seam
│   └── deploy/allsafe.conf   Apache VirtualHost
│
└── range/                    APP 2 — Allsafe Range (⚠️ intentionally vulnerable)
    ├── allsafe_range/
    │   ├── vulns/            one module per OWASP Top 10:2025 category
    │   ├── logging_setup.py  structured JSON logging (Wazuh-ready)
    │   └── db.py             SQLite schema + seed data
    ├── tests_smoke.py       16-test suite: every vuln + the logging contract
    ├── Dockerfile · docker-compose.yml
    └── deploy/              systemd · gunicorn · Apache proxy · Filebeat · rsyslog
```

---

## APP 1 — Allsafe Cybersecurity

A buttoned-up B2B security-vendor site — the kind of surface a red team would recon
and a blue team would monitor. Static files, **no build step**, single stylesheet,
inline-SVG logo, mobile-responsive.

- **6 pages** — Home (hero, service cards, client strip, CTA), Services, About
  (history, mission, leadership grid), Careers, Contact, and an isolated **Client Portal**.
- **Swappable auth seam** — the portal login posts JSON credentials to *one*
  configurable endpoint and renders the verdict, with **no knowledge of the auth
  method**. It ships with a hardcoded-credential stub; moving to real LDAP auth against
  `allsafe.local` is a one-line change, with nothing else in the site touched.
- **Deployment-ready** — reference Apache VirtualHost with clean-URL rewrites, CSP,
  security headers, and source-file denial.

```bash
# Preview locally (portal auth needs Apache/CGI; layout renders fine)
python3 -m http.server 8000 --directory site
```

**[`site/README.md`](site/README.md)** — file structure, Apache deploy steps,
`www-data` permissions, and the portal → LDAP swap guide.

---

## APP 2 — Allsafe Range

One deliberately vulnerable endpoint group per **OWASP Top 10:2025** category — each
individually toggleable, each logging **structured JSON** for Wazuh. **The logs are the
point:** exploit something, then read the logs and work out what a detection rule for it
would look like.

```bash
cd range
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Rebuild the SQLite DB from seed data (destructive, by design)
RANGE_DB_PATH=./data/range.db RANGE_LOG_DIR=./logs RANGE_UPLOAD_DIR=./data/uploads \
  .venv/bin/flask --app run init-db

# Run (the Werkzeug debugger is forced OFF — no live console)
RANGE_DB_PATH=./data/range.db RANGE_LOG_DIR=./logs RANGE_UPLOAD_DIR=./data/uploads \
  .venv/bin/python run.py            # → http://127.0.0.1:8080
```

Or, disposable:

```bash
docker compose up --build            # → http://127.0.0.1:8080
docker compose down -v               # wipe everything, fresh next time
```

### Coverage — OWASP Top 10:2025

| # | Category | Demonstrates | Key log signal |
|---|---|---|---|
| **A01** | Broken Access Control | IDOR · client-supplied `role` · SSRF | `account_access` `cross_tenant:true` |
| **A02** | Security Misconfiguration | default creds · rendered traceback · open dir listing | `default_credential_login_success` |
| **A03** | Software Supply Chain | live SBOM vs. a known-vulnerable pin | `sbom_exported` `vulnerable_components` |
| **A04** | Cryptographic Failures | unsalted MD5 · predictable/plaintext reset token · hardcoded key | `credential_material_exported` |
| **A05** | Injection | SQLi (search + login) · reflected & stored XSS | `sql_login_success` `via:sql_injection` |
| **A06** | Insecure Design | unlimited coupon stacking · no-balance transfer | `coupon_applied` `over_limit:true` |
| **A07** | Authentication Failures | no lockout · no password policy · eternal sessions | burst of `auth_login_failed` |
| **A08** | Data Integrity Failures | upload with unverified hash · unsigned update | `artifact_accepted_without_verification` |
| **A09** | Logging & Alerting Failures | **a deliberate blind spot** — failures never logged | *…silence (that's the finding)* |
| **A10** | Mishandling Exceptions | auth check that **fails open** when it throws | `authz_failed_open` |

> [!NOTE]
> **A09 is the twist.** `/a09/vault` never logs its *failed* attempts to `app.log`, while
> the identical `/a09/vault-fixed` does. An analyst watching only `app.log` sees the A02
> and A07 brute forces light up, assumes coverage is complete, and misses this one. Diff
> the two to find it — presence in the HTTP log is *not* the same as security-event coverage.

**[`range/README.md`](range/README.md)** — full endpoint → OWASP → CWE → *"what the SOC
should see"* table · **[`range/deploy/DEPLOYMENT.md`](range/deploy/DEPLOYMENT.md)** —
systemd/gunicorn behind Apache, VM firewalling, and shipping logs home over WireGuard.

---

## Scope & safety

The range demonstrates each weakness **only as far as needed to produce a realistic log
signal** — not to build a working attack platform:

- **No arbitrary code execution.** The Werkzeug interactive debugger is never enabled;
  A02 shows a *rendered* traceback instead.
- **A03**'s vulnerable dependency is *present but unreachable* — no untrusted input
  reaches a parser. The finding is the SBOM entry, not exploitation.
- **A08** stores and hashes uploads but never executes, unpacks, or interprets them.
- **No reverse shells, no C2, nothing aimed at third parties.**
- The **cloud-metadata guard rail** (A01 SSRF) is on by default, so a public-VM
  deployment can't be pivoted into credential theft with one request.

The goal is realistic logs, not a functioning botnet node.

---

## Testing

```bash
cd range
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests_smoke.py -q      # 16 passed
```

The suite asserts every intentional weakness behaves as designed **and** that the logging
contract holds (valid JSON per line, the A09 blind spot present, 404s stay 404s).

---

## Disclaimer

AllSafe is fictional and for **authorized, isolated lab use only**. "Allsafe" is used as
an original homage to *Mr. Robot*; no copy or branding is lifted from the show or from any
real vendor. The `range/` application is intentionally insecure — deploying it on a
production or internet-exposed system, or against data you don't own, is your
responsibility. See [`range/README-WARNING.md`](range/README-WARNING.md).
