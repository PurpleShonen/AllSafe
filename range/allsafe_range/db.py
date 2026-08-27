"""
Allsafe Range — SQLite storage and seed data
============================================
One file, one schema, disposable. `flask --app run init-db` (or
`python -m allsafe_range.db`) drops and rebuilds it from scratch. Treat any
running instance as throwaway — that is the whole operating model.

The password column stores unsalted MD5 on purpose (A04 Cryptographic Failures,
CWE-916/CWE-759). Seed passwords are deliberately weak so trainees can recover
them from the hashes with any wordlist.
"""

import hashlib
import os
import sqlite3

from flask import current_app, g

SCHEMA = """
PRAGMA journal_mode = WAL;

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT NOT NULL,
    -- A04: unsalted MD5. Never do this.
    password_md5  TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'client',
    full_name     TEXT NOT NULL,
    api_key       TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS accounts;
CREATE TABLE accounts (
    id             INTEGER PRIMARY KEY,
    owner_user_id  INTEGER NOT NULL,
    client_name    TEXT NOT NULL,
    contract_ref   TEXT NOT NULL,
    monthly_value  INTEGER NOT NULL,
    billing_email  TEXT NOT NULL,
    notes          TEXT NOT NULL
);

DROP TABLE IF EXISTS reports;
CREATE TABLE reports (
    id             INTEGER PRIMARY KEY,
    owner_user_id  INTEGER NOT NULL,
    title          TEXT NOT NULL,
    classification TEXT NOT NULL,
    body           TEXT NOT NULL
);

DROP TABLE IF EXISTS feedback;
CREATE TABLE feedback (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author     TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS coupons;
CREATE TABLE coupons (
    code         TEXT PRIMARY KEY,
    percent_off  INTEGER NOT NULL,
    times_used   INTEGER NOT NULL DEFAULT 0,
    max_uses     INTEGER NOT NULL DEFAULT 1   -- never actually enforced (A06)
);

DROP TABLE IF EXISTS reset_tokens;
CREATE TABLE reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    used       INTEGER NOT NULL DEFAULT 0
);

DROP TABLE IF EXISTS uploads;
CREATE TABLE uploads (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    filename       TEXT NOT NULL,
    stored_as      TEXT NOT NULL,
    claimed_sha256 TEXT,
    actual_sha256  TEXT NOT NULL,
    size_bytes     INTEGER NOT NULL,
    uploaded_by    TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS vault_items;
CREATE TABLE vault_items (
    id       INTEGER PRIMARY KEY,
    label    TEXT NOT NULL,
    secret   TEXT NOT NULL,
    pin      TEXT NOT NULL
);
"""


def md5(value: str) -> str:
    """A04 — unsalted MD5, exactly as it should never be done."""
    return hashlib.md5(value.encode("utf-8")).hexdigest()


SEED_USERS = [
    # id, username, email, password (plaintext -> md5), role, full name, api key
    (1, "admin",      "admin@range.allsafe.local",   "admin",       "admin",   "Range Administrator", "AR-KEY-0000-ADMIN"),
    (2, "j.ellis",    "j.ellis@northgate.example",   "Password1",   "client",  "Jordan Ellis",        "AR-KEY-1042-CLIENT"),
    (3, "p.mistry",   "p.mistry@meridian.example",   "sunshine",    "client",  "Priya Mistry",        "AR-KEY-2277-CLIENT"),
    (4, "s.okafor",   "s.okafor@calder.example",     "letmein",     "client",  "Sam Okafor",          "AR-KEY-3319-CLIENT"),
    (5, "analyst",    "analyst@range.allsafe.local", "analyst2024", "analyst", "Duty Analyst",        "AR-KEY-4400-ANALYST"),
]

SEED_ACCOUNTS = [
    (1001, 2, "Northgate Financial", "CT-2021-0087", 48000, "ap@northgate.example",
     "MDR + quarterly pentest. Escalation path: SOC bridge, then CISO mobile."),
    (1002, 3, "Meridian Health", "CT-2022-0140", 61500, "finance@meridian.example",
     "HIPAA scope. Break-glass account rotation due each January."),
    (1003, 4, "Calder Logistics", "CT-2023-0031", 22750, "billing@calder.example",
     "IR retainer only, 40 hours. Renewal at risk — do not discuss on calls."),
    (1004, 5, "Brightwell Energy", "CT-2020-0009", 93400, "treasury@brightwell.example",
     "OT segment monitoring. Regulator notification clause in section 9."),
]

SEED_REPORTS = [
    (5001, 2, "Northgate — Q3 external pentest", "CONFIDENTIAL",
     "Three high findings. Exposed Jenkins at 203.0.113.44 with anonymous read."),
    (5002, 3, "Meridian — HIPAA control gap review", "RESTRICTED",
     "Backup restore has not been tested in 22 months. Audit exposure."),
    (5003, 4, "Calder — IR tabletop debrief", "INTERNAL",
     "Nobody in the room knew who could authorise disconnecting the WAN link."),
    (5004, 1, "Allsafe Range — build notes", "SECRET",
     "Range admin password is 'admin'. Flag: ALLSAFE{br0ken_4ccess_c0ntr0l}"),
]

SEED_FEEDBACK = [
    ("Priya M.", "The new portal layout is much easier to follow, thanks."),
    ("Sam O.", "Ticket #4471 is still open after two weeks. Any update?"),
]

SEED_COUPONS = [
    ("WELCOME10", 10, 0, 1),
    ("SOC25", 25, 0, 1),
    ("RENEWAL50", 50, 0, 1),
]

SEED_VAULT = [
    (1, "Wi-Fi PSK — guest network", "GuestNet!2026", "4417"),
    (2, "Break-glass domain admin", "ALLSAFE{f4iled_t0_l0g_th3_f4ilure}", "9020"),
    (3, "Backup encryption passphrase", "correct-horse-battery-staple", "1188"),
]


def get_db() -> sqlite3.Connection:
    """Per-request SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path: str) -> None:
    """Drop and rebuild everything. Destructive by design."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.executemany(
            "INSERT INTO users (id, username, email, password_md5, role, full_name, api_key)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(i, u, e, md5(p), r, n, k) for (i, u, e, p, r, n, k) in SEED_USERS],
        )
        conn.executemany(
            "INSERT INTO accounts (id, owner_user_id, client_name, contract_ref,"
            " monthly_value, billing_email, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            SEED_ACCOUNTS,
        )
        conn.executemany(
            "INSERT INTO reports (id, owner_user_id, title, classification, body)"
            " VALUES (?, ?, ?, ?, ?)",
            SEED_REPORTS,
        )
        conn.executemany(
            "INSERT INTO feedback (author, message) VALUES (?, ?)", SEED_FEEDBACK
        )
        conn.executemany(
            "INSERT INTO coupons (code, percent_off, times_used, max_uses)"
            " VALUES (?, ?, ?, ?)",
            SEED_COUPONS,
        )
        conn.executemany(
            "INSERT INTO vault_items (id, label, secret, pin) VALUES (?, ?, ?, ?)",
            SEED_VAULT,
        )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":  # pragma: no cover
    from .config import Config

    init_db(Config.DB_PATH)
    print(f"[allsafe-range] database rebuilt at {Config.DB_PATH}")
