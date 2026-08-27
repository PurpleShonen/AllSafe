"""
Smoke tests for Allsafe Range.

These assert that each intentional weakness behaves as designed AND that the
logging contract holds (valid JSON, blind spot present, etc.). Run with:

    RANGE_DB_PATH=./data/test.db RANGE_LOG_DIR=./logs-test \
    RANGE_UPLOAD_DIR=./data/test-uploads .venv/bin/python -m pytest tests_smoke.py -q

Not shipped as part of the vulnerable surface — this is test tooling.
"""
import io
import json
import os
import tempfile

import pytest

from allsafe_range import create_app
from allsafe_range.config import Config
from allsafe_range import db as db_module


@pytest.fixture()
def client(tmp_path):
    class T(Config):
        DB_PATH = str(tmp_path / "range.db")
        LOG_DIR = str(tmp_path / "logs")
        UPLOAD_DIR = str(tmp_path / "uploads")
    db_module.init_db(T.DB_PATH)
    app = create_app(T)
    app.testing = True
    with app.test_client() as c:
        c._logdir = T.LOG_DIR
        yield c


def _applog(client):
    path = os.path.join(client._logdir, "app.log")
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path) if l.strip()]


def _events(client):
    return [e["event"] for e in _applog(client)]


def test_all_app_log_lines_are_json(client):
    client.get("/a01/account?id=1004")
    for entry in _applog(client):
        assert "timestamp" in entry and "event" in entry


def test_a01_idor(client):
    r = client.get("/a01/account?id=1004")
    assert b"Brightwell Energy" in r.data
    assert any(e.get("event") == "account_access" and e.get("cross_tenant")
               for e in _applog(client))


def test_a01_role_param(client):
    r = client.get("/a01/reports?role=admin")
    assert b"ALLSAFE{" in r.data


def test_a01_ssrf_metadata_blocked_by_default(client):
    r = client.post("/a01/fetch", data={"url": "http://169.254.169.254/"})
    assert b"metadata" in r.data
    assert "ssrf_metadata_blocked" in _events(client)


def test_a02_default_creds(client):
    r = client.post("/a02/admin", data={"username": "admin", "password": "admin"})
    assert b"default administrative account" in r.data
    assert "default_credential_login_success" in _events(client)


def test_a02_traceback_rendered(client):
    r = client.get("/a02/crash?divisor=0")
    assert r.status_code == 500
    assert b"Traceback" in r.data
    assert "unhandled_exception" in _events(client)


def test_a02_directory_listing(client):
    assert b".env" in client.get("/a02/files/").data
    assert b"ALLSAFE{d1r3ct0ry" in client.get("/a02/files/.env").data


def test_a04_md5_export(client):
    r = client.get("/a04/export")
    data = json.loads(r.data)
    admin = [u for u in data["users"] if u["username"] == "admin"][0]
    assert admin["password_md5"] == "21232f297a57a5a743894a0e4a801fc3"


def test_a05_sqli_login_bypass(client):
    r = client.post("/a05/login", data={"username": "' OR '1'='1' -- ", "password": "x"})
    assert b"Authenticated as" in r.data
    assert "sql_login_success" in _events(client)


def test_a05_stored_xss(client):
    client.post("/a05/feedback", data={"author": "a", "message": "<script>alert(1)</script>"})
    assert b"<script>alert(1)</script>" in client.get("/a05/feedback").data


def test_a06_coupon_stacks(client):
    last = 0
    for _ in range(3):
        r = client.post("/a06/coupon.json", data={"code": "RENEWAL50"})
        last = json.loads(r.data)["stacked_discount"]
    assert last > 100


def test_a07_no_lockout(client):
    for i in range(6):
        r = client.post("/a07/login", data={"username": "admin", "password": f"n{i}"})
        assert r.status_code == 200
    assert _events(client).count("auth_login_failed") >= 6


def test_a08_upload_unverified(client):
    r = client.post("/a08/upload", data={
        "sha256": "deadbeef" * 8,
        "artifact": (io.BytesIO(b"payload"), "agent.bin"),
    }, content_type="multipart/form-data")
    assert b"does NOT match" in r.data
    assert any(e.get("event") == "artifact_accepted_without_verification"
               and e.get("hash_matches") is False for e in _applog(client))


def test_a09_blind_spot(client):
    # Wrong PINs on both endpoints
    for pin in ("0000", "1111"):
        client.post("/a09/vault", data={"item": "1", "pin": pin})
        client.post("/a09/vault-fixed", data={"item": "1", "pin": pin})
    events = _applog(client)
    # vault-fixed logs failures; the blind vault logs none
    failed = [e for e in events if e.get("event") == "vault_unlock_failed"]
    assert failed, "vault-fixed should log failures"
    assert all(e.get("variant") == "fixed" for e in failed)
    blind_failures = [e for e in events
                      if e.get("path") == "/a09/vault" and e.get("event") == "vault_unlock_failed"]
    assert not blind_failures, "the blind vault must not log failures"


def test_a10_fail_open(client):
    denied = client.get("/a10/download?doc=board-minutes&clearance=level:0")
    assert b"Access denied" in denied.data
    legit = client.get("/a10/download?doc=board-minutes&clearance=level:4")
    assert b"granted legitimately" in legit.data
    exploit = client.get("/a10/download?doc=board-minutes&clearance=banana")
    assert b"failing open" in exploit.data
    assert b"ALLSAFE{" in exploit.data
    assert "authz_failed_open" in _events(client)


def test_404_is_404_not_500(client):
    assert client.get("/no-such-route").status_code == 404
