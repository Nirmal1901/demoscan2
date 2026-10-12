import time
from pathlib import Path
from unittest import mock

import pytest

from app import create_app
from app.auth import make_token, verify_token
from app.db import get_db


@pytest.fixture
def client(tmp_path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    (uploads / "hello.txt").write_text("hi")
    app = create_app({"DATABASE": str(tmp_path / "t.sqlite"), "UPLOAD_DIR": str(uploads), "JWT_SECRET": "test", "TESTING": True})
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO users (username, password_hash, role) VALUES ('root', 'x', 'admin')")
        db.commit()
    return app.test_client(), app


def _register_login(c, name="alice"):
    c.post("/api/register", json={"username": name, "password": "correct-horse"})
    token = c.post("/api/login", json={"username": name, "password": "correct-horse"}).get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_ticket_flow(client):
    c, _ = client
    h = _register_login(c)
    tid = c.post("/api/tickets", json={"title": "printer"}, headers=h).get_json()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"status": "closed"}, headers=h)
    assert r.status_code == 200 and r.get_json()["status"] == "closed"


def test_requires_auth(client):
    c, _ = client
    assert c.get("/api/files").status_code == 401


def test_file_download_and_dotdot_blocked(client):
    c, _ = client
    h = _register_login(c)
    assert c.get("/api/files/hello.txt", headers=h).data == b"hi"
    assert c.get("/api/files/..%2fsecret", headers=h).status_code in (400, 404)


def test_webhook_rejects_foreign_host(client):
    c, _ = client
    h = _register_login(c)
    assert c.post("/api/webhooks/test", json={"url": "http://example.org/x"}, headers=h).status_code == 400
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 204
        r = c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/a"}, headers=h)
    assert r.get_json()["status"] == 204


def test_prefs_roundtrip(client):
    c, _ = client
    h = _register_login(c)
    exported = c.post("/api/prefs/export", json={"theme": "dark"}, headers=h).get_json()
    r = c.post("/api/prefs/import", json=exported, headers=h)
    assert r.get_json()["prefs"] == {"theme": "dark"}
    assert c.post("/api/prefs/import", json={**exported, "sig": "0"}, headers=h).status_code == 400


def test_audit_summary_admin_only(client):
    c, app = client
    h = _register_login(c)
    assert c.get("/api/audit/summary", headers=h).status_code == 403
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/audit/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.get_json()["alice"] == 2


def test_login_next_local_only(client):
    c, _ = client
    c.post("/api/register", json={"username": "bob", "password": "correct-horse"})
    r = c.post("/api/login", json={"username": "bob", "password": "correct-horse", "next": "/dashboard"})
    assert r.status_code == 302 and r.headers["Location"] == "/dashboard"
    r = c.post("/api/login", json={"username": "bob", "password": "correct-horse", "next": "https://evil.example"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# app/auth.py — legitimate token issuance, verification, register/login flows
# ---------------------------------------------------------------------------


def test_make_token_and_verify_roundtrip(client):
    c, app = client
    with app.app_context():
        token = make_token({"id": 7, "username": "carol", "role": "user"})
        claims = verify_token(token)
    assert claims is not None
    assert claims["sub"] == 7
    assert claims["name"] == "carol"
    assert claims["role"] == "user"
    assert claims["iss"] == "vaultdesk"
    assert claims["exp"] > time.time()


def test_verify_token_rejects_malformed(client):
    c, app = client
    with app.app_context():
        assert verify_token("not-a-jwt") is None
        assert verify_token("!!!.@@@.###") is None


def test_register_and_login_contracts(client):
    c, _ = client
    assert c.post("/api/register", json={"username": "erin", "password": "long-enough-pw"}).status_code == 201
    # duplicate username is a conflict
    assert c.post("/api/register", json={"username": "erin", "password": "long-enough-pw"}).status_code == 409
    # too-short username / password rejected
    assert c.post("/api/register", json={"username": "ab", "password": "long-enough-pw"}).status_code == 400
    assert c.post("/api/register", json={"username": "erin2", "password": "short"}).status_code == 400
    # wrong password does not mint a token
    assert c.post("/api/login", json={"username": "erin", "password": "wrong"}).status_code == 401
    ok = c.post("/api/login", json={"username": "erin", "password": "long-enough-pw"})
    assert ok.status_code == 200 and ok.get_json()["token"]


def test_login_token_authenticates_requests(client):
    c, _ = client
    headers = _register_login(c, "quinn")
    assert c.get("/api/files", headers=headers).status_code == 200


def test_login_local_next_paths_redirect(client):
    c, _ = client
    c.post("/api/register", json={"username": "sam", "password": "correct-horse"})
    r = c.post("/api/login", json={"username": "sam", "password": "correct-horse", "next": "/api/tickets"})
    assert r.status_code == 302 and r.headers["Location"] == "/api/tickets"
    r2 = c.post("/api/login", json={"username": "sam", "password": "correct-horse", "next": "/"})
    assert r2.status_code == 302 and r2.headers["Location"] == "/"


# ---------------------------------------------------------------------------
# app/files.py — legitimate listing / download of files inside UPLOAD_DIR
# ---------------------------------------------------------------------------


def test_file_list_returns_sorted_names(client):
    c, app = client
    h = _register_login(c, "una")
    uploads = Path(app.config["UPLOAD_DIR"])
    (uploads / "a.txt").write_text("a")
    (uploads / "b.txt").write_text("b")
    r = c.get("/api/files", headers=h)
    assert r.status_code == 200
    assert r.get_json()["files"] == ["a.txt", "b.txt", "hello.txt"]


def test_file_download_nested_path(client):
    c, app = client
    h = _register_login(c, "vic")
    sub = Path(app.config["UPLOAD_DIR"]) / "reports"
    sub.mkdir()
    (sub / "q1.txt").write_text("quarterly")
    r = c.get("/api/files/reports/q1.txt", headers=h)
    assert r.status_code == 200 and r.data == b"quarterly"


def test_file_download_missing_returns_404(client):
    c, _ = client
    h = _register_login(c, "wes")
    assert c.get("/api/files/nope.txt", headers=h).status_code == 404


# ---------------------------------------------------------------------------
# app/prefs.py — signed export/import round-trip of real preference payloads
# ---------------------------------------------------------------------------


def test_prefs_roundtrip_nested_payload(client):
    c, _ = client
    h = _register_login(c, "xena")
    original = {"theme": "dark", "notifications": {"email": True, "sms": False}, "tags": ["a", "b"]}
    exported = c.post("/api/prefs/export", json=original, headers=h).get_json()
    assert set(exported) == {"data", "sig"}
    r = c.post("/api/prefs/import", json=exported, headers=h)
    assert r.status_code == 200 and r.get_json()["prefs"] == original


def test_prefs_empty_roundtrip(client):
    c, _ = client
    h = _register_login(c, "yuri")
    exported = c.post("/api/prefs/export", json={}, headers=h).get_json()
    r = c.post("/api/prefs/import", json=exported, headers=h)
    assert r.status_code == 200 and r.get_json()["prefs"] == {}


def test_prefs_endpoints_require_auth(client):
    c, _ = client
    assert c.post("/api/prefs/export", json={}).status_code == 401
    assert c.post("/api/prefs/import", json={}).status_code == 401


# ---------------------------------------------------------------------------
# app/reports.py — admin audit summary + stats contract
# ---------------------------------------------------------------------------


def _admin_headers(app):
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def test_stats_endpoint_contract(client):
    c, app = client
    h = _admin_headers(app)
    body = c.get("/api/stats/users", headers=h).get_json()
    assert body["kind"] == "users" and body["count"] == 1  # seeded 'root' only
    assert c.get("/api/stats/tickets", headers=h).get_json() == {"kind": "tickets", "count": 0}
    assert c.get("/api/stats/unknown", headers=h).status_code == 404


def test_stats_admin_only(client):
    c, _ = client
    h = _register_login(c, "zane")
    assert c.get("/api/stats/users", headers=h).status_code == 403


def test_audit_summary_handles_quoted_username(client):
    c, app = client
    c.post("/api/register", json={"username": "o'brien", "password": "correct-horse"})
    c.post("/api/login", json={"username": "o'brien", "password": "correct-horse"})
    r = c.get("/api/audit/summary", headers=_admin_headers(app))
    assert r.status_code == 200
    assert r.get_json()["o'brien"] == 2  # one 'register' + one 'login'


# ---------------------------------------------------------------------------
# app/tickets.py — create/update with the owner-or-admin rule
# ---------------------------------------------------------------------------


def test_ticket_owner_can_edit_fields(client):
    c, _ = client
    h = _register_login(c, "gina")
    tid = c.post("/api/tickets", json={"title": "vpn", "body": "down"}, headers=h).get_json()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"title": "vpn2", "body": "up", "status": "closed"}, headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["title"] == "vpn2" and body["body"] == "up" and body["status"] == "closed"


def test_ticket_create_requires_title(client):
    c, _ = client
    h = _register_login(c, "hank")
    assert c.post("/api/tickets", json={"body": "no title"}, headers=h).status_code == 400


def test_ticket_update_missing_returns_404(client):
    c, _ = client
    h = _register_login(c, "iris")
    assert c.patch("/api/tickets/9999", json={"status": "closed"}, headers=h).status_code == 404


def test_ticket_admin_can_edit_others(client):
    c, app = client
    h = _register_login(c, "jack")
    tid = c.post("/api/tickets", json={"title": "printer"}, headers=h).get_json()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"status": "closed"}, headers=_admin_headers(app))
    assert r.status_code == 200 and r.get_json()["status"] == "closed"


def test_ticket_cross_user_forbidden_and_row_unchanged(client):
    c, _ = client
    h_a = _register_login(c, "mona")
    tid = c.post("/api/tickets", json={"title": "secret"}, headers=h_a).get_json()["id"]
    h_b = _register_login(c, "nate")
    assert c.patch(f"/api/tickets/{tid}", json={"status": "closed"}, headers=h_b).status_code == 403
    # owner still sees the untouched row
    r = c.patch(f"/api/tickets/{tid}", json={"body": "still mine"}, headers=h_a)
    assert r.get_json()["status"] == "open"


def test_ticket_owner_id_not_mass_assignable(client):
    c, _ = client
    h = _register_login(c, "olive")
    tid = c.post("/api/tickets", json={"title": "mine"}, headers=h).get_json()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"owner_id": 999, "assignee": "pete"}, headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["owner_id"] != 999
    assert body["assignee"] is None  # not an editable field


# ---------------------------------------------------------------------------
# app/webhooks.py — the exact allowed host still works
# ---------------------------------------------------------------------------


def test_webhook_allowed_host_posts_ping(client):
    c, _ = client
    h = _register_login(c, "kate")
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 200
        r = c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/hook"}, headers=h)
    assert r.status_code == 200 and r.get_json()["status"] == 200
    post.assert_called_once()
    args, kwargs = post.call_args
    assert args[0] == "https://hooks.vaultdesk.example/hook"
    assert kwargs.get("json") == {"event": "ping"}
    assert kwargs.get("allow_redirects") is False


def test_webhook_allowed_host_with_443_port(client):
    c, _ = client
    h = _register_login(c, "liam")
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 204
        r = c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example:443/hook"}, headers=h)
    assert r.status_code == 200 and r.get_json()["status"] == 204


def test_webhook_requires_auth(client):
    c, _ = client
    assert c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/x"}).status_code == 401


def test_webhook_rejects_non_https_without_posting(client):
    c, _ = client
    h = _register_login(c, "leo")
    with mock.patch("app.webhooks.requests.post") as post:
        r = c.post("/api/webhooks/test", json={"url": "http://hooks.vaultdesk.example/x"}, headers=h)
    assert r.status_code == 400
    post.assert_not_called()
