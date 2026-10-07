import pytest
from fastapi.testclient import TestClient

from app import db, config
from app.web import app


@pytest.fixture()
def fresh_setup():
    with db._connect() as conn:
        conn.execute("DELETE FROM app_settings")
        conn.executemany(
            "INSERT INTO app_settings (key, value) VALUES (?, ?)",
            [("admin_setup", "required"), ("setup_token", "test-setup-key")],
        )
    yield
    with db._connect() as conn:
        conn.execute("DELETE FROM app_settings")
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('admin_setup', 'complete')")


@pytest.fixture()
def admin_client():
    # Enable admin creds for the duration of this fixture.
    admin_user = "admin"
    admin_pass = "secret"
    real_user = config.WEB_ADMIN_USER
    real_pass = config.WEB_ADMIN_PASS
    config.WEB_ADMIN_USER = admin_user
    config.WEB_ADMIN_PASS = admin_pass
    try:
        with TestClient(app) as c:
            yield c, admin_user, admin_pass
    finally:
        config.WEB_ADMIN_USER = real_user
        config.WEB_ADMIN_PASS = real_pass



@pytest.fixture()
def seed_two_ips():
    db.record_event("connect", "203.0.113.9", 51234, client_version="SSH-2.0-libssh2_1.10")
    db.record_event(
        "password", "203.0.113.9", 51234,
        username="root", detail="123456", client_version="SSH-2.0-libssh2_1.10",
    )
    db.record_event("connect", "198.51.100.7", 40000)
    # One older event for retention tests: tamper its ts backwards.
    with db._connect() as conn:
        conn.execute(
            "UPDATE events SET ts = ? WHERE ip = '203.0.113.9' AND event = 'connect' AND ip_port = 51234",
            ("2020-01-01T00:00:00Z",),
        )
    return db.get_summary()


def _basic_auth(user, pass_):
    import base64
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pass_}".encode()).decode()}


class TestFirstRunAdminSetup:
    def test_fresh_install_routes_to_setup_and_creates_persisted_admin(self, fresh_setup):
        config.WEB_ADMIN_USER = ""
        config.WEB_ADMIN_PASS = ""
        with TestClient(app) as c:
            setup = c.get("/", follow_redirects=False)
            assert setup.status_code == 303
            assert setup.headers["location"] == "/setup?key=test-setup-key"
            assert c.get("/setup").status_code == 404
            page = c.get("/setup?key=test-setup-key")
            assert page.status_code == 200
            assert page.headers["cache-control"] == "no-store"
            assert "Create admin account" in page.text
            missing_key = c.post("/setup", data={
                "username": "owner",
                "password": "a-long-first-run-password",
                "password_confirm": "a-long-first-run-password",
            })
            assert missing_key.status_code == 404
            assert db.admin_setup_required()

            invalid = c.post("/setup", data={
                "username": "owner",
                "password": "short",
                "password_confirm": "short",
                "setup_key": "test-setup-key",
            })
            assert invalid.status_code == 400
            assert "at least 12 characters" in invalid.text
            assert db.admin_setup_required()

            password = "a-long-first-run-password"
            created = c.post("/setup", data={
                "username": "owner",
                "password": password,
                "password_confirm": password,
                "setup_key": "test-setup-key",
            }, follow_redirects=False)
            assert created.status_code == 303
            assert created.headers["location"] == "/"
            assert not db.admin_setup_required()
            stored = db.admin_credentials()
            assert stored["username"] == "owner"
            assert stored["password_hash"] != password
            assert password not in str(stored)

            assert c.get("/", follow_redirects=False).status_code == 401
            assert c.get("/api/stats").status_code == 401
            assert c.get("/api/stats", auth=("owner", password)).status_code == 200
            assert c.get("/", auth=("owner", password)).status_code == 200
            event_id = db.record_event("connect", "203.0.113.10")
            deleted = c.delete(f"/api/events/{event_id}", auth=("owner", password))
            assert deleted.status_code == 200
            assert db.get_summary()["recent"] == []
            assert c.get("/setup?key=test-setup-key", follow_redirects=False).status_code == 303
            assert c.post("/setup", data={
                "username": "attacker",
                "password": password,
                "password_confirm": password,
                "setup_key": "test-setup-key",
            }).status_code == 409
            assert db.admin_credentials()["username"] == "owner"

    def test_setup_password_confirmation_required(self, fresh_setup):
        with TestClient(app) as c:
            response = c.post("/setup", data={
                "username": "owner",
                "password": "a-long-first-run-password",
                "password_confirm": "a-different-long-password",
                "setup_key": "test-setup-key",
            })
            assert response.status_code == 400
            assert "confirmation does not match" in response.text
            assert db.admin_setup_required()


class TestAdminAuthGate:
    def test_dashboard_prompts_for_login_and_protects_data_routes(self, admin_client):
        c, user, password = admin_client
        page = c.get("/")
        assert page.status_code == 401
        assert page.headers["www-authenticate"].startswith("Basic realm=")
        assert "Authentication required" in page.text
        assert c.get("/api/stats").status_code == 401
        assert c.get("/api/ips").status_code == 401
        assert c.get("/ssh-blocklist.txt").status_code == 401
        assert c.get("/export.csv").status_code == 401
        assert c.request("DELETE", "/api/events/all").status_code == 401

        authenticated = c.get("/", headers=_basic_auth(user, password))
        assert authenticated.status_code == 200
        assert "timezone-select" in authenticated.text
        assert "format-select" in authenticated.text
        assert password not in authenticated.text

    def test_purge_without_auth_returns_401(self):
        with TestClient(app) as c:
            config.WEB_ADMIN_USER = "u"
            config.WEB_ADMIN_PASS = "p"
            try:
                res = c.request("DELETE", "/api/events")
                assert res.status_code == 401
                assert res.json()["detail"] == "admin auth required"
            finally:
                config.WEB_ADMIN_USER = ""
                config.WEB_ADMIN_PASS = ""

    def test_purge_disabled_when_no_creds(self):
        config.WEB_ADMIN_USER = ""
        config.WEB_ADMIN_PASS = ""
        try:
            with TestClient(app) as c:
                res = c.request("DELETE", "/api/events")
                assert res.status_code == 404
        finally:
            config.WEB_ADMIN_USER = ""
            config.WEB_ADMIN_PASS = ""

    def test_delete_event_without_auth_returns_401(self):
        with TestClient(app) as c:
            config.WEB_ADMIN_USER = "u"
            config.WEB_ADMIN_PASS = "p"
            try:
                res = c.request("DELETE", "/api/events/1")
                assert res.status_code == 401
                assert res.json()["detail"] == "admin auth required"
            finally:
                config.WEB_ADMIN_USER = ""
                config.WEB_ADMIN_PASS = ""

    def test_delete_event_disabled_when_no_creds(self):
        config.WEB_ADMIN_USER = ""
        config.WEB_ADMIN_PASS = ""
        try:
            with TestClient(app) as c:
                res = c.request("DELETE", "/api/events/1")
                assert res.status_code == 404
        finally:
            config.WEB_ADMIN_USER = ""
            config.WEB_ADMIN_PASS = ""


class TestAdminDeleteEvent:
    def test_delete_all_events(self, admin_client, seed_two_ips):
        c, user, password = admin_client
        response = c.request("DELETE", "/api/events/all", headers=_basic_auth(user, password))
        assert response.status_code == 200
        assert response.json() == {"ok": True, "deleted": 3}
        assert db.get_summary()["recent"] == []

    def test_delete_event_by_id(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        rows_before = db.get_summary()["recent"]
        target = rows_before[0]["id"]

        res = c.request(
            "DELETE",
            f"/api/events/{target}",
            headers=_basic_auth(user, pass_),
        )
        assert res.status_code == 200
        assert res.json()["deleted"] == target
        assert res.json()["ok"] is True

        # The event is gone from the DB.
        remaining = [e for e in db.get_summary()["recent"] if e["id"] == target]
        assert remaining == []

    def test_delete_nonexistent_event_returns_404(self, admin_client):
        c, user, pass_ = admin_client
        res = c.request(
            "DELETE",
            "/api/events/999999",
            headers=_basic_auth(user, pass_),
        )
        assert res.status_code == 404
        assert res.json()["detail"] == "event not found"


class TestAdminPurge:
    def test_purge_by_ips(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        res = c.request(
            "DELETE",
            "/api/events",
            headers=_basic_auth(user, pass_),
            params={"ips": "203.0.113.9"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ips"] == ["203.0.113.9"]
        assert body["removed_ips"] >= 1  # at least the two 203 rows
        assert body["removed_older_than_hours"] == 0

        # Only 198.51.100.7 remains.
        ips = {r["ip"] for r in db.get_ip_rows()}
        assert ips == {"198.51.100.7"}

    def test_purge_by_age(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        # The seed puts one row back in 2020; purge anything older than 1 hour.
        res = c.request(
            "DELETE",
            "/api/events",
            headers=_basic_auth(user, pass_),
            params={"older_than_hours": 1},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["older_than_hours"] == 1
        assert body["removed_older_than_hours"] >= 1
        assert body["removed_ips"] == 0

        # All remaining rows are recent.
        recent = db.get_summary()["recent"]
        for e in recent:
            assert e["ts"] >= "2020-02-01T00:00:00Z"  # not the 2020 row

    def test_purge_combined(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        res = c.request(
            "DELETE",
            "/api/events",
            headers=_basic_auth(user, pass_),
            params={"ips": "198.51.100.7", "older_than_hours": 1},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["total_removed"] == body["removed_ips"] + body["removed_older_than_hours"]
        # Only 203.0.113.9 recent rows should remain.
        ips = {r["ip"] for r in db.get_ip_rows()}
        assert ips == {"203.0.113.9"}

    def test_purge_invalid_older_than_hours(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        res = c.request(
            "DELETE",
            "/api/events",
            headers=_basic_auth(user, pass_),
            params={"older_than_hours": "not-a-number"},
        )
        assert res.status_code == 200
        assert res.json()["error"] == "older_than_hours must be an integer"


class TestRetentionCount:
    def test_count_events_older_than(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        older = db.count_events_older_than(1)
        # The seed has one row dated 2020-01-01, which is older than 1h.
        assert older >= 1


class TestDashboardAfterDeletion:
    def test_dashboard_no_longer_shows_deleted_event(self, admin_client, seed_two_ips):
        c, user, pass_ = admin_client
        target = db.get_summary()["recent"][0]["id"]
        c.request(
            "DELETE",
            f"/api/events/{target}",
            headers=_basic_auth(user, pass_),
        )
        res = c.get("/", headers=_basic_auth(user, pass_))
        assert res.status_code == 200
        html = res.text
        # The deleted event's id shouldn't appear in a data-id attribute.
        assert f'data-id="{target}"' not in html
