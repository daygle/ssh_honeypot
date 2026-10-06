import pytest
from fastapi.testclient import TestClient

from app import db, config
from app.web import app


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


class TestAdminAuthGate:
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
        res = c.get("/")
        assert res.status_code == 200
        html = res.text
        # The deleted event's id shouldn't appear in a data-id attribute.
        assert f'data-id="{target}"' not in html
