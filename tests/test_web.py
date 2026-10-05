import pytest
from fastapi.testclient import TestClient

from app import db
from app.web import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _seed():
    db.record_event("connect", "203.0.113.9", 51234, client_version="SSH-2.0-libssh2_1.10")
    db.record_event(
        "password", "203.0.113.9", 51234,
        username="root", detail="123456", client_version="SSH-2.0-libssh2_1.10",
    )
    db.record_event("connect", "198.51.100.7", 40000)


def test_dashboard_renders_ip_list(client):
    _seed()

    res = client.get("/")

    assert res.status_code == 200
    html = res.text
    assert "Daygle SSH Honeypot" in html
    assert "203.0.113.9" in html
    assert "198.51.100.7" in html
    assert "root" in html
    assert "123456" in html


def test_dashboard_shows_empty_state(client):
    res = client.get("/")

    assert res.status_code == 200
    assert "No attempts recorded yet" in res.text


def test_api_stats(client):
    _seed()

    stats = client.get("/api/stats").json()

    assert stats["connections_total"] == 2
    assert stats["unique_ips"] == 2
    assert stats["auth_total"] == 1
    assert len(stats["hourly"]) == 24
    assert stats["top_ips"][0]["ip"] in {"203.0.113.9", "198.51.100.7"}
    assert len(stats["recent"]) == 3


def test_api_ips(client):
    _seed()

    rows = client.get("/api/ips").json()

    assert {r["ip"] for r in rows} == {"203.0.113.9", "198.51.100.7"}


def test_blocklist_txt(client):
    _seed()

    res = client.get("/ssh-blocklist.txt")

    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/plain")
    assert set(res.text.splitlines()) == {"203.0.113.9", "198.51.100.7"}

    # The endpoint was renamed; the old path must be gone.
    assert client.get("/blocklist.txt").status_code == 404


def test_export_csv(client):
    _seed()

    res = client.get("/export.csv")

    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    lines = res.text.strip().splitlines()
    assert lines[0].startswith("timestamp_utc,ip,ip_port,event")
    assert len(lines) == 4


def test_healthz(client):
    res = client.get("/healthz")

    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_security_headers_and_csp_nonce(client):
    res = client.get("/")

    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    csp = res.headers["content-security-policy"]
    nonce = csp.split("'nonce-", 1)[1].split("'", 1)[0]
    assert f'<script nonce="{nonce}">' in res.text
    assert client.get("/healthz").headers["x-content-type-options"] == "nosniff"


def test_dashboard_escapes_attacker_strings(client):
    db.record_event("password", "203.0.113.9", username="<script>alert(1)</script>", detail="x")

    res = client.get("/")

    assert "<script>alert(1)</script>" not in res.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in res.text


def test_api_docs_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
