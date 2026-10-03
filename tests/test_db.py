from app import db


def test_records_events_and_summarizes():
    db.record_event("connect", "203.0.113.9", 51234, client_version="SSH-2.0-libssh2_1.10")
    db.record_event(
        "password", "203.0.113.9", 51234,
        username="root", detail="hunter2", client_version="SSH-2.0-libssh2_1.10",
    )
    db.record_event("connect", "198.51.100.7", 40000)

    summary = db.get_summary()

    assert summary["connections_total"] == 2
    assert summary["connections_24h"] == 2
    assert summary["auth_total"] == 1
    assert summary["auth_24h"] == 1
    assert summary["unique_ips"] == 2
    assert summary["unique_ips_24h"] == 2
    assert summary["last_seen"] is not None
    assert summary["last_event"]["ip"] == "198.51.100.7"

    assert len(summary["recent"]) == 3
    assert sum(b["count"] for b in summary["hourly"]) == 2
    assert len(summary["hourly"]) == 24


def test_ip_aggregates_order_and_counts():
    db.record_event("connect", "203.0.113.9")
    db.record_event("connect", "203.0.113.9")
    db.record_event("pubkey", "203.0.113.9", username="admin", detail="SHA256:abc")
    db.record_event("connect", "198.51.100.7")

    rows = db.get_ip_rows()
    ips = [r["ip"] for r in rows]

    assert set(ips) == {"203.0.113.9", "198.51.100.7"}
    top = next(r for r in rows if r["ip"] == "203.0.113.9")
    assert top["connections"] == 2
    assert top["auth_attempts"] == 1
    assert top["first_seen"] is not None


def test_blocklist_text_lists_unique_ips_one_per_line():
    db.record_event("connect", "203.0.113.9")
    db.record_event("connect", "203.0.113.9")
    db.record_event("connect", "198.51.100.7")

    text = db.blocklist_text()

    assert text.splitlines() == ["198.51.100.7", "203.0.113.9"]
    assert text.endswith("\n")


def test_events_csv_export():
    db.record_event("connect", "203.0.113.9", 2222, client_version="SSH-2.0-test")

    csv_text = db.events_csv()
    lines = csv_text.strip().splitlines()

    assert lines[0] == "timestamp_utc,ip,ip_port,event,username,detail,client_version"
    assert len(lines) == 2
    assert "203.0.113.9" in lines[1]


def test_set_client_version_fills_missing_banner():
    event_id = db.record_event("connect", "203.0.113.9")

    db.set_client_version(event_id, "SSH-2.0-OpenSSH_9.6")
    db.set_client_version(event_id, "SSH-2.0-should-not-overwrite")

    row = db.get_summary()["recent"][0]
    assert row["client_version"] == "SSH-2.0-OpenSSH_9.6"
