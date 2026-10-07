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


def test_events_csv_neutralises_formula_injection():
    db.record_event("password", "203.0.113.9", username="=HYPERLINK(\"http://x\")", detail="+1-2", client_version="@SUM")
    db.record_event("password", "203.0.113.9", username="root", detail="-")

    lines = db.events_csv().splitlines()

    assert "'=HYPERLINK" in lines[1]
    assert ",'+1-2," in lines[1]
    assert lines[1].endswith(",'@SUM")
    assert ",root,'-," in lines[2]


def test_events_csv_streams_in_batches():
    for i in range(5):
        db.record_event("connect", f"203.0.113.{i}")

    chunks = list(db.iter_events_csv(batch_size=2))

    assert len(chunks) == 3
    assert "".join(chunks).count("\n") == 6


def test_attacker_controlled_fields_are_capped():
    huge = "A" * 100_000
    event_id = db.record_event("password", "203.0.113.9", username=huge, detail=huge)
    db.set_client_version(event_id, huge)

    row = db.get_summary()["recent"][0]
    assert len(row["username"]) == db.MAX_FIELD_LEN
    assert len(row["detail"]) == db.MAX_FIELD_LEN
    assert len(row["client_version"]) == db.MAX_FIELD_LEN


def test_top_ips_ranked_by_connections():
    for _ in range(3):
        db.record_event("connect", "203.0.113.9")
    db.record_event("connect", "198.51.100.7")

    top = db.get_summary(top_limit=1)["top_ips"]

    assert [r["ip"] for r in top] == ["203.0.113.9"]
    assert top[0]["connections"] == 3


def test_empty_database_summary():
    summary = db.get_summary()

    assert summary["connections_total"] == 0
    assert summary["last_seen"] is None
    assert summary["last_event"] is None
    assert db.blocklist_text() == ""
    assert db.events_csv().strip() == "timestamp_utc,ip,ip_port,event,username,detail,client_version"


def test_init_db_marks_existing_events_database_as_legacy_setup_complete():
    db.init_db()
    assert not db.admin_setup_required()
    assert db.setup_token() is None
    db.record_event("connect", "203.0.113.9")
    db.init_db()
    assert len(db.get_summary()["recent"]) == 1
    assert not db.admin_setup_required()


def test_init_db_migrates_legacy_indexes():
    with db._connect() as conn:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip)")

    db.init_db()

    names = {r["name"] for r in db._connect().execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert "idx_events_ip" not in names
    assert {"idx_events_ip_event_ts", "idx_events_event_ts"} <= names
