"""SQLite storage for honeypot connection events.

Every row is one observed event (a TCP connection, or a credential attempt).
Aggregations used by the dashboard are derived at query time, so there is no
cron job and nothing to truncate/reinsert.
"""

from __future__ import annotations

import csv
import io
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Optional

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    ip_port INTEGER,
    event TEXT NOT NULL,
    username TEXT,
    detail TEXT,
    client_version TEXT
);
-- Superseded by the covering indexes below.
DROP INDEX IF EXISTS idx_events_ip;
DROP INDEX IF EXISTS idx_events_ts;
-- Covers the per-IP aggregates without touching the table.
CREATE INDEX IF NOT EXISTS idx_events_ip_event_ts ON events (ip, event, ts);
-- Covers the hourly connection histogram.
CREATE INDEX IF NOT EXISTS idx_events_event_ts ON events (event, ts);
"""

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Attacker-controlled strings are capped so a single client cannot bloat the
# database (or the dashboard) with megabyte-sized usernames or banners.
MAX_FIELD_LEN = 512

CSV_HEADER = ("timestamp_utc", "ip", "ip_port", "event", "username", "detail", "client_version")

# Spreadsheet apps evaluate cells starting with these as formulas.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_IP_AGGREGATE_SQL = """
    SELECT ip,
           SUM(event = 'connect') AS connections,
           SUM(event IN ('password', 'pubkey')) AS auth_attempts,
           MIN(ts) AS first_seen,
           MAX(ts) AS last_seen
    FROM events
    GROUP BY ip
    ORDER BY last_seen DESC
"""

_local = threading.local()


def _open() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _connect() -> sqlite3.Connection:
    """Return this thread's cached connection, opening it on first use.

    Use as ``with _connect() as conn:`` - the block commits on success and
    rolls back on error; the connection itself stays open for reuse.
    """
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _local.conn = _open()
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(SCHEMA)


def _fmt(dt: datetime) -> str:
    return dt.strftime(TS_FORMAT)


def now_iso() -> str:
    return _fmt(datetime.now(timezone.utc))


def _clip(value: Optional[str]) -> Optional[str]:
    if value is None or len(value) <= MAX_FIELD_LEN:
        return value
    return value[:MAX_FIELD_LEN]


def record_event(
    event: str,
    ip: str,
    ip_port: Optional[int] = None,
    username: Optional[str] = None,
    detail: Optional[str] = None,
    client_version: Optional[str] = None,
) -> int:
    """Insert one event row and return its id."""
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO events (ts, ip, ip_port, event, username, detail, client_version)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now_iso(), ip, ip_port, event, _clip(username), _clip(detail), _clip(client_version)),
        )
        return int(cur.lastrowid)


def set_client_version(event_id: int, client_version: Optional[str]) -> None:
    """Fill in the client banner once the SSH version exchange has completed."""
    if not client_version:
        return
    with _connect() as conn:
        conn.execute(
            "UPDATE events SET client_version = ? WHERE id = ? AND client_version IS NULL",
            (_clip(client_version), event_id),
        )


def _ip_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(_IP_AGGREGATE_SQL)]


def get_ip_rows() -> list[dict[str, Any]]:
    """Per-IP aggregates, most recently seen first."""
    return _ip_rows(_connect())


def _hourly(conn: sqlite3.Connection, hours: int) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    rows = conn.execute(
        """
        SELECT substr(ts, 1, 13) AS bucket, COUNT(*) AS count
        FROM events
        WHERE event = 'connect' AND ts >= ?
        GROUP BY bucket
        """,
        (_fmt(start),),
    ).fetchall()
    counts = {r["bucket"]: r["count"] for r in rows}
    out: list[dict[str, Any]] = []
    for i in range(hours):
        t = start + timedelta(hours=i)
        out.append({"label": t.strftime("%H:00"), "count": counts.get(t.strftime("%Y-%m-%dT%H"), 0)})
    return out


def get_hourly_connections(hours: int = 24) -> list[dict[str, Any]]:
    """Connection counts bucketed by hour, gaps filled with zero."""
    return _hourly(_connect(), hours)


def get_summary(recent_limit: int = 25, top_limit: int = 8) -> dict[str, Any]:
    """Everything the dashboard needs, in one call."""
    cutoff = _fmt(datetime.now(timezone.utc) - timedelta(hours=24))
    conn = _connect()
    totals = conn.execute(
        """
        SELECT
            SUM(event = 'connect') AS connections_total,
            SUM(event = 'connect' AND ts >= :cutoff) AS connections_24h,
            SUM(event IN ('password', 'pubkey')) AS auth_total,
            SUM(event IN ('password', 'pubkey') AND ts >= :cutoff) AS auth_24h,
            COUNT(DISTINCT ip) AS unique_ips,
            COUNT(DISTINCT CASE WHEN ts >= :cutoff THEN ip END) AS unique_ips_24h,
            MAX(ts) AS last_seen
        FROM events
        """,
        {"cutoff": cutoff},
    ).fetchone()
    recent = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (recent_limit,))]
    ips = _ip_rows(conn)
    hourly = _hourly(conn, 24)

    # Derived from the per-IP rows rather than a second GROUP BY pass.
    top_ips = sorted(ips, key=lambda r: (r["connections"], r["last_seen"]), reverse=True)[:top_limit]
    counts = {k: totals[k] or 0 for k in
              ("connections_total", "connections_24h", "auth_total", "auth_24h", "unique_ips", "unique_ips_24h")}
    return {
        "generated_at": now_iso(),
        **counts,
        "last_seen": totals["last_seen"],
        "last_event": recent[0] if recent else None,
        "top_ips": top_ips,
        "recent": recent,
        "hourly": hourly,
        "ips": ips,
    }


def blocklist_text() -> str:
    """Unique source IPs, one per line, most recently seen first."""
    rows = _connect().execute("SELECT ip FROM events GROUP BY ip ORDER BY MAX(ts) DESC").fetchall()
    return "".join(f"{r['ip']}\n" for r in rows)


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in attacker-supplied text."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def iter_events_csv(batch_size: int = 1000) -> Iterator[str]:
    """Yield the full event log as CSV, one chunk per batch of rows.

    Uses a dedicated connection because a streaming response may resume the
    generator on a different worker thread each time.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADER)
    conn = _open()
    try:
        cur = conn.execute(
            "SELECT ts, ip, ip_port, event, username, detail, client_version FROM events ORDER BY id ASC"
        )
        while True:
            rows = cur.fetchmany(batch_size)
            if not rows:
                break
            writer.writerows([_csv_safe(v) for v in row] for row in rows)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
    finally:
        conn.close()
    if buf.tell():
        yield buf.getvalue()


def events_csv() -> str:
    return "".join(iter_events_csv())


# Deletion helpers -----------------------------------------------------------

def delete_event(event_id: int) -> bool:
    """Delete a single event by id. Returns True if a row was removed."""
    with _connect() as conn:
        cur = conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
        return bool(cur.rowcount)


def delete_events_for_ips(ips: list[str]) -> int:
    """Delete all events whose source IP is in `ips`. Returns rows removed."""
    if not ips:
        return 0
    with _connect() as conn:
        conn.execute("DELETE FROM events WHERE ip IN ({})".format(", ".join("?" * len(ips))), ips)
        return int(conn.total_changes - getattr(conn, "_prev_total_changes", 0))


def delete_events_older_than(hours: int) -> int:
    """Delete events older than `hours` hours. Returns rows removed."""
    if hours <= 0:
        return 0
    with _connect() as conn:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(TS_FORMAT)
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        return int(cur.rowcount)


def count_events_older_than(hours: int) -> int:
    """How many events are older than `hours` hours (for retention UI)."""
    if hours <= 0:
        return 0
    conn = _connect()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(TS_FORMAT)
    row = conn.execute("SELECT COUNT(*) AS c FROM events WHERE ts < ?", (cutoff,)).fetchone()
    return int(row["c"]) if row else 0

