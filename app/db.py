"""SQLite storage for honeypot connection events.

Every row is one observed event (a TCP connection, or a credential attempt).
Aggregations used by the dashboard are derived at query time, so there is no
cron job and nothing to truncate/reinsert.
"""

from __future__ import annotations

import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

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
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
"""

AUTH_EVENTS = ("password", "pubkey")


def _connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(SCHEMA)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cutoff_iso(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


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
            (now_iso(), ip, ip_port, event, username, detail, client_version),
        )
        return int(cur.lastrowid)


def set_client_version(event_id: int, client_version: Optional[str]) -> None:
    """Fill in the client banner once the SSH version exchange has completed."""
    if not client_version:
        return
    with _connect() as conn:
        conn.execute(
            "UPDATE events SET client_version = ? WHERE id = ? AND client_version IS NULL",
            (client_version, event_id),
        )


def get_ip_rows() -> list[dict[str, Any]]:
    """Per-IP aggregates, most recently seen first."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ip,
                   SUM(CASE WHEN event = 'connect' THEN 1 ELSE 0 END) AS connections,
                   SUM(CASE WHEN event IN ('password', 'pubkey') THEN 1 ELSE 0 END) AS auth_attempts,
                   MIN(ts) AS first_seen,
                   MAX(ts) AS last_seen
            FROM events
            GROUP BY ip
            ORDER BY last_seen DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def get_hourly_connections(hours: int = 24) -> list[dict[str, Any]]:
    """Connection counts bucketed by hour, gaps filled with zero."""
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT substr(ts, 1, 13) AS bucket, COUNT(*) AS count
            FROM events
            WHERE event = 'connect' AND ts >= ?
            GROUP BY bucket
            """,
            (start.strftime("%Y-%m-%dT%H:%M:%SZ"),),
        ).fetchall()
    counts = {r["bucket"]: r["count"] for r in rows}
    out: list[dict[str, Any]] = []
    for i in range(hours):
        t = start + timedelta(hours=i)
        out.append(
            {
                "label": t.strftime("%H:00"),
                "count": counts.get(t.strftime("%Y-%m-%dT%H"), 0),
            }
        )
    return out


def get_summary(recent_limit: int = 25, top_limit: int = 8) -> dict[str, Any]:
    """Everything the dashboard needs, in one call."""
    cutoff = cutoff_iso(24)
    with _connect() as conn:
        totals = conn.execute(
            """
            SELECT
                SUM(CASE WHEN event = 'connect' THEN 1 ELSE 0 END) AS connections_total,
                SUM(CASE WHEN event = 'connect' AND ts >= ? THEN 1 ELSE 0 END) AS connections_24h,
                SUM(CASE WHEN event IN ('password', 'pubkey') THEN 1 ELSE 0 END) AS auth_total,
                SUM(CASE WHEN event IN ('password', 'pubkey') AND ts >= ? THEN 1 ELSE 0 END) AS auth_24h,
                COUNT(DISTINCT ip) AS unique_ips,
                COUNT(DISTINCT CASE WHEN ts >= ? THEN ip END) AS unique_ips_24h,
                MAX(ts) AS last_seen
            FROM events
            """,
            (cutoff, cutoff, cutoff),
        ).fetchone()
        last_event = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1").fetchone()
        top_ips = conn.execute(
            """
            SELECT ip,
                   SUM(CASE WHEN event = 'connect' THEN 1 ELSE 0 END) AS connections,
                   SUM(CASE WHEN event IN ('password', 'pubkey') THEN 1 ELSE 0 END) AS auth_attempts,
                   MIN(ts) AS first_seen,
                   MAX(ts) AS last_seen
            FROM events
            GROUP BY ip
            ORDER BY connections DESC, last_seen DESC
            LIMIT ?
            """,
            (top_limit,),
        ).fetchall()
        recent = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (recent_limit,)
        ).fetchall()

    zero = {"connections_total": 0, "connections_24h": 0, "auth_total": 0,
            "auth_24h": 0, "unique_ips": 0, "unique_ips_24h": 0, "last_seen": None}
    counts = {k: (totals[k] if totals[k] is not None else v) for k, v in zero.items()}
    return {
        "generated_at": now_iso(),
        **counts,
        "last_event": dict(last_event) if last_event else None,
        "top_ips": [dict(r) for r in top_ips],
        "recent": [dict(r) for r in recent],
        "hourly": get_hourly_connections(),
        "ips": get_ip_rows(),
    }


def blocklist_text() -> str:
    """Unique source IPs, one per line (same shape as the old page)."""
    ips = [row["ip"] for row in get_ip_rows()]
    return "\n".join(ips) + ("\n" if ips else "")


def events_csv() -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp_utc", "ip", "ip_port", "event", "username", "detail", "client_version"])
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, ip, ip_port, event, username, detail, client_version FROM events ORDER BY id ASC"
        ).fetchall()
    for r in rows:
        writer.writerow([r["ts"], r["ip"], r["ip_port"], r["event"], r["username"], r["detail"], r["client_version"]])
    return buf.getvalue()
