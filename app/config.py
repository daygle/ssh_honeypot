"""Runtime configuration, read once from environment variables."""

from __future__ import annotations

import os
from pathlib import Path


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def _positive_int(name: str, default: int) -> int:
    """Like _int but rejects values below 1 (for retention-visible ceilings)."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if value < 1:
        raise ValueError(f"{name} must be >= 1, got {value}") from None
    return value


# Storage -------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("DATA_DIR", "data")).expanduser()
DB_PATH = Path(os.environ.get("DB_PATH", str(DATA_DIR / "honeypot.db")))
HOST_KEY_PATH = Path(os.environ.get("HOST_KEY_PATH", str(DATA_DIR / "host_key")))

# Honeypot (decoy SSH listener) ---------------------------------------------

HONEYPOT_ENABLED = _flag("HONEYPOT_ENABLED", True)
HONEYPOT_HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
HONEYPOT_PORT = _int("HONEYPOT_PORT", 22)
# Advertised SSH banner. Many scanners fingerprint the server first; a
# plausibly boring banner keeps them talking. Exclude the "SSH-2.0-" protocol
# prefix: asyncssh adds it when composing the wire banner, so including it here
# would emit a doubled "SSH-2.0-SSH-2.0-..." that gives the decoy away.
HONEYPOT_BANNER = os.environ.get("HONEYPOT_BANNER", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

# Dashboard -----------------------------------------------------------------

WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
# Some hosting platforms inject PORT; standalone runs use WEB_PORT.
WEB_PORT = _int("WEB_PORT", _int("PORT", 8080))

# Admin / deletion ----------------------------------------------------------
# Basic-auth credentials for the admin deletion/purge endpoints. If either
# is empty the admin endpoints are disabled (return 404) so a default
# install is not accidentally exposed.
WEB_ADMIN_USER = os.environ.get("WEB_ADMIN_USER", "").strip()
WEB_ADMIN_PASS = os.environ.get("WEB_ADMIN_PASS", "").strip()

# Retention ------------------------------------------------------------------
# Auto-purge events older than this many hours. Set to 0 to disable automatic
# purging (manual purge endpoints are still available to admins).
RETENTION_HOURS = _int("RETENTION_HOURS", 0)

# Dashboard display preferences ------------------------------------------------
# Jinja date/time format used for event timestamps, feed timestamps and the
# generated-at footer line. Defaults to the existing UTC space-separated form.
DATE_FORMAT = os.environ.get("DATE_FORMAT", "%Y-%m-%d %H:%M:%S %Z")
# Relative-time style used for "last seen" / hero hints. One of:
#   "compact"  -> 2h ago / 3d ago
#   "verbose"  -> 2 hours ago / 3 days ago
RELATIVE_FORMAT = os.environ.get("RELATIVE_FORMAT", "compact")
