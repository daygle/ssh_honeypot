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
    return int(raw)


# Storage -------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("DATA_DIR", "data")).expanduser()
DB_PATH = Path(os.environ.get("DB_PATH", str(DATA_DIR / "honeypot.db")))
HOST_KEY_PATH = Path(os.environ.get("HOST_KEY_PATH", str(DATA_DIR / "host_key")))

# Honeypot (decoy SSH listener) ---------------------------------------------

HONEYPOT_ENABLED = _flag("HONEYPOT_ENABLED", True)
HONEYPOT_HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
HONEYPOT_PORT = _int("HONEYPOT_PORT", 22)
# Advertised SSH banner. Many scanners fingerprint the server first; a
# plausibly boring banner keeps them talking.
HONEYPOT_BANNER = os.environ.get("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

# Dashboard -----------------------------------------------------------------

WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
# Freebuff previews inject PORT; standalone runs use WEB_PORT.
WEB_PORT = _int("WEB_PORT", _int("PORT", 8080))
