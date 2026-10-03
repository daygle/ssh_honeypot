"""Decoy SSH service that records every connection attempt.

This is a logger, not an emulator: it never authenticates anyone and never
opens a shell. Each TCP connection is recorded the moment it arrives (so even
non-SSH garbage probes are captured), credential guesses are stored with the
attempted username, and the client banner is filled in once the SSH version
exchange completes.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import asyncssh

from . import config, db

log = logging.getLogger("daygle.honeypot")


def _peer(conn: Any) -> tuple[str, Optional[int]]:
    peer = conn.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return str(peer[0]), int(peer[1])
    return (str(peer) if peer else "unknown"), None


def _client_version(conn: Any) -> Optional[str]:
    raw = conn.get_extra_info("client_version")
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw) if raw else None


class DaygleSSHServer(asyncssh.SSHServer):
    """Records connection metadata and credential guesses; grants nothing."""

    def connection_made(self, conn: Any) -> None:
        self._conn = conn
        self._ip, self._port = _peer(conn)
        self._event_id: Optional[int] = None
        try:
            self._event_id = db.record_event("connect", self._ip, self._port)
        except Exception:
            log.exception("failed to record connect event")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        try:
            if self._event_id is not None:
                db.set_client_version(self._event_id, _client_version(self._conn))
        except Exception:
            log.exception("failed to update client banner")

    def begin_auth(self, username: str) -> bool:
        # Always require authentication so the session is always refused.
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self._record("password", username, password)
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: Any) -> bool:
        fingerprint = "unknown"
        try:
            fingerprint = key.get_fingerprint()
        except Exception:
            pass
        self._record("pubkey", username, fingerprint)
        return False

    def _record(self, event: str, username: str, detail: str) -> None:
        try:
            db.record_event(
                event,
                getattr(self, "_ip", "unknown"),
                getattr(self, "_port", None),
                username=username,
                detail=detail,
                client_version=_client_version(self._conn),
            )
        except Exception:
            log.exception("failed to record %s event", event)


def _load_or_create_host_key() -> Any:
    path = config.HOST_KEY_PATH
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(path))
        path.chmod(0o600)
        log.info("generated new host key at %s", path)
    return asyncssh.read_private_key(str(path))


async def start() -> Any:
    """Start the decoy SSH listener; returns the acceptor."""
    if not config.HONEYPOT_ENABLED:
        log.info("honeypot disabled via HONEYPOT_ENABLED")
        return None
    acceptor = await asyncssh.listen(
        config.HONEYPOT_HOST,
        config.HONEYPOT_PORT,
        server_factory=DaygleSSHServer,
        server_host_keys=[_load_or_create_host_key()],
        server_version=config.HONEYPOT_BANNER,
    )
    log.info("honeypot listening on %s:%d", config.HONEYPOT_HOST, config.HONEYPOT_PORT)
    return acceptor


async def stop(acceptor: Any) -> None:
    if acceptor is None:
        return
    acceptor.close()
    await acceptor.wait_closed()
