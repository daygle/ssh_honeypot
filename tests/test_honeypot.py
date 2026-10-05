import asyncio

import asyncssh
import pytest

from app import db, honeypot


def test_records_probes_and_credential_guesses():
    asyncio.run(_scenario())


async def _scenario():
    acceptor = await honeypot.start()
    port = acceptor.get_port()
    try:
        # 1. Bare TCP probe that never speaks SSH (still captured).
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)

        # 2. Real SSH client guessing a password (always refused).
        with pytest.raises(asyncssh.Error):
            await asyncssh.connect(
                "127.0.0.1",
                port,
                username="root",
                password="hunter2",
                known_hosts=None,
                login_timeout=10,
            )
        await asyncio.sleep(0.2)
    finally:
        await honeypot.stop(acceptor)

    summary = db.get_summary()
    assert summary["connections_total"] >= 2
    assert summary["auth_total"] >= 1

    guesses = [e for e in summary["recent"] if e["event"] == "password"]
    assert guesses, "password attempt was not recorded"
    assert guesses[0]["username"] == "root"
    assert guesses[0]["detail"] == "hunter2"
    assert guesses[0]["ip"] == "127.0.0.1"

    connects = [e for e in summary["recent"] if e["event"] == "connect"]
    assert connects, "TCP connections were not recorded"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("::ffff:203.0.113.9", "203.0.113.9"),
        ("203.0.113.9", "203.0.113.9"),
        ("2001:db8::1", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("not-an-ip", "not-an-ip"),
    ],
)
def test_normalize_ip(raw, expected):
    assert honeypot._normalize_ip(raw) == expected


def test_host_key_created_private(tmp_path, monkeypatch):
    path = tmp_path / "keys" / "host_key"
    monkeypatch.setattr(honeypot.config, "HOST_KEY_PATH", path)

    key = honeypot._load_or_create_host_key()

    assert path.stat().st_mode & 0o777 == 0o600
    reloaded = honeypot._load_or_create_host_key()
    assert reloaded.get_fingerprint() == key.get_fingerprint()
