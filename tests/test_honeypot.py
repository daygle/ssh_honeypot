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
