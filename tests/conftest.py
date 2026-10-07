import os
import tempfile

# Configure before any app module is imported: isolated DB, ephemeral honeypot port.
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="daygle-test-"))
os.environ.setdefault("HONEYPOT_PORT", "0")

import pytest

from app import db


@pytest.fixture(autouse=True)
def fresh_db():
    db.init_db()
    with db._connect() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM app_settings")
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('admin_setup', 'complete')")
    yield
