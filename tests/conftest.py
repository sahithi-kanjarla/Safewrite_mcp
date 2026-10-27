import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safewrite_mcp.demo import create_demo_db  # noqa: E402
from safewrite_mcp.engine import GuardedDB, db_fingerprint  # noqa: E402
from safewrite_mcp.policy import Policy  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def scalar(db, sql, *args):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql, args).fetchone()[0]
    finally:
        conn.close()


@pytest.fixture
def db(tmp_path):
    return create_demo_db(tmp_path / "demo.db")


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def g(db, clock):
    engine = GuardedDB(db, policy=Policy(protected_tables=["settings"]), clock=clock)
    yield engine
    engine.close()


@pytest.fixture
def fp(db):
    return lambda: db_fingerprint(db)
