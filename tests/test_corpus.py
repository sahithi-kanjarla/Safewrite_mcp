"""The benchmark's headline claims, as regression tests.

If someone weakens the classifier or the dry run, the corpus catches it here, in seconds, instead of only
in the benchmark report. (Resource-exhaustion attacks are excluded because they intentionally burn the
2-second timeout; that behaviour is covered in test_engine.)
"""

import pytest

from bench.corpus import ATTACKS, BENIGN
from bench.run import Arena, attack_safewrite, policy
from safewrite_mcp.engine import GuardedDB

FAST_ATTACKS = [(cat, sql) for cat, sql in ATTACKS if cat != "resource"]


@pytest.fixture(scope="module")
def arena(tmp_path_factory):
    return Arena(tmp_path_factory.mktemp("arena"))


@pytest.mark.parametrize("cat,sql", FAST_ATTACKS, ids=[f"{c}-{i}" for i, (c, _) in enumerate(FAST_ATTACKS)])
def test_attack_is_stopped_and_data_is_untouched(arena, cat, sql):
    label, _ = attack_safewrite(arena, sql.replace("__TMP__", str(arena.tmp)))
    assert label in ("blocked", "gated"), f"{sql!r} -> {label}"


@pytest.mark.parametrize("kind,sql", [b for b in BENIGN if b[0] != "read"], ids=lambda v: str(v)[:40])
def test_benign_writes_have_the_expected_friction(arena, kind, sql):
    g = GuardedDB(arena.fresh(), policy=policy())
    plan = g.plan(sql, "test")
    g.close()
    assert plan["status"] == "planned"
    assert plan["requires_approval"] is (kind == "bulk")


def test_resource_attacks_are_blocked_or_contained_quickly(arena, tmp_path):
    from safewrite_mcp.policy import Policy
    from safewrite_mcp.engine import Blocked, SafeWriteError

    g = GuardedDB(arena.fresh(), policy=Policy(protected_tables=["settings"], query_timeout_ms=200))
    for sql in [s for c, s in ATTACKS if c == "resource"]:
        with pytest.raises((Blocked, SafeWriteError)):
            g.read(sql)
    g.close()
