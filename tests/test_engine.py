import sqlite3

import pytest

from safewrite_mcp.engine import ApprovalRequired, Blocked, GuardedDB, PlanInvalid, SafeWriteError
from safewrite_mcp.policy import Policy

from .conftest import scalar

LOW = "UPDATE customers SET status='vip' WHERE id=7"
CASCADE = "DELETE FROM customers WHERE id=1"


# ------------------------------------------------------------------ planning
@pytest.mark.parametrize("sql", [
    LOW, CASCADE, "DELETE FROM customers", "UPDATE orders SET amount=0 WHERE id>=0",
    "INSERT INTO products (name, price, stock) VALUES ('x', 1, 1)",
    "INSERT OR REPLACE INTO products (id, name, price, stock) VALUES (1, 'x', 0, 0)",
])
def test_planning_never_changes_the_database(g, fp, sql):
    before = fp()
    assert g.plan(sql, "test")["status"] == "planned"
    assert fp() == before


def test_plan_reports_cascades_into_other_tables(g, db):
    orders_of_1 = scalar(db, "SELECT COUNT(*) FROM orders WHERE customer_id=1")
    plan = g.plan(CASCADE, "remove customer")
    assert plan["impact"]["rows_affected"] == 1
    assert plan["impact"]["collateral_changes"] == {"orders": -orders_of_1}
    assert plan["risk"] == "high" and plan["requires_approval"]
    assert any("collateral" in r for r in plan["reasons"])


def test_dry_run_catches_what_static_analysis_cannot(g):
    plan = g.plan("UPDATE orders SET amount=0 WHERE id>=0", "x")
    assert plan["risk"] == "high"
    assert plan["impact"]["rows_affected"] == 1000
    assert any("100%" in r for r in plan["reasons"])


def test_update_diff_shows_before_and_after(g):
    diff = g.plan(LOW, "x")["impact"]["diff"]
    assert diff["kind"] == "update"
    assert diff["rows_changed"][0]["changes"]["status"][1] == "vip"


def test_delete_and_insert_diffs(g):
    d = g.plan("DELETE FROM orders WHERE id=999", "x")["impact"]["diff"]
    assert d["kind"] == "delete" and d["rows_removed"][0]["id"] == 999
    assert "__rid" not in d["rows_removed"][0] and d["rows_removed"][0]["rowid"] == 999   # no internal names leak
    i = g.plan("INSERT INTO products (name, price, stock) VALUES ('Widget', 2.5, 3)", "x")["impact"]["diff"]
    assert i["kind"] == "insert" and i["rows_added"][0]["name"] == "Widget"


def test_overwrite_is_detected(g):
    plan = g.plan("INSERT OR REPLACE INTO products (id, name, price, stock) VALUES (1, 'x', 0, 0)", "x")
    assert plan["impact"]["overwritten_rows"] == 1 and plan["requires_approval"]


def test_small_clean_write_is_low_risk_and_needs_no_approval(g):
    plan = g.plan(LOW, "x")
    assert plan["risk"] == "low" and not plan["requires_approval"]


def test_row_count_threshold_gates_medium_risk(g):
    plan = g.plan("UPDATE orders SET status='x' WHERE id BETWEEN 1 AND 40", "x")
    assert plan["risk"] == "medium" and plan["impact"]["rows_affected"] == 40


def test_hard_limit_blocks_outright(db):
    g = GuardedDB(db, policy=Policy(hard_max_rows=5))
    plan = g.plan("UPDATE orders SET status='x' WHERE id <= 50", "x")
    assert plan["status"] == "blocked" and "hard limit" in plan["reasons"][-1]
    g.close()


def test_blocked_statements_return_reasons_and_no_token(g):
    plan = g.plan("DROP TABLE customers", "x")
    assert plan["status"] == "blocked" and "plan_id" not in plan


def test_select_is_not_a_write(g):
    assert g.plan("SELECT 1", "x")["status"] == "not_a_write"


def test_failing_statements_report_errors_without_side_effects(g, fp):
    before = fp()
    assert g.plan("UPDATE nonexistent SET x=1 WHERE id=1", "x")["status"] == "error"
    dup = g.plan("INSERT INTO customers (id, name, email, created_at) VALUES (1, 'a', 'a', 'a')", "x")
    assert dup["status"] == "error" and "UNIQUE" in dup["error"]
    assert fp() == before


# ------------------------------------------------------------------ applying
def test_low_risk_applies_without_approval(g, db):
    res = g.apply(g.plan(LOW, "x")["plan_id"])
    assert res["status"] == "applied" and res["approved_via"] == "auto (low risk)"
    assert scalar(db, "SELECT status FROM customers WHERE id=7") == "vip"


def test_high_risk_cannot_apply_without_approval(g, fp):
    before = fp()
    plan = g.plan(CASCADE, "x")
    with pytest.raises(ApprovalRequired):
        g.apply(plan["plan_id"])
    assert fp() == before


def test_out_of_band_approval_unlocks_the_plan(g, db):
    plan = g.plan(CASCADE, "x")
    g.approve(plan["plan_id"])
    res = g.apply(plan["plan_id"])
    assert res["approved_via"] == "out-of-band"
    assert scalar(db, "SELECT COUNT(*) FROM customers WHERE id=1") == 0


def test_approval_for_one_plan_does_not_cover_another(g):
    a = g.plan(CASCADE, "x")
    b = g.plan("DELETE FROM customers WHERE id=2", "x")
    g.approve(a["plan_id"])
    with pytest.raises(ApprovalRequired):
        g.apply(b["plan_id"])


def test_approval_is_consumed(g):
    plan = g.plan(CASCADE, "x")
    g.approve(plan["plan_id"])
    g.apply(plan["plan_id"])
    assert not (g.home / "approvals" / plan["plan_id"]).exists()


def test_plan_is_single_use(g):
    plan = g.plan(LOW, "x")
    g.apply(plan["plan_id"])
    with pytest.raises(PlanInvalid):
        g.apply(plan["plan_id"])


def test_plans_expire(g, clock):
    plan = g.plan(LOW, "x")
    clock.advance(g.policy.plan_ttl_s + 1)
    with pytest.raises(PlanInvalid, match="expired"):
        g.apply(plan["plan_id"])


def test_any_change_invalidates_other_pending_plans(g):
    a, b = g.plan(LOW, "x"), g.plan("UPDATE customers SET status='vip' WHERE id=8", "x")
    g.apply(a["plan_id"])
    with pytest.raises(PlanInvalid, match="changed"):
        g.apply(b["plan_id"])


def test_external_writer_invalidates_plans(g, db):
    plan = g.plan(LOW, "x")
    other = sqlite3.connect(db)
    other.execute("INSERT INTO products (name, price, stock) VALUES ('sneaky', 1, 1)")
    other.commit()
    other.close()
    with pytest.raises(PlanInvalid, match="changed"):
        g.apply(plan["plan_id"])


@pytest.mark.parametrize("bad", ["../../etc/passwd", "", "zzzz", "A" * 16, None])
def test_malformed_plan_ids_are_rejected(g, bad):
    with pytest.raises(PlanInvalid):
        g.apply(bad)
    with pytest.raises(PlanInvalid):
        g.approve(bad or "")


def test_unknown_plan_id(g):
    with pytest.raises(PlanInvalid, match="unknown"):
        g.apply("0" * 16)


def test_real_effect_diverging_from_the_plan_is_rolled_back(g, fp):
    before = fp()
    plan = g.plan(LOW, "x")
    g._plans[plan["plan_id"]].impact["rows_affected"] += 1       # simulate a plan that no longer matches reality
    with pytest.raises(PlanInvalid, match="rolled back"):
        g.apply(plan["plan_id"])
    assert fp() == before
    assert not list((g.home / "snapshots").glob("chg_*.db"))     # no orphaned snapshot
    assert any(e["event"] == "apply_aborted" for e in g.audit.tail(10))


def test_snapshot_size_cap_refuses_writes_instead_of_losing_undo(db, fp):
    g = GuardedDB(db, policy=Policy(snapshot_max_mb=0))
    before = fp()
    with pytest.raises(SafeWriteError, match="snapshot_max_mb"):
        g.apply(g.plan(LOW, "x")["plan_id"])
    assert fp() == before
    g.close()


def test_pending_lists_only_plans_that_can_still_be_applied(g):
    a, b = g.plan(LOW, "x"), g.plan("DELETE FROM orders WHERE id=999", "y")
    assert {p["plan_id"] for p in g.pending()} == {a["plan_id"], b["plan_id"]}
    g.apply(a["plan_id"])
    # `a` is used, and `b` went stale because the database changed; neither should be offered for approval
    assert g.pending() == []
    assert not list((g.home / "pending").glob("*.json"))


def test_stale_plan_files_are_removed_for_the_human_cli_too(g):
    a, b = g.plan(LOW, "x"), g.plan(CASCADE, "y")
    g.apply(a["plan_id"])
    g.plan("DELETE FROM orders WHERE id=999", "z")          # planning triggers cleanup
    names = {f.stem for f in (g.home / "pending").glob("*.json")}
    assert b["plan_id"] not in names and a["plan_id"] not in names


# ---------------------------------------------------------------------- undo
def test_undo_restores_exactly(g, fp):
    before = fp()
    plan = g.plan(CASCADE, "x")
    g.approve(plan["plan_id"])
    g.apply(plan["plan_id"])
    assert fp() != before
    assert g.undo_last()["status"] == "undone"
    assert fp() == before


def test_undo_is_single_level(g):
    g.apply(g.plan(LOW, "x")["plan_id"])
    g.undo_last()
    with pytest.raises(PlanInvalid, match="nothing to undo"):
        g.undo_last()


def test_undo_with_nothing_applied(g):
    with pytest.raises(PlanInvalid, match="nothing to undo"):
        g.undo_last()


def test_undo_refused_if_someone_else_wrote_since(g, db):
    g.apply(g.plan(LOW, "x")["plan_id"])
    other = sqlite3.connect(db)
    other.execute("INSERT INTO products (name, price, stock) VALUES ('newer', 1, 1)")
    other.commit()
    other.close()
    with pytest.raises(PlanInvalid, match="newer data"):
        g.undo_last()
    assert scalar(db, "SELECT COUNT(*) FROM products WHERE name='newer'") == 1     # newer data survived


def test_undo_invalidates_pending_plans(g):
    g.apply(g.plan(LOW, "x")["plan_id"])
    stale = g.plan("DELETE FROM orders WHERE id=999", "x")
    g.undo_last()
    with pytest.raises(PlanInvalid):
        g.apply(stale["plan_id"])


def test_old_snapshots_are_rotated(db):
    g = GuardedDB(db, policy=Policy(keep_snapshots=2))
    for i in range(5):
        g.apply(g.plan(f"UPDATE customers SET status='s{i}' WHERE id=7", "x")["plan_id"])
    assert len(list((g.home / "snapshots").glob("chg_*.db"))) == 2
    g.close()


# --------------------------------------------------------------------- reads
def test_read_returns_rows_and_truncates(g):
    small = g.read("SELECT id FROM customers WHERE id <= 3 ORDER BY id")
    assert small["rows"] == [[1], [2], [3]] and not small["truncated"]
    big = g.read("SELECT * FROM orders")
    assert big["row_count"] == g.policy.read_row_limit and big["truncated"]


def test_read_refuses_writes_and_blocked_sql(g, fp):
    before = fp()
    with pytest.raises(SafeWriteError, match="only runs read"):
        g.read("DELETE FROM customers WHERE id=1")
    with pytest.raises(Blocked):
        g.read("SELECT 1; DROP TABLE customers")
    assert fp() == before


def test_read_connection_is_read_only_even_if_the_classifier_were_fooled(g):
    ro = g._ro()
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM customers")
    ro.close()


def test_runaway_read_is_aborted(db):
    g = GuardedDB(db, policy=Policy(query_timeout_ms=150))
    with pytest.raises(SafeWriteError, match="exceeded"):
        g.read("SELECT count(*) FROM orders a, orders b, orders c")
    g.close()


def test_sql_errors_are_reported_cleanly(g):
    with pytest.raises(SafeWriteError, match="SQL error"):
        g.read("SELECT * FROM no_such_table")


def test_schema_and_table_listing(g):
    assert "CREATE TABLE customers" in g.schema()
    tables = {t["table"]: t for t in g.list_tables()}
    assert tables["settings"]["protected"] and not tables["customers"]["protected"]
    assert tables["orders"]["rows"] == 1000


# --------------------------------------------------------------------- audit
def test_every_step_is_audited_and_the_chain_verifies(g):
    plan = g.plan(CASCADE, "remove test customer")
    g.approve(plan["plan_id"])
    g.apply(plan["plan_id"])
    g.undo_last()
    g.plan("DROP TABLE customers", "oops")
    g.read("SELECT 1")
    events = [e["event"] for e in g.audit.tail(20)]
    assert events == ["plan", "apply", "undo", "blocked", "read"]
    assert g.audit.verify()["ok"]
    plan_entry = g.audit.tail(20)[0]
    assert plan_entry["intent"] == "remove test customer"
    assert g.audit.tail(20)[1]["approved_via"] == "out-of-band"


def test_missing_database_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        GuardedDB(tmp_path / "nope.db")
