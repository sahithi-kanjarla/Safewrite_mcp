import sqlite3

from safewrite_mcp.engine import GuardedDB, impact_lines
from safewrite_mcp.policy import Policy

from .conftest import scalar

CASCADE = "DELETE FROM customers WHERE id=1"


def test_cascade_impact_has_per_table_counts_and_sample(g, db):
    n_orders = scalar(db, "SELECT COUNT(*) FROM orders WHERE customer_id=1")
    n_cust = scalar(db, "SELECT COUNT(*) FROM customers")
    n_all_orders = scalar(db, "SELECT COUNT(*) FROM orders")
    tables = g.plan(CASCADE, "x")["impact"]["tables"]
    assert tables["customers"]["before"] == n_cust and tables["customers"]["after"] == n_cust - 1
    assert tables["orders"] == {**tables["orders"], "before": n_all_orders, "after": n_all_orders - n_orders,
                                "change": -n_orders, "sample_kind": "removed"}
    sample = tables["orders"]["sample"]
    assert len(sample) == min(3, n_orders) and all(r["customer_id"] == 1 for r in sample)
    assert "__rid" not in sample[0]


def test_samples_never_exceed_three_rows_per_table(g):
    tables = g.plan("DELETE FROM customers WHERE id <= 20", "x")["impact"]["tables"]
    assert tables["customers"]["change"] == -20 and tables["orders"]["change"] < -3
    assert all(len(t["sample"]) <= 3 for t in tables.values())
    assert len(tables["customers"]["sample"]) == 3 and len(tables["orders"]["sample"]) == 3


def test_long_values_are_truncated_to_60_chars(db):
    conn = sqlite3.connect(db)
    conn.execute("UPDATE customers SET name=? WHERE id=1", ("x" * 200,))
    conn.commit()
    conn.close()
    g = GuardedDB(db, policy=Policy())
    try:
        sample = g.plan(CASCADE, "x")["impact"]["tables"]["customers"]["sample"]
        assert len(sample[0]["name"]) == 60 and sample[0]["name"].endswith("...")
        upd = g.plan("UPDATE customers SET name=? || 'y' WHERE id=1".replace("?", "'" + "z" * 100 + "'"), "x")
        change = upd["impact"]["tables"]["customers"]["sample"][0]["changes"]["name"]
        assert all(len(v) <= 60 for v in change)
    finally:
        g.close()


def test_why_lists_plain_reasons(g, db):
    n_orders = scalar(db, "SELECT COUNT(*) FROM orders WHERE customer_id=1")
    assert f"cascades into orders (-{n_orders} rows)" in g.plan(CASCADE, "x")["impact"]["why"]
    assert any("30 rows is above the auto-approve limit of 10" in w
               for w in g.plan("UPDATE orders SET status='x' WHERE id <= 30", "x")["impact"]["why"])
    assert "no WHERE clause: this affects every row" in g.plan("UPDATE products SET stock=0", "x")["impact"]["why"]
    assert "within the auto-approve limit" in g.plan("UPDATE customers SET status='vip' WHERE id=7", "x")["impact"]["why"][0]


def test_reversible_section_and_text_rendering(g):
    plan = g.plan(CASCADE, "x")
    assert plan["impact"]["reversible"]["undoable"] and plan["impact"]["reversible"]["how"] == "undo_last_change"
    text = "\n".join(impact_lines(plan["impact"]))
    assert "orders:" in text and "cascade/trigger" in text and "reversible: yes, via undo_last_change" in text


def test_risk_and_existing_fields_unchanged_by_impact_section(g):
    plan = g.plan(CASCADE, "x")
    assert plan["risk"] == "high" and plan["impact"]["collateral_changes"]
    assert "_before_counts" not in plan["impact"]


def test_undo_reports_restored_rows_per_table(g, db):
    n_orders = scalar(db, "SELECT COUNT(*) FROM orders WHERE customer_id=1")
    plan = g.plan(CASCADE, "x")
    g.approve(plan["plan_id"])
    g.apply(plan["plan_id"])
    res = g.undo_last()
    assert res["restored"] == {"customers": 1, "orders": n_orders}
    assert res["tables"]["orders"]["after"] - res["tables"]["orders"]["before"] == n_orders


def test_undo_of_update_restores_no_rows(g):
    g.apply(g.plan("UPDATE customers SET status='vip' WHERE id=7", "x")["plan_id"])
    assert g.undo_last()["restored"] == {}
