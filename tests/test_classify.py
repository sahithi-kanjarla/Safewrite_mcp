import pytest

from safewrite_mcp.classify import classify
from safewrite_mcp.policy import Policy

POLICY = Policy(protected_tables=["settings"])

CASES = [
    # (sql, expected risk)
    ("SELECT 1", "low"),
    ("WITH x AS (SELECT id FROM customers) SELECT * FROM x", "low"),
    ("UPDATE customers SET status='x' WHERE id=1", "low"),
    ("UPDATE customers AS c SET status='x' WHERE c.id=1", "low"),
    ("DELETE FROM main.customers WHERE id=1", "low"),
    ("INSERT INTO products (name, price, stock) VALUES ('a', 1, 1)", "low"),
    # no WHERE / always-true WHERE
    ("DELETE FROM customers", "high"),
    ("UPDATE orders SET amount=0", "high"),
    ("DELETE FROM customers WHERE 1=1", "high"),
    ("DELETE FROM customers WHERE id=1 OR 1=1", "high"),
    ("DELETE FROM customers WHERE (1=1)", "high"),
    ("DELETE FROM customers WHERE TRUE", "high"),
    ("DELETE FROM customers WHERE 'a'='a'", "high"),
    ("DELETE FROM customers WHERE id=id", "high"),
    ("DELETE FROM customers WHERE 1", "high"),
    # not statically knowable: left to the dry run
    ("DELETE FROM customers WHERE id>=0", "low"),
    ("DELETE FROM customers WHERE 1=0", "low"),
    # may overwrite
    ("INSERT OR REPLACE INTO products (id, name, price, stock) VALUES (1, 'a', 1, 1)", "medium"),
    ("INSERT INTO customers (id, name, email, created_at) VALUES (1,'a','a','a') ON CONFLICT(id) DO UPDATE SET name='b'", "medium"),
    # blocked
    ("DROP TABLE customers", "blocked"),
    ("DrOp TaBlE customers", "blocked"),
    ("ALTER TABLE customers ADD COLUMN x TEXT", "blocked"),
    ("CREATE TABLE t (id INTEGER)", "blocked"),
    ("SELECT 1; SELECT 2", "blocked"),
    ("UPDATE products SET stock=1 WHERE id=1; DELETE FROM orders", "blocked"),
    ("PRAGMA foreign_keys=OFF", "blocked"),
    ("ATTACH DATABASE 'x.db' AS x", "blocked"),
    ("VACUUM", "blocked"),
    ("BEGIN", "blocked"),
    ("COMMIT", "blocked"),
    ("UPDATE settings SET value='x'", "blocked"),
    ("update SETTINGS set value='x'", "blocked"),
    ("INSERT INTO settings (key, value) VALUES ('a', 'b')", "blocked"),
    ("UPDATE sqlite_master SET sql=''", "blocked"),
    ("SELECT load_extension('x')", "blocked"),
    ("SELECT zeroblob(1000000000)", "blocked"),
    ("DELETE FROM other.customers WHERE id=1", "blocked"),
    ("garbage ((( not sql", "blocked"),
    ("", "blocked"),
    ("   ", "blocked"),
    ("-- only a comment", "blocked"),
]


@pytest.mark.parametrize("sql,risk", CASES)
def test_risk(sql, risk):
    assert classify(sql, POLICY).risk == risk


@pytest.mark.parametrize("sql,kind", [
    ("SELECT 1", "select"), ("UPDATE customers SET status='x' WHERE id=1", "update"),
    ("DELETE FROM customers WHERE id=1", "delete"), ("INSERT INTO products (name, price, stock) VALUES ('a',1,1)", "insert"),
])
def test_kind(sql, kind):
    assert classify(sql, POLICY).kind == kind


def test_comment_cannot_hide_a_missing_where():
    c = classify("DELETE FROM customers -- WHERE id=1", POLICY)
    assert c.risk == "high"
    assert "WHERE" not in c.canonical_sql and "--" not in c.canonical_sql


def test_executed_sql_is_regenerated_not_the_original_text():
    c = classify("DELETE/**/FROM/**/customers /* x */ WHERE id = 5", POLICY)
    assert c.canonical_sql == "DELETE FROM customers WHERE id = 5"


def test_identifier_quoting_styles_resolve_to_the_same_table():
    for q in ('"customers"', "`customers`", "[customers]", "CUSTOMERS"):
        assert classify(f"DELETE FROM {q}", POLICY).target_table.lower() == "customers"


def test_protected_table_is_case_insensitive_and_blocks_writes_only():
    assert classify("UPDATE SeTtInGs SET value='x'", POLICY).blocked
    assert classify("SELECT * FROM settings", POLICY).risk == "low"


def test_ddl_policy_toggles():
    assert "disabled by policy" in classify("DROP TABLE customers", POLICY).reasons[0]
    drop = classify("DROP TABLE customers", Policy(allow_drop=True))
    assert (drop.risk, drop.kind, drop.target_table) == ("high", "drop", "customers")
    alter = classify("ALTER TABLE customers ADD COLUMN x TEXT", Policy(allow_ddl=True))
    assert alter.risk == "medium"
    # protected tables stay protected even when DDL is allowed
    assert classify("DROP TABLE settings", Policy(allow_drop=True, protected_tables=["settings"])).blocked


def test_target_and_where_are_extracted():
    c = classify("UPDATE customers AS c SET status='x' WHERE c.id=1", POLICY)
    assert (c.target_table, c.target_alias, c.where_sql) == ("customers", "c", "c.id = 1")
    assert classify("DELETE FROM customers", POLICY).where_sql is None
