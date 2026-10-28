"""Static SQL classification.

Two design rules make this robust:

1. Parse-then-regenerate. We never execute the text the agent sent. We parse it
   into an AST, judge the AST, and execute SQL regenerated from that same AST.
   Comments, casing, quoting and whitespace tricks therefore cannot make the
   thing we analyze differ from the thing that runs.
2. Fail closed. Anything we cannot parse, or do not recognise, is blocked.

Static analysis alone cannot know how many rows a statement touches. That is
the job of the dry run in engine.py; this module only supplies the first,
cheap line of defence and the facts the planner needs (target table, WHERE).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from .policy import Policy

# sqlglot logs a warning when it falls back to a generic Command node. We already
# treat Command as blocked, so the noise on stderr adds nothing.
logging.getLogger("sqlglot").setLevel(logging.ERROR)

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "blocked": 3}

READ_NODES = {"Select", "Union", "Intersect", "Except", "Subquery"}
WRITE_NODES = {"Insert": "insert", "Update": "update", "Delete": "delete"}
DDL_NODES = {"Create": "create", "Alter": "alter", "AlterTable": "alter", "Drop": "drop", "TruncateTable": "truncate"}

# Functions that read/write the filesystem, load code, or exhaust memory in one call.
DANGEROUS_FUNCS = {
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "zeroblob", "randomblob",
}


@dataclass
class Classification:
    kind: str                       # select | insert | update | delete | create | alter | drop | truncate | other
    risk: str                       # low | medium | high | blocked
    reasons: list[str] = field(default_factory=list)
    canonical_sql: str | None = None
    target_table: str | None = None
    target_alias: str | None = None
    tables: list[str] = field(default_factory=list)
    where_sql: str | None = None

    @property
    def blocked(self) -> bool:
        return self.risk == "blocked"

    def escalate(self, risk: str, reason: str) -> None:
        if RISK_ORDER[risk] > RISK_ORDER[self.risk]:
            self.risk = risk
        self.reasons.append(reason)


def _blocked(kind: str, reason: str) -> Classification:
    return Classification(kind=kind, risk="blocked", reasons=[reason])


def _is_tautology(node: exp.Expression | None) -> bool:
    """True when a WHERE condition is obviously true for every row (1=1, TRUE, 'a'='a', x=x, ...)."""
    while isinstance(node, exp.Paren):
        node = node.this
    if node is None:
        return False
    if isinstance(node, exp.Boolean):
        return bool(node.this)
    if isinstance(node, exp.Literal) and not node.is_string:
        try:
            return float(node.this) != 0
        except ValueError:
            return False
    if isinstance(node, (exp.EQ, exp.GTE, exp.LTE)):
        return node.left == node.right
    if isinstance(node, exp.Or):
        return _is_tautology(node.left) or _is_tautology(node.right)
    if isinstance(node, exp.And):
        return _is_tautology(node.left) and _is_tautology(node.right)
    return False


def _target(expr: exp.Expression) -> exp.Table | None:
    t = expr.this
    if isinstance(t, exp.Schema):
        t = t.this
    return t if isinstance(t, exp.Table) else expr.find(exp.Table)


def classify(sql: str, policy: Policy) -> Classification:
    if not sql or not sql.strip():
        return _blocked("other", "empty statement")
    try:
        parsed = [e for e in sqlglot.parse(sql, read="sqlite") if e is not None]
    except Exception as e:  # noqa: BLE001 - any parser failure must fail closed
        return _blocked("other", f"unparseable SQL (fail-closed): {str(e).splitlines()[0][:120]}")
    if not parsed:
        return _blocked("other", "no executable statement (comments only)")
    if len(parsed) > 1:
        return _blocked("other", f"stacked statements ({len(parsed)}) are not allowed; send one statement per call")

    expr = parsed[0]
    node = type(expr).__name__

    if node in READ_NODES:
        kind = "select"
    elif node in WRITE_NODES:
        kind = WRITE_NODES[node]
    elif node in DDL_NODES:
        kind = DDL_NODES[node]
    else:
        return _blocked("other", f"{node} statements are not allowed (PRAGMA, ATTACH, VACUUM, transactions, ...)")

    try:
        canonical = expr.sql(dialect="sqlite", comments=False)
    except Exception as e:  # noqa: BLE001
        return _blocked(kind, f"could not regenerate SQL (fail-closed): {str(e)[:100]}")

    cte_names = {c.alias_or_name.lower() for c in expr.find_all(exp.CTE)}
    tables: list[str] = []
    for t in expr.find_all(exp.Table):
        if not t.name or t.name.lower() in cte_names:
            continue
        if t.db and t.db.lower() != "main":
            return _blocked(kind, f"schema-qualified table '{t.db}.{t.name}' is not allowed")
        if t.name not in tables:
            tables.append(t.name)

    for f in expr.find_all(exp.Func):
        fname = (f.name if isinstance(f, exp.Anonymous) else f.sql_name()).lower()
        if fname in DANGEROUS_FUNCS:
            return _blocked(kind, f"function '{fname}' is not allowed")

    c = Classification(kind=kind, risk="low", canonical_sql=canonical, tables=tables)
    if kind == "select":
        return c

    # Policy gates for DDL come first so the block reason names the real cause.
    if kind in ("drop", "truncate") and not policy.allow_drop:
        return _blocked(kind, f"{kind.upper()} is disabled by policy. A person can enable it by setting "
                              "allow_drop to true in policy.json and restarting the server.")
    if kind in ("create", "alter") and not policy.allow_ddl:
        return _blocked(kind, f"{kind.upper()} is disabled by policy. A person can enable it by setting "
                              "allow_ddl to true in policy.json and restarting the server.")

    target = _target(expr)
    if target is None or not target.name:
        return _blocked(kind, "could not determine the target table")
    c.target_table = target.name
    c.target_alias = target.alias or None
    low = target.name.lower()
    if low.startswith("sqlite_"):
        return _blocked(kind, f"'{target.name}' is an internal SQLite table")
    if low in policy.protected_tables:
        return _blocked(kind, f"'{target.name}' is a protected table (read-only)")

    if kind in ("update", "delete"):
        where = expr.args.get("where")
        if where is None:
            c.escalate("high", "no WHERE clause: this affects every row")
        else:
            c.where_sql = where.this.sql(dialect="sqlite")
            if _is_tautology(where.this):
                c.escalate("high", "WHERE clause is always true: this affects every row")
    elif kind == "insert":
        alt = expr.args.get("alternative")
        if alt and str(alt).upper() == "REPLACE":
            c.escalate("medium", "INSERT OR REPLACE can silently overwrite existing rows")
        if expr.args.get("conflict"):
            c.escalate("medium", "upsert (ON CONFLICT) can overwrite existing rows")
    elif kind in ("drop", "truncate"):
        c.escalate("high", f"{kind.upper()} destroys data and schema")
    elif kind in ("create", "alter"):
        c.escalate("medium", "schema change")
    return c
