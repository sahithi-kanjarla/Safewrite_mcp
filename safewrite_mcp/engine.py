"""GuardedDB: the engine behind the MCP tools.

Life of a write:

    plan(sql)   -> classify statically, then run the canonical SQL inside a
                   transaction that is ALWAYS rolled back, measuring the true
                   blast radius (rows, per-table deltas, cascades, overwrites).
                   Returns a short-lived single-use token. Nothing changes.
    apply(id)   -> checks the token (unexpired, unused, DB unchanged since the
                   plan), requires a human approval unless the plan is low
                   risk, snapshots the DB, executes, and verifies the real
                   effect matches the plan. Any mismatch is rolled back.
    undo_last() -> restores the snapshot, but only if nothing else has touched
                   the database since, so newer data is never lost.

The agent can never approve its own plan: approval arrives out-of-band
(MCP elicitation handled by the server, or a file written by the human's
terminal via `safewrite-mcp approve`).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .classify import RISK_ORDER, Classification, classify
from .policy import Policy

SAMPLE_ROWS = 5
PLAN_ID_RE = re.compile(r"[0-9a-f]{16}")


class SafeWriteError(Exception):
    """Base class; the message is safe to show to the agent."""


class Blocked(SafeWriteError):
    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


class ApprovalRequired(SafeWriteError):
    pass


class PlanInvalid(SafeWriteError):
    pass


class _Diverged(Exception):
    pass


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _j(v: Any) -> Any:
    return f"<{len(v)} bytes>" if isinstance(v, bytes) else v


def _row(cols: list[str], values: Any) -> dict[str, Any]:
    """Row as a JSON-safe dict; our internal rowid helper column is exposed as plain 'rowid'."""
    return {("rowid" if c == "__rid" else c): _j(v) for c, v in zip(cols, values)}


def db_fingerprint(path: Path | str) -> str:
    """Content hash of schema + every row. Used by tests and the benchmark to prove 'nothing changed'."""
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        h = hashlib.sha256()
        for name, sql in conn.execute("SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"):
            h.update(f"{name}|{sql}".encode())
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for t in tables:
            try:
                cur = conn.execute(f"SELECT * FROM {_q(t)} ORDER BY rowid")
            except sqlite3.Error:
                cur = conn.execute(f"SELECT * FROM {_q(t)}")
            for row in cur:
                h.update(repr(row).encode())
        return h.hexdigest()
    finally:
        conn.close()


@dataclass
class Plan:
    plan_id: str
    sql: str
    kind: str
    risk: str
    reasons: list[str]
    impact: dict[str, Any]
    intent: str
    expires: float
    epoch: int
    data_version: int
    used: bool = False

    @property
    def requires_approval(self) -> bool:
        return self.risk != "low"


class GuardedDB:
    def __init__(
        self,
        db_path: Path | str,
        home: Path | str | None = None,
        policy: Policy | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.db_path = Path(db_path).resolve()
        if not self.db_path.exists():
            raise FileNotFoundError(f"database not found: {self.db_path}")
        self.home = Path(home) if home else self.db_path.parent / ".safewrite"
        for sub in ("approvals", "pending", "snapshots"):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        self.policy = policy or Policy.load(self.home / "policy.json")
        self.audit = AuditLog(self.home / "audit.jsonl")
        self.clock = clock
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._epoch = 0
        self._plans: dict[str, Plan] = {}
        self._last_change: dict[str, Any] | None = None

    # ------------------------------------------------------------ plumbing
    @staticmethod
    def _arm(conn: sqlite3.Connection, ms: int) -> None:
        deadline = time.monotonic() + ms / 1000
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1000)

    @staticmethod
    def _disarm(conn: sqlite3.Connection) -> None:
        conn.set_progress_handler(None, 0)

    def _data_version(self) -> int:
        return self._conn.execute("PRAGMA data_version").fetchone()[0]

    @staticmethod
    def _user_tables(conn: sqlite3.Connection) -> list[str]:
        return [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]

    @staticmethod
    def _counts(conn: sqlite3.Connection, tables: list[str]) -> dict[str, int]:
        return {t: conn.execute(f"SELECT COUNT(*) FROM {_q(t)}").fetchone()[0] for t in tables}

    def _ro(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True)
        conn.execute("PRAGMA query_only = ON")
        return conn

    # ---------------------------------------------------------------- reads
    def read(self, sql: str) -> dict[str, Any]:
        c = classify(sql, self.policy)
        if c.blocked:
            self.audit.append("blocked", sql=sql[:500], kind=c.kind, reasons=c.reasons)
            raise Blocked(c.reasons)
        if c.kind != "select":
            raise SafeWriteError("query() only runs read statements. Use plan_change() for writes.")
        ro = self._ro()
        limit = self.policy.read_row_limit
        try:
            self._arm(ro, self.policy.query_timeout_ms)
            cur = ro.execute(c.canonical_sql)
            rows = cur.fetchmany(limit + 1)
            cols = [d[0] for d in cur.description or []]
        except sqlite3.Error as e:
            if "interrupted" in str(e):
                self.audit.append("read_timeout", sql=c.canonical_sql)
                raise SafeWriteError(f"query exceeded {self.policy.query_timeout_ms} ms and was aborted") from e
            raise SafeWriteError(f"SQL error: {e}") from e
        finally:
            ro.close()
        self.audit.append("read", sql=c.canonical_sql, rows=min(len(rows), limit))
        return {
            "columns": cols,
            "rows": [[_j(v) for v in r] for r in rows[:limit]],
            "row_count": min(len(rows), limit),
            "truncated": len(rows) > limit,
        }

    def schema(self) -> str:
        ro = self._ro()
        try:
            rows = ro.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type DESC, name")
            return ";\n\n".join(r[0] for r in rows) + ";"
        finally:
            ro.close()

    def list_tables(self) -> list[dict[str, Any]]:
        ro = self._ro()
        try:
            out = []
            for t in self._user_tables(ro):
                cols = [r[1] for r in ro.execute(f"PRAGMA table_info({_q(t)})")]
                n = ro.execute(f"SELECT COUNT(*) FROM {_q(t)}").fetchone()[0]
                out.append({"table": t, "rows": n, "columns": cols,
                            "protected": t.lower() in self.policy.protected_tables})
            return out
        finally:
            ro.close()

    # ------------------------------------------------------------ dry run
    def _from_clause(self, c: Classification) -> str:
        t = _q(c.target_table or "")
        return f"{t} AS {_q(c.target_alias)}" if c.target_alias else t

    def _sample_before(self, conn: sqlite3.Connection, c: Classification) -> dict[str, Any] | None:
        try:
            if c.kind == "insert":
                mx = conn.execute(f"SELECT COALESCE(MAX(rowid),0) FROM {_q(c.target_table or '')}").fetchone()[0]
                return {"max_rowid": mx}
            if c.kind in ("update", "delete"):
                where = f" WHERE {c.where_sql}" if c.where_sql else ""
                rid = f"{_q(c.target_alias)}.rowid" if c.target_alias else "rowid"
                cur = conn.execute(
                    f"SELECT {rid} AS __rid, * FROM {self._from_clause(c)}{where} ORDER BY {rid} LIMIT {SAMPLE_ROWS}")
                return {"cols": [d[0] for d in cur.description], "rows": cur.fetchall()}
        except sqlite3.Error:
            return None
        return None

    def _sample_after(self, conn: sqlite3.Connection, c: Classification, sb: dict[str, Any] | None):
        if not sb:
            return None
        try:
            if c.kind == "insert":
                cur = conn.execute(
                    f"SELECT rowid AS __rid, * FROM {_q(c.target_table or '')} WHERE rowid > ? ORDER BY rowid LIMIT {SAMPLE_ROWS}",
                    (sb["max_rowid"],))
                return {"cols": [d[0] for d in cur.description], "rows": cur.fetchall()}
            if c.kind == "update" and sb["rows"]:
                rids = [r[0] for r in sb["rows"]]
                cur = conn.execute(
                    f"SELECT rowid AS __rid, * FROM {_q(c.target_table or '')} "
                    f"WHERE rowid IN ({','.join('?' * len(rids))}) ORDER BY rowid", rids)
                return {"cols": [d[0] for d in cur.description], "rows": cur.fetchall()}
        except sqlite3.Error:
            return None
        return None

    @staticmethod
    def _diff(c: Classification, sb: dict[str, Any] | None, sa: dict[str, Any] | None) -> dict[str, Any] | None:
        if not sb:
            return None
        if c.kind == "delete":
            return {"kind": "delete", "sample_limit": SAMPLE_ROWS,
                    "rows_removed": [_row(sb["cols"], r) for r in sb["rows"]]}
        if c.kind == "insert" and sa:
            return {"kind": "insert", "sample_limit": SAMPLE_ROWS,
                    "rows_added": [_row(sa["cols"], r) for r in sa["rows"]]}
        if c.kind == "update" and sa:
            after_by = {r[0]: r for r in sa["rows"]}
            changed = []
            for r in sb["rows"]:
                a = after_by.get(r[0])
                if a is not None:
                    changed.append({
                        "rowid": r[0],
                        "changes": {col: [_j(o), _j(n)] for col, o, n in zip(sb["cols"], r, a) if o != n},
                    })
            return {"kind": "update", "sample_limit": SAMPLE_ROWS, "rows_changed": changed}
        return None

    def _simulate(self, c: Classification) -> dict[str, Any]:
        """Run the statement in a transaction that is ALWAYS rolled back and measure what it did."""
        conn = self._conn
        t0 = time.perf_counter()
        conn.execute("BEGIN IMMEDIATE")
        try:
            self._arm(conn, self.policy.query_timeout_ms)
            before = self._counts(conn, self._user_tables(conn))
            sb = self._sample_before(conn, c)
            changes0 = conn.total_changes
            cur = conn.execute(c.canonical_sql or "")
            cur.fetchall()
            rowcount = cur.rowcount
            changes = conn.total_changes - changes0
            after = self._counts(conn, self._user_tables(conn))
            sa = self._sample_after(conn, c, sb)
        finally:
            self._disarm(conn)
            if conn.in_transaction:
                conn.execute("ROLLBACK")
        secs = time.perf_counter() - t0

        names = set(before) | set(after)
        net = {t: after.get(t, 0) - before.get(t, 0) for t in sorted(names)}
        net = {t: d for t, d in net.items() if d}
        t_key = next((t for t in names if c.target_table and t.lower() == c.target_table.lower()), c.target_table)
        rows_affected = rowcount if rowcount is not None and rowcount >= 0 else None
        n_before = before.get(t_key) if t_key else None
        overwritten = 0
        if c.kind == "insert" and rows_affected is not None:
            overwritten = max(0, rows_affected - net.get(t_key, 0))
        return {
            "target_table": t_key,
            "rows_affected": rows_affected,
            "table_rows_before": n_before,
            "table_fraction": round(rows_affected / n_before, 3) if rows_affected and n_before else 0.0,
            "net_row_changes": net,
            "collateral_changes": {t: d for t, d in net.items() if t != t_key},
            "trigger_or_cascade_changes": max(0, changes - rows_affected) if rows_affected is not None else 0,
            "overwritten_rows": overwritten,
            "diff": self._diff(c, sb, sa),
            "dry_run_ms": round(secs * 1000, 2),
        }

    def _assess(self, c: Classification, impact: dict[str, Any]) -> tuple[str, list[str]]:
        p = self.policy
        risk, reasons = c.risk, list(c.reasons)

        def esc(level: str, why: str) -> None:
            nonlocal risk
            if RISK_ORDER[level] > RISK_ORDER[risk]:
                risk = level
            reasons.append(why)

        n, tb = impact["rows_affected"], impact["table_rows_before"]
        if n is not None:
            if n > p.hard_max_rows:
                esc("blocked", f"would change {n} rows; the hard limit is {p.hard_max_rows}")
            elif n > p.auto_approve_max_rows:
                esc("medium", f"changes {n} rows (auto-approve limit is {p.auto_approve_max_rows})")
        if n and tb and tb >= p.min_rows_for_fraction and n / tb >= p.max_table_fraction:
            esc("high", f"touches {n} of {tb} rows ({n / tb:.0%}) in '{impact['target_table']}'")
        if impact["collateral_changes"] or impact["trigger_or_cascade_changes"]:
            esc("high", f"collateral effects via cascade/trigger: {impact['collateral_changes'] or 'row updates in other tables'}")
        if impact["overwritten_rows"]:
            esc("medium", f"overwrites {impact['overwritten_rows']} existing row(s)")
        return risk, reasons

    # ---------------------------------------------------------------- plan
    def plan(self, sql: str, intent: str = "") -> dict[str, Any]:
        with self._lock:
            c = classify(sql, self.policy)
            base = {"statement": c.canonical_sql, "kind": c.kind}
            if c.blocked:
                self.audit.append("blocked", sql=sql[:500], kind=c.kind, reasons=c.reasons, intent=intent)
                return {"status": "blocked", "risk": "blocked", "reasons": c.reasons, **base}
            if c.kind == "select":
                return {"status": "not_a_write", "message": "This is a read-only statement. Use query()."}
            try:
                impact = self._simulate(c)
            except sqlite3.Error as e:
                msg = f"exceeded {self.policy.query_timeout_ms} ms" if "interrupted" in str(e) else str(e)
                self.audit.append("plan_error", sql=c.canonical_sql, error=msg, intent=intent)
                return {"status": "error", "error": f"the statement failed in the dry run; nothing was changed: {msg}", **base}
            risk, reasons = self._assess(c, impact)
            if risk == "blocked":
                self.audit.append("blocked", sql=c.canonical_sql, kind=c.kind, reasons=reasons, intent=intent)
                return {"status": "blocked", "risk": "blocked", "reasons": reasons, "impact": impact, **base}
            plan = Plan(
                plan_id=secrets.token_hex(8), sql=c.canonical_sql or "", kind=c.kind, risk=risk, reasons=reasons,
                impact=impact, intent=intent, expires=self.clock() + self.policy.plan_ttl_s,
                epoch=self._epoch, data_version=self._data_version(),
            )
            self._gc()
            self._plans[plan.plan_id] = plan
            view = self._view(plan)
            (self.home / "pending" / f"{plan.plan_id}.json").write_text(json.dumps(view, indent=2, default=str), encoding="utf-8")
            self.audit.append("plan", plan_id=plan.plan_id, sql=plan.sql, risk=risk, reasons=reasons,
                              rows=impact["rows_affected"], net=impact["net_row_changes"], intent=intent)
            return view

    def _view(self, p: Plan) -> dict[str, Any]:
        return {
            "status": "planned", "plan_id": p.plan_id, "statement": p.sql, "kind": p.kind, "risk": p.risk,
            "requires_approval": p.requires_approval, "reasons": p.reasons, "impact": p.impact,
            "intent": p.intent, "expires_in_s": max(0, int(p.expires - self.clock())),
        }

    def _gc(self) -> None:
        """Drop plans that can no longer be applied, so nobody is asked to approve a dead plan."""
        now = self.clock()
        epoch, version = self._epoch, self._data_version()
        dead = [k for k, p in self._plans.items()
                if p.used or now > p.expires or p.epoch != epoch or p.data_version != version]
        for pid in dead:
            del self._plans[pid]
            (self.home / "pending" / f"{pid}.json").unlink(missing_ok=True)

    def plan_view(self, plan_id: str) -> dict[str, Any] | None:
        with self._lock:
            p = self._plans.get(plan_id)
            return self._view(p) if p else None

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            self._gc()
            return [self._view(p) for p in self._plans.values()]

    # ------------------------------------------------------------ approval
    def approve(self, plan_id: str) -> None:
        """Human side: record approval for a plan. Called by the CLI, never exposed as an MCP tool."""
        if not PLAN_ID_RE.fullmatch(plan_id):
            raise PlanInvalid("malformed plan id")
        (self.home / "approvals" / plan_id).write_text(str(self.clock()), encoding="utf-8")

    def _consume_approval(self, plan_id: str) -> bool:
        f = self.home / "approvals" / plan_id
        if f.exists():
            f.unlink()
            return True
        return False

    # --------------------------------------------------------------- apply
    def apply(self, plan_id: str, approved_via: str | None = None) -> dict[str, Any]:
        with self._lock:
            if not PLAN_ID_RE.fullmatch(plan_id or ""):
                raise PlanInvalid("malformed plan id")
            p = self._plans.get(plan_id)
            if p is None:
                raise PlanInvalid("unknown plan id (expired, superseded by a later change, or the server restarted); "
                                  "call plan_change again")
            if p.used:
                raise PlanInvalid("this plan was already applied")
            if self.clock() > p.expires:
                raise PlanInvalid("this plan expired; call plan_change again")
            if p.epoch != self._epoch or p.data_version != self._data_version():
                raise PlanInvalid("the database changed since this plan was made; call plan_change again")
            if p.risk == "blocked":
                raise Blocked(p.reasons)
            via = approved_via
            if p.requires_approval and not via:
                if self._consume_approval(plan_id):
                    via = "out-of-band"
                else:
                    raise ApprovalRequired(f"plan {plan_id} is {p.risk} risk and needs human approval")
            return self._execute(p, via or "auto (low risk)")

    def _snapshot(self, change_id: str) -> Path:
        size_mb = self.db_path.stat().st_size / 1e6
        if size_mb > self.policy.snapshot_max_mb:
            raise SafeWriteError(
                f"database is {size_mb:.0f} MB, above snapshot_max_mb={self.policy.snapshot_max_mb}; "
                "raise the limit in policy.json to allow undoable writes")
        dest_path = self.home / "snapshots" / f"{change_id}.db"
        dest = sqlite3.connect(dest_path)
        try:
            self._conn.backup(dest)
        finally:
            dest.close()
        snaps = sorted((self.home / "snapshots").glob("chg_*.db"), key=lambda s: s.stat().st_mtime)
        for old in snaps[: -self.policy.keep_snapshots]:
            old.unlink(missing_ok=True)
        return dest_path

    def _execute(self, p: Plan, via: str) -> dict[str, Any]:
        conn = self._conn
        change_id = f"chg_{secrets.token_hex(4)}"
        snap = self._snapshot(change_id)
        conn.execute("BEGIN IMMEDIATE")
        try:
            self._arm(conn, self.policy.query_timeout_ms)
            before = self._counts(conn, self._user_tables(conn))
            cur = conn.execute(p.sql)
            cur.fetchall()
            rowcount = cur.rowcount
            after = self._counts(conn, self._user_tables(conn))
            net = {t: after.get(t, 0) - before.get(t, 0) for t in set(before) | set(after)}
            net = {t: d for t, d in net.items() if d}
            want = p.impact["rows_affected"]
            if (want is not None and rowcount != want) or net != p.impact["net_row_changes"]:
                raise _Diverged(f"expected {want} rows / {p.impact['net_row_changes']}, got {rowcount} / {net}")
            self._disarm(conn)
            conn.execute("COMMIT")
        except BaseException as e:
            self._disarm(conn)
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            snap.unlink(missing_ok=True)
            if isinstance(e, _Diverged):
                self.audit.append("apply_aborted", plan_id=p.plan_id, why=str(e))
                raise PlanInvalid(f"real effect differed from the plan, so it was rolled back: {e}") from e
            if isinstance(e, sqlite3.Error):
                raise SafeWriteError(f"apply failed and was rolled back: {e}") from e
            raise
        self._epoch += 1
        p.used = True
        (self.home / "pending" / f"{p.plan_id}.json").unlink(missing_ok=True)
        self._last_change = {
            "change_id": change_id, "snapshot": snap, "epoch_after": self._epoch,
            "data_version_after": self._data_version(), "sql": p.sql,
        }
        self.audit.append("apply", plan_id=p.plan_id, change_id=change_id, sql=p.sql, risk=p.risk,
                          rows=rowcount, approved_via=via, intent=p.intent)
        return {"status": "applied", "change_id": change_id, "rows_affected": rowcount,
                "approved_via": via, "undo_available": True}

    # ---------------------------------------------------------------- undo
    def undo_last(self) -> dict[str, Any]:
        with self._lock:
            lc = self._last_change
            if not lc:
                raise PlanInvalid("nothing to undo in this session")
            if self._epoch != lc["epoch_after"] or self._data_version() != lc["data_version_after"]:
                raise PlanInvalid("the database changed after that change, so undo was refused to avoid losing newer data")
            snap = sqlite3.connect(lc["snapshot"])
            try:
                snap.backup(self._conn)
            finally:
                snap.close()
            self._epoch += 1
            self._last_change = None
            self.audit.append("undo", change_id=lc["change_id"], sql=lc["sql"])
            return {"status": "undone", "change_id": lc["change_id"], "undid": lc["sql"]}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
