"""Reproducible red-team benchmark for safewrite-mcp.

    python -m bench.run            # writes bench/results.json and bench/RESULTS.md

Compares three ways of letting an agent run SQL against the same seeded database:

  naive   executes whatever it is given (what a minimal "run SQL" MCP server does)
  regex   a good-faith keyword filter: blocks DROP/ALTER/ATTACH/PRAGMA/..., writes
          without the word WHERE, and stacked statements
  safewrite  this project, with no human approval granted

"Damage" means the database's schema or contents changed. Each case runs on a fresh
copy of the same seeded database, and the content hash is compared before and after.
"""

from __future__ import annotations

import json
import platform
import random
import re
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import sqlglot

from safewrite_mcp.audit import AuditLog
from safewrite_mcp.classify import classify
from safewrite_mcp.demo import create_demo_db
from safewrite_mcp.engine import ApprovalRequired, Blocked, GuardedDB, SafeWriteError, db_fingerprint
from safewrite_mcp.policy import Policy

from .corpus import ATTACKS, BENIGN

HERE = Path(__file__).parent
WATCHDOG_S = 2.0
SEED = 1234
BAD = ("damage", "unbounded")          # outcomes where the attack got through
STOPPED = ("blocked", "gated", "contained")


def policy() -> Policy:
    return Policy(protected_tables=["settings"])


class Arena:
    """Hands out fresh copies of one seeded database."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.golden = create_demo_db(tmp / "golden.db")
        self.fp = db_fingerprint(self.golden)
        self._n = 0

    def fresh(self) -> Path:
        self._n += 1
        d = self.tmp / f"case{self._n}"
        d.mkdir()
        p = d / "demo.db"
        shutil.copy(self.golden, p)
        return p


# --------------------------------------------------------------------- systems
def naive_exec(path: Path, sql: str) -> str:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    deadline = time.monotonic() + WATCHDOG_S
    conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1000)
    try:
        conn.executescript(sql)
        return "executed"
    except sqlite3.OperationalError as e:
        return "unbounded" if "interrupted" in str(e) else "error"
    except sqlite3.Error:
        return "error"
    finally:
        conn.close()


DENY = re.compile(r"\b(drop|truncate|alter|attach|detach|pragma|vacuum|load_extension)\b", re.I)


def regex_allows(sql: str) -> bool:
    if DENY.search(sql):
        return False
    if re.search(r"\b(delete|update)\b", sql, re.I) and not re.search(r"\bwhere\b", sql, re.I):
        return False
    if sql.strip().rstrip(";").count(";"):
        return False
    return True


def attack_naive(arena: Arena, sql: str) -> str:
    p = arena.fresh()
    status = naive_exec(p, sql)
    if status == "unbounded":
        return "unbounded"
    return "damage" if db_fingerprint(p) != arena.fp else "harmless"


def attack_regex(arena: Arena, sql: str) -> str:
    if not regex_allows(sql):
        return "blocked"
    return attack_naive(arena, sql)


def attack_safewrite(arena: Arena, sql: str) -> tuple[str, str]:
    """Returns (outcome, static_risk). No human approval is ever granted."""
    p = arena.fresh()
    g = GuardedDB(p, policy=policy())
    label = "harmless"
    static = classify(sql, g.policy)
    try:
        if static.kind == "select" and not static.blocked:
            try:
                g.read(sql)
            except Blocked:
                label = "blocked"
            except SafeWriteError as e:
                label = "contained" if "exceeded" in str(e) else "harmless"
        else:
            plan = g.plan(sql, "benchmark")
            if plan["status"] == "blocked":
                label = "blocked"
            elif plan["status"] == "planned":
                try:
                    g.apply(plan["plan_id"])
                    label = "applied"
                except ApprovalRequired:
                    label = "gated"
    finally:
        g.close()
    if db_fingerprint(p) != arena.fp:
        label = "damage"
    elif label == "applied":
        label = "harmless"
    return label, static.risk


# --------------------------------------------------------------------- attacks
def run_attacks(arena: Arena) -> dict:
    per_system: dict[str, Counter] = {s: Counter() for s in ("naive", "regex", "safewrite")}
    by_cat: dict[str, dict[str, Counter]] = defaultdict(lambda: {s: Counter() for s in per_system})
    gated_static: Counter = Counter()
    misses: list[str] = []
    for cat, raw in ATTACKS:
        sql = raw.replace("__TMP__", str(arena.tmp))
        results = {
            "naive": attack_naive(arena, sql),
            "regex": attack_regex(arena, sql),
        }
        results["safewrite"], static_risk = attack_safewrite(arena, sql)
        for system, label in results.items():
            per_system[system][label] += 1
            by_cat[cat][system][label] += 1
        if results["safewrite"] == "gated":
            gated_static[static_risk] += 1
        if results["safewrite"] in BAD:
            misses.append(raw)
    n = len(ATTACKS)
    return {
        "total": n,
        "per_system": {s: dict(c) for s, c in per_system.items()},
        "got_through": {s: sum(c[b] for b in BAD) for s, c in per_system.items()},
        "stopped": {s: sum(c[b] for b in STOPPED) for s, c in per_system.items()},
        "by_category": {cat: {s: dict(c) for s, c in d.items()} for cat, d in by_cat.items()},
        "gated_total": sum(gated_static.values()),
        "gated_invisible_to_static_analysis": gated_static.get("low", 0),
        "safewrite_misses": misses,
    }


# ---------------------------------------------------------------------- benign
def run_benign(arena: Arena) -> dict:
    out = Counter()
    problems: list[str] = []
    for kind, sql in BENIGN:
        p_ref = arena.fresh()
        is_read = kind == "read"
        if is_read:
            conn = sqlite3.connect(p_ref)
            ref_rows = [list(r) for r in conn.execute(sql).fetchall()]
            conn.close()
            ref_fp = None
        else:
            if naive_exec(p_ref, sql) != "executed":
                problems.append(f"naive failed on corpus statement: {sql}")
            ref_fp = db_fingerprint(p_ref)
            ref_rows = None
        if not regex_allows(sql):
            out["regex_false_positives"] += 1

        p = arena.fresh()
        g = GuardedDB(p, policy=policy())
        try:
            if is_read:
                res = g.read(sql)
                out["reads_total"] += 1
                if res["rows"] == ref_rows:
                    out["reads_identical_to_direct_sql"] += 1
                else:
                    problems.append(f"read mismatch: {sql}")
                out["no_friction"] += 1
                continue
            plan = g.plan(sql, "benchmark")
            out["writes_total"] += 1
            if kind == "bulk":
                out["bulk_total"] += 1
            if plan["status"] != "planned":
                out["blocked_or_error"] += 1
                problems.append(f"benign write not planned ({plan['status']}): {sql}")
                continue
            if plan["requires_approval"]:
                out["needed_approval"] += 1
                if kind == "bulk":
                    out["bulk_needed_approval"] += 1
                g.approve(plan["plan_id"])
            else:
                out["no_friction"] += 1
            g.apply(plan["plan_id"])
            if db_fingerprint(p) == ref_fp:
                out["writes_identical_to_direct_sql"] += 1
            else:
                problems.append(f"write result differs from direct execution: {sql}")
            g.undo_last()
            if db_fingerprint(p) == arena.fp:
                out["writes_undone_exactly"] += 1
        finally:
            g.close()
    out["total"] = len(BENIGN)
    return {**dict(out), "problems": problems}


# ---------------------------------------------------------- undo round-trips
def random_write(rng: random.Random) -> str:
    kind = rng.choice(["upd_orders", "upd_orders2", "del_orders", "upd_customers", "del_customer",
                       "ins_products", "upd_products"])
    a, span = rng.randint(1, 900), rng.choice([0, 1, 2, 4, 8, 15, 40, 80])
    c = rng.randint(1, 150)
    if kind == "upd_orders":
        return f"UPDATE orders SET amount = amount + {rng.randint(1, 50)} WHERE id BETWEEN {a} AND {a + span}"
    if kind == "upd_orders2":
        return f"UPDATE orders SET status = '{rng.choice(['pending', 'shipped', 'cancelled'])}' WHERE id BETWEEN {a} AND {a + span}"
    if kind == "del_orders":
        return f"DELETE FROM orders WHERE id BETWEEN {a} AND {a + span}"
    if kind == "upd_customers":
        return f"UPDATE customers SET status = '{rng.choice(['vip', 'inactive', 'active'])}' WHERE id BETWEEN {c} AND {c + min(span, 40)}"
    if kind == "del_customer":
        return f"DELETE FROM customers WHERE id BETWEEN {c} AND {c + rng.randint(0, 3)}"
    if kind == "ins_products":
        rows = ", ".join(f"('P{rng.randint(1, 999)}', {rng.randint(1, 99)}.5, {rng.randint(0, 50)})" for _ in range(rng.randint(1, 4)))
        return f"INSERT INTO products (name, price, stock) VALUES {rows}"
    return f"UPDATE products SET price = price * 1.05 WHERE id BETWEEN {rng.randint(1, 45)} AND {rng.randint(46, 50)}"


def run_roundtrips(arena: Arena, n: int = 200) -> dict:
    rng = random.Random(SEED)
    p = arena.fresh()
    g = GuardedDB(p, policy=policy())
    planned = changed = restored = approvals = skipped = 0
    try:
        for _ in range(n):
            sql = random_write(rng)
            before = db_fingerprint(p)
            plan = g.plan(sql, "roundtrip")
            if plan["status"] != "planned":
                skipped += 1
                continue
            planned += 1
            if plan["requires_approval"]:
                approvals += 1
                g.approve(plan["plan_id"])
            g.apply(plan["plan_id"])
            if db_fingerprint(p) == before:
                g.undo_last()
                continue
            changed += 1
            g.undo_last()
            if db_fingerprint(p) == before:
                restored += 1
        audit_path = g.home / "audit.jsonl"
        audit_copy = arena.tmp / "audit_for_tamper.jsonl"
        shutil.copy(audit_path, audit_copy)
    finally:
        g.close()
    return {"trials": n, "planned": planned, "skipped": skipped, "needed_approval": approvals,
            "changed_the_database": changed, "restored_byte_identical": restored, "audit_copy": str(audit_copy)}


# ------------------------------------------------------------------- latency
def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]


def run_latency(tmp: Path) -> list[dict]:
    rows = []
    for n_orders in (1_000, 10_000, 100_000):
        db = create_demo_db(tmp / f"lat_{n_orders}.db", customers=max(200, n_orders // 5), orders=n_orders)
        g = GuardedDB(db, home=tmp / f"lat_{n_orders}_home", policy=policy())
        size_mb = db.stat().st_size / 1e6
        try:
            targeted, tenth, apply_ms = [], [], []
            for _ in range(30):
                t = time.perf_counter()
                g.plan("UPDATE orders SET status='x' WHERE id=500", "bench")
                targeted.append((time.perf_counter() - t) * 1000)
            for _ in range(10):
                t = time.perf_counter()
                g.plan(f"UPDATE orders SET status='x' WHERE id <= {n_orders // 10}", "bench")
                tenth.append((time.perf_counter() - t) * 1000)
            for i in range(10):
                plan = g.plan(f"UPDATE orders SET amount = amount + 1 WHERE id = {600 + i}", "bench")
                t = time.perf_counter()
                g.apply(plan["plan_id"])
                apply_ms.append((time.perf_counter() - t) * 1000)
            raw = []
            conn = sqlite3.connect(db, isolation_level=None)
            for i in range(10):
                t = time.perf_counter()
                conn.execute(f"UPDATE orders SET amount = amount + 1 WHERE id = {700 + i}")
                raw.append((time.perf_counter() - t) * 1000)
            conn.close()
        finally:
            g.close()
        rows.append({
            "orders": n_orders, "db_mb": round(size_mb, 2),
            "plan_targeted_p50_ms": round(statistics.median(targeted), 2), "plan_targeted_p95_ms": round(pct(targeted, 0.95), 2),
            "plan_10pct_p50_ms": round(statistics.median(tenth), 2),
            "apply_with_snapshot_p50_ms": round(statistics.median(apply_ms), 2),
            "raw_update_p50_ms": round(statistics.median(raw), 3),
        })
    return rows


# ------------------------------------------------------------- audit tamper
def run_tamper(log_path: Path, tmp: Path) -> dict:
    rng = random.Random(SEED)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert AuditLog(log_path).verify()["ok"], "pristine log must verify"
    res = {"log_entries": len(lines)}
    for kind in ("modify", "delete", "reorder"):
        detected = 0
        trials = 50
        for _ in range(trials):
            L = list(lines)
            i = rng.randrange(len(L) - 1)          # never the final line: tail truncation is a known limit
            if kind == "modify":
                e = json.loads(L[i])
                e["event"] = "read" if e["event"] != "read" else "apply"
                L[i] = json.dumps(e, sort_keys=True)
            elif kind == "delete":
                del L[i]
            else:
                L[i], L[i + 1] = L[i + 1], L[i]
            f = tmp / "tampered.jsonl"
            f.write_text("\n".join(L) + "\n", encoding="utf-8")
            if not AuditLog(f).verify()["ok"]:
                detected += 1
        res[kind] = {"trials": trials, "detected": detected}
    return res


# ----------------------------------------------------------------- reporting
def markdown(r: dict) -> str:
    a, b, rt, lat, tm, env = r["attacks"], r["benign"], r["roundtrips"], r["latency"], r["tamper"], r["env"]
    n = a["total"]
    s = a["per_system"]
    L = [
        "# Benchmark results",
        "",
        f"Generated {env['date']} · Python {env['python']} · SQLite {env['sqlite']} · sqlglot {env['sqlglot']} · seed {SEED}",
        "",
        "Reproduce: `python -m bench.run`. The corpora are written by the project author (see `bench/corpus.py`), "
        "so these numbers measure this design against these cases; they are not a security guarantee.",
        "",
        f"## 1. Red team: {n} attacks, no human approval granted",
        "",
        "| System | Reached the data or ran unbounded | Blocked | Held for approval | Contained by timeout | Harmless |",
        "|---|---|---|---|---|---|",
    ]
    for name, label in (("naive", "No guard (executes anything)"), ("regex", "Keyword filter"), ("safewrite", "safewrite-mcp")):
        c = s[name]
        L.append(f"| {label} | **{a['got_through'][name]}/{n}** | {c.get('blocked', 0)} | {c.get('gated', 0)} | {c.get('contained', 0)} | {c.get('harmless', 0)} |")
    L += [
        "",
        f"Of the {a['gated_total']} attacks safewrite held for approval, **{a['gated_invisible_to_static_analysis']}** looked "
        "low-risk to static analysis, which would have let them run without approval. Only the dry run revealed their real effect.",
        "",
        "| Category | Attacks | No guard got through | Keyword filter got through | safewrite got through |",
        "|---|---|---|---|---|",
    ]
    for cat, d in a["by_category"].items():
        tot = sum(d["naive"].values())
        gt = {k: sum(v.get(x, 0) for x in BAD) for k, v in d.items()}
        L.append(f"| {cat} | {tot} | {gt['naive']} | {gt['regex']} | {gt['safewrite']} |")
    if a["safewrite_misses"]:
        L += ["", "**safewrite misses:**"] + [f"- `{m}`" for m in a["safewrite_misses"]]
    L += [
        "",
        f"## 2. Everyday workload: {b['total']} legitimate statements "
        f"({b['total'] - b.get('bulk_total', 0)} routine, {b.get('bulk_total', 0)} legitimate bulk operations)",
        "",
        f"- Routine statements that ran with no friction: **{b.get('no_friction', 0)}/{b['total'] - b.get('bulk_total', 0)}**",
        f"- Legitimate bulk operations held for one approval (by design): **{b.get('bulk_needed_approval', 0)}/{b.get('bulk_total', 0)}**; blocked or errored: {b.get('blocked_or_error', 0)}",
        f"- Reads returning results identical to direct SQL: **{b.get('reads_identical_to_direct_sql', 0)}/{b.get('reads_total', 0)}**",
        f"- Writes leaving the database byte-identical to direct execution: **{b.get('writes_identical_to_direct_sql', 0)}/{b.get('writes_total', 0)}**",
        f"- Writes undone back to the exact original state: **{b.get('writes_undone_exactly', 0)}/{b.get('writes_total', 0)}**",
        f"- Keyword filter false positives: {b.get('regex_false_positives', 0)}/{b['total']}",
    ]
    if b["problems"]:
        L += ["", "**Problems:**"] + [f"- {p}" for p in b["problems"]]
    L += [
        "",
        f"## 3. Write → undo round-trips ({rt['trials']} randomized statements)",
        "",
        f"- {rt['changed_the_database']} statements changed the database ({rt['needed_approval']} needed approval, {rt['skipped']} refused)",
        f"- **{rt['restored_byte_identical']}/{rt['changed_the_database']}** restored a byte-identical database after undo",
        "",
        "## 4. Latency (median unless noted)",
        "",
        "| Orders | DB size | Preview, 1 row | Preview, 1 row p95 | Preview, 10% of table | Apply incl. snapshot | Raw UPDATE |",
        "|---|---|---|---|---|---|---|",
    ]
    for x in lat:
        L.append(f"| {x['orders']:,} | {x['db_mb']} MB | {x['plan_targeted_p50_ms']} ms | {x['plan_targeted_p95_ms']} ms | "
                 f"{x['plan_10pct_p50_ms']} ms | {x['apply_with_snapshot_p50_ms']} ms | {x['raw_update_p50_ms']} ms |")
    L += [
        "",
        f"## 5. Audit-log tamper detection ({tm['log_entries']} entries)",
        "",
        f"- Edited entry: **{tm['modify']['detected']}/{tm['modify']['trials']}** detected",
        f"- Deleted entry: **{tm['delete']['detected']}/{tm['delete']['trials']}** detected",
        f"- Reordered entries: **{tm['reorder']['detected']}/{tm['reorder']['trials']}** detected",
        "- Known limit: truncating the end of the log is not detectable by a hash chain alone.",
        "",
        "## Metric definitions and caveats",
        "",
        "- *Reached the data or ran unbounded*: the database's schema/contents changed, or a read ran until the harness stopped it at "
        f"{WATCHDOG_S:.0f} s. Writes to files outside the database (e.g. ATTACH creating a file) are not counted as damage.",
        "- *Keyword filter* is a baseline written for this benchmark; real filters vary.",
        "- The corpus is small and author-written. Thresholds were set before the first run (see `policy.py`).",
    ]
    return "\n".join(L) + "\n"


def main() -> None:
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="safewrite-bench-") as d:
        tmp = Path(d)
        arena = Arena(tmp)
        print(f"[1/5] red team ({len(ATTACKS)} attacks x 3 systems)...", flush=True)
        attacks = run_attacks(arena)
        print("[2/5] benign workload...", flush=True)
        benign = run_benign(arena)
        print("[3/5] write/undo round-trips...", flush=True)
        rt = run_roundtrips(arena)
        print("[4/5] latency at 1k / 10k / 100k rows...", flush=True)
        latency = run_latency(tmp)
        print("[5/5] audit tamper detection...", flush=True)
        tamper = run_tamper(Path(rt.pop("audit_copy")), tmp)
        results = {
            "env": {"date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "python": platform.python_version(),
                    "sqlite": sqlite3.sqlite_version, "sqlglot": sqlglot.__version__, "platform": platform.platform()},
            "attacks": attacks, "benign": benign, "roundtrips": rt, "latency": latency, "tamper": tamper,
        }
    (HERE / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    md = markdown(results)
    (HERE / "RESULTS.md").write_text(md, encoding="utf-8")
    sys.stdout.buffer.write((md + "\n").encode("utf-8"))
    sys.stdout.flush()
    print(f"done in {time.time() - t0:.0f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
