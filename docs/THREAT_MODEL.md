# Threat model

What safewrite-mcp is meant to stop, and what it is not. Everything here is derived from the code in `safewrite_mcp/` and the tests in `tests/`. For measured results see [`bench/RESULTS.md`](../bench/RESULTS.md) (author-written corpora, not a guarantee).

## The setting

An AI agent talks to one SQLite database through MCP tools. The agent is **untrusted-but-useful**: it may be wrong, or it may be steered by text it read. The human operator and the machine safewrite runs on are trusted.

The agent gets `query` (read-only) and `plan_change` / `apply_change` / `undo_last_change`. No tool takes an approval argument; approval comes from MCP elicitation or from `safewrite-mcp approve <plan_id>` run in a terminal (`approval_mode: "out_of_band"` disables elicitation).

## What it defends against

| Threat | How the code handles it |
|---|---|
| **A mistaken agent** (wrong table, wrong condition, wrong idea of scope) | `plan_change` runs the statement in a transaction that is always rolled back and reports the measured rows, per-table deltas and before/after sample. Writes over `auto_approve_max_rows`, over `max_table_fraction` of a table, or with collateral changes need a human. Writes over `hard_max_rows` are refused. |
| **Hidden instructions in text the agent reads** (prompt injection) | safewrite does not detect injection. It limits what an injected agent can *do*: the agent cannot approve its own plan, DDL/DROP/PRAGMA/ATTACH are blocked by default, and anything large or cascading is held for a person who sees the real impact. |
| **A missing `WHERE`** | `UPDATE`/`DELETE` with no `WHERE` is rated high risk statically. Always-true conditions (`1=1`, `TRUE`, `x=x`, ...) are too. Conditions that look harmless but match everything (e.g. `id >= 0`) are caught by the dry run's row count, not by pattern matching. |
| **Cascades and triggers** | The dry run diffs row counts of *every* user table, so deletes that cascade through foreign keys (the connection enables `foreign_keys`) or fire triggers show up as collateral changes and are rated high. At apply time the real effect is compared to the plan and rolled back on any mismatch. |
| **Comment / quoting / casing tricks** | The SQL is parsed (sqlglot), judged, and the SQL that runs is *regenerated from the same AST* with comments stripped. `DELETE FROM t -- WHERE id=1` is judged and executed as a `DELETE` with no `WHERE`. Unparseable SQL, stacked statements, schema-qualified tables, unknown statement types, and `load_extension`/`readfile`/`writefile`/`edit`/`fts3_tokenizer`/`zeroblob`/`randomblob` are blocked (fail closed). |
| **Stale or replayed plans** | Plans expire (`plan_ttl_s`), are single-use, and are invalidated by any change to the database, including one made by another process (checked via `PRAGMA data_version`). |
| **Runaway reads/dry runs** | `query` uses a read-only connection, a row cap and a timeout. The dry run and apply also run under the timeout. |
| **Regret after an approved change** | `undo_last_change` restores a pre-change snapshot, and refuses if the database changed since. |
| **Silent history rewriting by mistake or casual edit** | The audit log is hash-chained; `verify` detects edited, deleted or reordered entries (the benchmark and `tests/test_policy_audit.py` exercise this). |

## What it does NOT defend against

- **Small harmful edits under the auto-approve limit.** A write that touches at most `auto_approve_max_rows` rows with no cascade is low risk and applies with no human. `UPDATE customers SET email='attacker@x.com' WHERE id=7` is indistinguishable from a legitimate edit. Set the threshold to 0 to require approval for everything. Repeating many small writes is also not rate-limited.
- **A wrong change that looks fine in the preview.** safewrite measures size and reversibility, not correctness. A human approving without reading the plan defeats the gate.
- **A compromised client.** With `approval_mode: "elicit"`, the client answers the prompt, and a client may answer automatically. Use `out_of_band` for autonomous agents. Which real clients auto-answer is untested here.
- **A malicious human, or any process with the agent's filesystem access.** Approval is a file written under `<db dir>/.safewrite/approvals/`. Anyone who can write there, or open the database file directly, bypasses everything. If the agent also has a shell or file tool on the same machine, it can bypass safewrite entirely; run it without such tools or in a separate account/container.
- **Reading data.** `query` can read any table. `protected_tables` blocks *writes* only. Data exfiltration through reads is out of scope.
- **Truncating the end of the audit log.** A hash chain detects edits, deletions in the middle and reordering, but removing the last N entries leaves a valid chain. Anyone able to rewrite the whole file can also rebuild it. Ship the log off the machine if that matters.
- **Other databases.** SQLite only, one writer. The SQL dialect, `PRAGMA data_version`, and snapshotting are SQLite-specific.
- **Undo beyond one level.** Undo covers the last change in the current server session only, and snapshots are capped by `snapshot_max_mb`; writes above it are refused rather than applied without undo.
- **Side effects outside the database file** (e.g. an `ATTACH` creating a file is blocked, but anything else on the host is out of scope).

## Assumptions

- The machine, the Python environment and the `.safewrite/` directory are not controlled by the agent.
- The human reads the plan before approving.
- Policy thresholds fit your data; they are conservative defaults, not tuned to your workload.
