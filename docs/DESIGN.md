# Design

How safewrite-mcp is built. Moved here from the README.

## MCP surface

| Kind | Name | Purpose |
|---|---|---|
| tool | `query` | One read-only `SELECT`: read-only connection, 200-row cap, 2 s timeout |
| tool | `plan_change(sql, intent)` | Dry-run a write; returns a plain-English `summary`, impact, diff, risk, `plan_id`. Intent is required and logged |
| tool | `apply_change(plan_id)` | Apply a plan. Takes **only** a plan id, nothing that could approve |
| tool | `undo_last_change` | Restore the pre-change snapshot, if nothing else has changed since |
| tool | `list_tables`, `pending_changes`, `audit_tail`, `verify_audit` | Inspection |
| resource | `db://schema`, `policy://current` | Context for the model |
| prompt | `safe_cleanup(goal)` | A careful plan → explain → apply workflow |

## Design decisions

1. **Parse, judge, then execute the regenerated SQL, never the original text.** The statement is parsed to an AST (sqlglot), judged, and the SQL that runs is regenerated from that same AST. Comments, casing, quoting, and whitespace tricks cannot make the analyzed statement differ from the executed one. `DELETE FROM customers -- WHERE id=1` is seen for what it is: no `WHERE`.
2. **Fail closed.** Unparseable SQL, unknown statement types (`PRAGMA`, `ATTACH`, `VACUUM`, transaction control), stacked statements, schema-qualified tables, and file/extension functions are blocked.
3. **Measure, don't guess.** Static rules can't know how many rows a statement touches or what a foreign key will cascade into. The dry run executes the statement in a transaction that is always rolled back and diffs row counts for every table.
4. **Defense in depth on reads.** `query` also uses a read-only SQLite connection, so a classifier bug still can't write.
5. **Plans are bound to database state.** A plan expires, is single-use, and is invalidated by any change to the database, including one by another process. At apply time the real effect is compared to the plan and rolled back on any mismatch.
6. **Undo can't destroy newer data.** It restores a snapshot, but only if the database is exactly as the last change left it.
7. **Approval can't come from the agent.** Two findings from building this against the MCP Python SDK 2.2.0: server→client elicitation works when the test client connects in `legacy` mode but raises `NoBackChannelError` in the default `auto` mode, and the SDK's own docs note a client *may answer an elicitation automatically* instead of asking a person. So there are two approval paths: elicitation when it works, and an out-of-band terminal command that only the human can run (also the automatic fallback). `approval_mode: "out_of_band"` disables elicitation entirely, for autonomous clients. Which mode real clients such as Claude Desktop use is untested here.
8. **Tamper-evident audit.** JSON Lines with each entry hashing the previous one; every plan, block, apply, and undo is logged with the agent's stated intent.

## Layout

```
safewrite_mcp/  classify.py  static SQL analysis      engine.py  dry run · apply · undo
                audit.py     hash-chained log          server.py  MCP tools/resources/prompt
                policy.py    knobs                     cli.py     serve · approve · verify
bench/          corpus.py (attacks + benign)  run.py (3 systems, latency, undo, tamper)
tests/  examples/  docs/claims.md
```
