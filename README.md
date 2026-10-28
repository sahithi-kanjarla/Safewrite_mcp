# safewrite-mcp

Most "run SQL" MCP servers hand the model an `execute(sql)` tool, so one prompt injection, one missing `WHERE`, or one cascading foreign key can destroy your data.

**safewrite-mcp is a database MCP server where an AI agent can propose writes but cannot make them without a human, and every change is previewed, audited, and undoable.**

## How it works

```
 agent                          safewrite-mcp                              human
   │  query(sql) ─────────────▶ read-only connection, row cap, timeout
   │  plan_change(sql, why) ──▶ parse → judge → DRY RUN in a transaction
   │                            that is always rolled back
   │  ◀── exact rows, cascades, before/after, risk, plan_id (expires)
   │  apply_change(plan_id) ──▶ low risk? apply.  Otherwise ─────────────▶ approve?
   │                            snapshot → run → verify it matched the plan   (elicitation
   │  ◀── applied / approval_required                                         or terminal)
   │  undo_last_change() ─────▶ restore snapshot (refused if the DB changed since)
```

The agent has no tool, argument, or code path that approves its own plan.

<!-- TODO: demo GIF here -->

**Headline results** (from [`bench/RESULTS.md`](bench/RESULTS.md); author-written corpora, so not a security guarantee):

- Red team, 72 attacks, no human approval granted: safewrite-mcp reached the data **0/72** (No guard: **60/72**, keyword filter: **31/72**)
- Routine statements that ran with no friction: **31/31**
- **196/196** restored a byte-identical database after undo

## Tested with

The "risky instructions" in these tests (delete customer 1, `DROP TABLE`) were given by me, the author, on purpose to exercise the guard. They are not mistakes the AI made by itself.

| Client | What I observed |
|---|---|
| Claude Code (headless, throwaway demo database) | Asked to delete customer 1. Rated high risk (4 cascaded orders). The apply was declined because no human was present. The database was unchanged and the audit chain verified. |
| VS Code Copilot Agent mode | Update of customer 7 applied with no safewrite approval (low risk). Delete of customer 1 was held, needed terminal approval, then applied. `DROP TABLE` was blocked by policy. Undo: after a delete of customer 2 was approved and applied (it also removed 7 related orders), "undo the last change" ran and Copilot reported customer 2 was present again. Tested with VS Code 1.143.1 on 2026-10-27. |
| Claude Desktop | Not tested. |
| Cursor | Not tested. |

## Results

Measured by `python -m bench.run` (seeded, reproducible, full report in [`bench/RESULTS.md`](bench/RESULTS.md)). The 72 attacks and 36 legitimate statements were written by the author, so read these as "this design against these cases", not as a security guarantee.

| 72 red-team statements, no human approval | Reached the data or ran unbounded |
|---|---|
| No guard (executes anything) | **60 / 72** |
| Keyword filter (blocks DROP/ALTER/…, writes without `WHERE`, stacked statements) | **31 / 72** |
| **safewrite-mcp** | **0 / 72** (32 blocked, 37 held for approval, 3 aborted by timeout) |

- **10 of the 37 held attacks looked harmless to static analysis** (`WHERE id>=0`, `WHERE id IN (SELECT id …)`, a 1-row delete that cascades into other tables). Only the dry run, which measures what a statement actually does, caught them.
- **31/31 routine statements ran with no friction**; 5/5 legitimate bulk operations were held for a single approval (by design). Read results and the resulting database content were identical to running the SQL directly (10/10 reads, 26/26 writes).
- **196/196** randomized write → undo round-trips restored a byte-identical database.
- Median **5.6–23.3 ms** to preview a single-row change (28.3 ms for a 10% update at 100k rows); **15.0–70.3 ms** to apply including the undo snapshot, for 1k–100k orders. Measured on a Windows 11 laptop (`Windows-11-10.0.26200-SP0`, Python 3.13.8) in one run (2026-10-27); it varies by machine and run, and `python -m bench.run` reproduces it.
- Audit log: **150/150** edits, deletions, and reorderings detected.

## A real session

Captured from [`examples/walkthrough.py`](examples/walkthrough.py) (`examples/walkthrough.txt`). Highlights:

```
[agent] Remove the test customer, id 1.
   tool: plan_change
   -> status=planned risk=high rows=1 cascades={'orders': -4}
   tool: apply_change -> approval_required        # customers still: 200

[human] $ safewrite-mcp approve 9e0d3c62e87a073b --db shop.db --yes
   This will delete 1 row from customers and 4 rows from orders (cascade/trigger). customers would go from 200 to 199 rows. High risk. It can be undone.

   plan  9e0d3c62e87a073b   risk: HIGH
   SQL   DELETE FROM customers WHERE id = 1
   rows  1 of 200 in 'customers'      cascades  {'orders': -4}

[agent] tool: apply_change -> applied (out-of-band)     # customers 199, orders 996
[human] tool: undo_last_change -> undone                # customers 200, orders 1000

[agent (prompt-injected)] DELETE FROM customers -- WHERE id=1
   -> risk=high rows=200 cascades={'orders': -1000}
   SQL that would actually run: 'DELETE FROM customers'
```

## Quick start

```bash
git clone https://github.com/sahithi-kanjarla/Safewrite_mcp.git
cd Safewrite_mcp
pip install -e ".[dev]"                 # tested on Python 3.13
safewrite-mcp demo-db demo.db           # a seeded demo database
safewrite-mcp serve --db demo.db        # MCP server over stdio
```

Point an MCP client at it (tested end to end with Claude Code 2.1 in headless mode and with the MCP Python client over real stdio; not tested with Claude Desktop):

```json
{ "mcpServers": { "safewrite": {
    "command": "python",
    "args": ["-m", "safewrite_mcp", "serve", "--db", "/absolute/path/to/demo.db"] } } }
```

When a plan needs approval and the client can't prompt you, the tool replies with a command to run in **your** terminal:

```bash
safewrite-mcp approve <plan_id> --db demo.db      # shows the plan, asks y/N
```

### Connect a client

**Claude Code** (any project, any SQLite file):

```bash
pip install git+https://github.com/sahithi-kanjarla/Safewrite_mcp.git
claude mcp add safewrite -- python -m safewrite_mcp serve --db /absolute/path/to/app.db
```

**Claude Desktop / Cursor / other MCP clients**: use the JSON block above. Use absolute paths, and the same Python that has `safewrite-mcp` installed.

Notes:
- Start-up imports the MCP SDK, which can be slow on a loaded or cold machine. If a client reports a connect timeout, raise it (Claude Code: `MCP_TIMEOUT=120000`).
- To protect a live project, point `--db` at a copy first, or keep `approval_mode: "out_of_band"` so only your terminal can approve.
- The audit log and pending plans live in `<db dir>/.safewrite/`. Check integrity any time with `safewrite-mcp verify --db app.db`.

Policy lives in `<db dir>/.safewrite/policy.json` (all keys optional):

```json
{ "protected_tables": ["settings"], "auto_approve_max_rows": 10, "hard_max_rows": 1000,
  "allow_ddl": false, "allow_drop": false, "approval_mode": "elicit" }
```

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

## Limitations (read before relying on this)

- **Small harmful writes pass by design.** A write touching ≤ `auto_approve_max_rows` rows with no cascade is auto-approved. `UPDATE customers SET email='attacker@x.com' WHERE id=7` is indistinguishable from a legitimate edit. Set the threshold to 0 to approve everything.
- It cannot judge whether a change is *correct*, only how large and how reversible it is.
- SQLite only, one writer. Undo is one level deep and lasts for the server session. Snapshot-based undo is O(database size) (capped by `snapshot_max_mb`).
- Any change to the database invalidates other pending plans (safer, but means re-planning).
- The audit chain is tamper-*evident*: truncating the end of the log isn't detectable without an external anchor.
- Elicitation is only as trustworthy as the client; use `out_of_band` for autonomous agents.
- Benchmark corpora are author-written; the keyword-filter baseline is one reasonable filter, not all filters.

More detail: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (what it does and does not defend against) and [`docs/COMPARISON.md`](docs/COMPARISON.md) (how it differs from other categories of database MCP servers, and what it trades off).

## Testing

```bash
pytest --cov=safewrite_mcp      # 254 tests, 95% line coverage
python -m bench.run             # regenerates bench/RESULTS.md and results.json
python examples/walkthrough.py  # the session above, live
```

The suite passes on `mcp` 2.2.0 and 2.3.0. It includes in-process MCP client tests, real subprocess stdio tests (terminal-approval CLI, elicitation accept/decline, `out_of_band` ignoring a client that would auto-approve, state surviving restarts), and the full attack corpus as regression tests. Coverage is measured in-process, so branches exercised only through the subprocess tests (the elicitation path) are tested but not counted.

## Layout

```
safewrite_mcp/  classify.py  static SQL analysis      engine.py  dry run · apply · undo
                audit.py     hash-chained log          server.py  MCP tools/resources/prompt
                policy.py    knobs                     cli.py     serve · approve · verify
bench/          corpus.py (attacks + benign)  run.py (3 systems, latency, undo, tamper)
tests/  examples/  docs/claims.md
```

MIT licensed.
