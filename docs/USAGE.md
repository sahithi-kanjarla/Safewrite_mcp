# Usage

Worked example, setup details, policy settings and testing. For what it defends against see [THREAT_MODEL.md](THREAT_MODEL.md); for how it is built see [DESIGN.md](DESIGN.md).

## Why

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

## Results

Measured by `python -m bench.run` (seeded, reproducible, full report in [`bench/RESULTS.md`](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/bench/RESULTS.md)). The 72 attacks and 36 legitimate statements were written by the author, so read these as "this design against these cases", not as a security guarantee.

| 72 red-team statements, no human approval | Reached the data or ran unbounded |
|---|---|
| No guard (executes anything) | **60 / 72** |
| Keyword filter (blocks DROP/ALTER/…, writes without `WHERE`, stacked statements) | **31 / 72** |
| **safewrite-mcp** | **0 / 72** (32 blocked, 37 held for approval, 3 aborted by timeout) |

- **10 of the 37 held attacks looked harmless to static analysis** (`WHERE id>=0`, `WHERE id IN (SELECT id …)`, a 1-row delete that cascades into other tables). Only the dry run, which measures what a statement actually does, caught them.
- **31/31 routine statements ran with no friction**; 5/5 legitimate bulk operations were held for a single approval (by design). Read results and the resulting database content were identical to running the SQL directly (10/10 reads, 26/26 writes).
- **196/196** randomized write → undo round-trips restored a byte-identical database.
- Median **6.4–20.8 ms** to preview a single-row change (26.0 ms for a 10% update at 100k rows); **15.6–71.0 ms** to apply including the undo snapshot, for 1k–100k orders. Measured on a Windows 11 laptop (`Windows-11-10.0.26200-SP0`, Python 3.13.8) in one run (2026-10-28); it varies by machine and run, and `python -m bench.run` reproduces it.
- Audit log: **150/150** edits, deletions, and reorderings detected.

## A real session

Captured from [`examples/walkthrough.py`](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/examples/walkthrough.py) (`examples/walkthrough.txt`). Highlights:

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
- Snapshot-based undo is O(database size) (capped by `snapshot_max_mb`).
- The audit log and pending plans live in `<db dir>/.safewrite/`. Check integrity any time with `safewrite-mcp verify --db app.db`.

Policy lives in `<db dir>/.safewrite/policy.json` (all keys optional):

```json
{ "protected_tables": ["settings"], "auto_approve_max_rows": 10, "hard_max_rows": 1000,
  "allow_ddl": false, "allow_drop": false, "approval_mode": "elicit" }
```

- `allow_drop` (default `false`): `DROP` and `TRUNCATE` are blocked, and the block message tells a person to set this to true and restart the server. When true, a `DROP TABLE` is planned as high risk, always needs human approval, and `undo_last_change` restores the table and its rows (including rows removed by cascades into other tables, which the plan lists). Protected tables stay blocked even when this is true.
- `allow_ddl` (default `false`): `CREATE` and `ALTER` are blocked, with a message that points to this setting. When true they are classified as medium risk, so they need approval. This path is covered by classifier tests only; unlike `allow_drop`, the full plan, apply and undo flow for it has not been tested.

Policy is read when the server starts, so changes to `policy.json` take effect after a restart.

## Testing

```bash
pytest --cov=safewrite_mcp      # 263 tests, 95% line coverage
python -m bench.run             # regenerates bench/RESULTS.md and results.json
python examples/walkthrough.py  # the session above, live
```

The suite passes on `mcp` 2.2.0 and 2.3.0. It includes in-process MCP client tests, real subprocess stdio tests (terminal-approval CLI, elicitation accept/decline, `out_of_band` ignoring a client that would auto-approve, state surviving restarts), and the full attack corpus as regression tests. Coverage is measured in-process, so branches exercised only through the subprocess tests (the elicitation path) are tested but not counted.
