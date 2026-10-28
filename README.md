# safewrite-mcp

An MCP server that sits between an AI agent and your SQLite database. Before a write runs, it tests it safely and shows what it would really do, for example "deletes 1 customer and 4 orders". Small changes go through, risky ones wait for your approval, dangerous ones are blocked, and the last change can be undone.

<!-- TODO: demo GIF here -->

## How it works

- **Low risk** changes run immediately.
- **Risky** changes are held until you approve them in your terminal (or in the client, if it supports that).
- **Dangerous** changes, such as `DROP TABLE`, are blocked by policy.
- **Every step is logged** in a tamper-evident audit log you can verify with `safewrite-mcp verify`.

## Example

Abridged output of [`examples/walkthrough.py`](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/examples/walkthrough.py):

```
[agent] Remove the test customer, id 1.
   -> status=planned risk=high rows=1 cascades={'orders': -4}
   tool: apply_change -> approval_required (plan cd4b97ecfa6853b5 is high risk and needs human approval)
[human] $ safewrite-mcp approve cd4b97ecfa6853b5 --db shop.db --yes
   This will delete 1 row from customers and 4 rows from orders (cascade/trigger). customers would go from 200 to 199 rows. High risk. It can be undone.
   tool: apply_change -> applied (out-of-band)
   customers now: 199, orders now: 996
[human] That removed too much. Undo.
   tool: undo_last_change -> undone
   customers: 200, orders: 1000
```

## Results

From [`bench/RESULTS.md`](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/bench/RESULTS.md). Run `python -m bench.run` to reproduce them.

72 red-team attacks, with no human approval granted:

| System | Reached the data or ran unbounded |
|---|---|
| No guard (executes anything) | **60/72** |
| Keyword filter | **31/72** |
| safewrite-mcp | **0/72** |

The 72 attacks were written by the author. This measures the design against these cases. It is not a security guarantee.

- **31/31** routine statements ran with no friction.
- **196/196** write-then-undo round-trips restored a byte-identical database.

Full report: [`bench/RESULTS.md`](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/bench/RESULTS.md)

## Install and connect

Install from the repo for now:

```bash
pip install git+https://github.com/sahithi-kanjarla/Safewrite_mcp.git
safewrite-mcp demo-db demo.db    # optional: a seeded demo database
```

Use absolute paths. Use the same Python that has `safewrite-mcp` installed.

**Claude Code**

```bash
claude mcp add safewrite -- python -m safewrite_mcp serve --db /absolute/path/to/app.db
```

**VS Code** (`.vscode/mcp.json`)

```json
{
  "servers": {
    "safewrite": {
      "type": "stdio",
      "command": "/absolute/path/to/python",
      "args": ["-m", "safewrite_mcp", "serve", "--db", "/absolute/path/to/app.db"]
    }
  }
}
```

**Approve a held change.** Some changes are held for a human. If your client cannot ask you, the tool replies with a command to run in your own terminal:

```bash
safewrite-mcp approve <plan_id> --db app.db
```

It shows the plan and asks y/N. If you leave out the plan id, it lets you pick from the pending plans.

## Tested with

The "risky instructions" in these tests (delete customer 1, `DROP TABLE`) were given by me, the author, on purpose to exercise the guard. They are not mistakes the AI made by itself.

| Client | What I observed |
|---|---|
| Claude Code (headless, throwaway demo database) | Asked to delete customer 1. Rated high risk (4 cascaded orders). The apply was declined because no human was present. The database was unchanged and the audit chain verified. |
| VS Code Copilot Agent mode | Update of customer 7 applied with no safewrite approval (low risk). Delete of customer 1 was held, needed terminal approval, then applied. `DROP TABLE` was blocked by policy. Undo: after a delete of customer 2 was approved and applied (it also removed 7 related orders), "undo the last change" ran and Copilot reported customer 2 was present again. Tested with VS Code 1.143.1 on 2026-10-27. |
| Claude Desktop | Not tested. |
| Cursor | Not tested. |

## Limitations

- **Small harmful writes pass by design.** A write that touches few rows and has no cascade is auto-approved. `UPDATE customers SET email='attacker@x.com' WHERE id=7` looks the same as a real edit. Set `auto_approve_max_rows` to 0 to approve everything.
- **Approval by prompt is only as trustworthy as the client.** A client may answer it automatically. For autonomous agents, set `approval_mode: "out_of_band"`.
- **SQLite only, one writer.** Undo is one level deep and lasts for the server session.
- **An agent with terminal access could approve its own plan.** Approval is only as strong as the separation between the agent and your terminal.

More: [Usage](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/docs/USAGE.md), [Design](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/docs/DESIGN.md), [Threat model](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/docs/THREAT_MODEL.md), [Comparison](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/docs/COMPARISON.md)

## License

MIT. See [`LICENSE`](https://github.com/sahithi-kanjarla/Safewrite_mcp/blob/main/LICENSE).
