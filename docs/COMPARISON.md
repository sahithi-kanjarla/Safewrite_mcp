# How safewrite-mcp compares, by category

Categories only. No specific products are named and no claims are made about any product; each description is what servers of that kind *typically* do, and any given product may differ. Check the one you use.

| | (a) Plain "run SQL" server | (b) Read-only database server | (c) Gateway / proxy filtering tool calls | (d) safewrite-mcp |
|---|---|---|---|---|
| Typical shape | One `execute(sql)` tool | Query tools on a read-only connection or credential | Sits between client and server; allow/deny rules on tool names, arguments or patterns | Reads plus a propose → preview → approve → apply → undo flow |
| Can the agent write? | Yes, anything the DB user can | No | Whatever the upstream server allows and the rules permit | Yes, but only through a plan; large or risky writes need a human |
| How risk is judged | Not judged | Not needed for writes | Rules on the request (names, patterns, sometimes SQL text) | Parsed SQL checks, then the **measured** effect of a rolled-back dry run |
| Undo | Database backups, if you have them | N/A | Usually none of its own | Snapshot restore of the last change (session-scoped, size-capped) |
| Audit | Depends on the server | Depends on the server | Often central request logging | Hash-chained log, tamper-evident |
| Agent usefulness | Full | Read/analyse only | Depends on rules | Reads, small writes, and approved bulk writes |

## Where each fits

**(a) Plain "run SQL".** Simplest and most capable, and the most dangerous if the model is wrong or manipulated. Reasonable on a disposable database.

**(b) Read-only.** The strongest answer when the agent never needs to write: there is nothing to preview or undo. Its limit is that it cannot help with changes at all. safewrite's `query` tool is also read-only, so choose (b) if you do not need writes.

**(c) Gateway / proxy.** Useful for policy across many tools, not only databases, and for central logging or access control. Filtering on the request can only reason about what the request *says*. For SQL, a condition such as `WHERE id >= 0` or a one-row delete that cascades looks the same as a safe statement until it is run. A gateway can still be combined with safewrite; they work at different layers.

**(d) safewrite-mcp.** Differs in two ways: it measures the real impact (rows, per-table deltas, cascades) with a dry run that is always rolled back, and it keeps a snapshot so the last change can be undone.

## What safewrite trades off

- **Scope.** SQLite only, one writer; the other categories may support more databases or tools.
- **Friction.** Bulk or cascading writes stop and wait for a person by design. A read-only server never interrupts you.
- **Auto-approved small writes.** Small writes pass without a human, so a small harmful edit is not stopped (see [THREAT_MODEL.md](THREAT_MODEL.md)).
- **Undo is narrow.** One level, current session, and the cost grows with database size.
- **Cost of the dry run.** Each write is executed once to preview and again to apply; costly statements are bounded by a timeout.
- **Trust in the approval channel.** Elicitation is only as trustworthy as the client; the terminal path (`approval_mode: "out_of_band"`) is the safer setting for autonomous agents.
- **Maturity.** It is a small project with author-written tests and benchmarks and limited client testing (see the README), not an audited or widely deployed system.
