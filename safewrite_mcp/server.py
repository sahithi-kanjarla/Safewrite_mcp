"""safewrite MCP server.

The agent gets reads and *proposals*. It never gets a way to approve its own
proposal: approval comes from the human, through MCP elicitation or through the
terminal (`safewrite-mcp approve <plan_id>`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from pydantic import BaseModel, Field

from .engine import ApprovalRequired, Blocked, GuardedDB, PlanInvalid, SafeWriteError
from .policy import Policy

mcp = MCPServer(
    "safewrite",
    instructions=(
        "Database access with human-in-the-loop writes. Read with query(). To change data: call "
        "plan_change(sql, intent) to preview the exact effect (rows, cascades, before/after) without "
        "changing anything, show that preview to the user in plain language, then call apply_change(plan_id). "
        "Medium and high risk changes require the user's approval, which you cannot grant or bypass. "
        "If a change is blocked, explain why and propose a safer alternative; do not try to rephrase it to "
        "slip past the policy."
    ),
)

_engine: GuardedDB | None = None


def configure(db_path: str | Path | None = None, home: str | Path | None = None,
              policy: Policy | None = None) -> GuardedDB:
    global _engine
    path = db_path or os.environ.get("SAFEWRITE_DB")
    if not path:
        raise RuntimeError("no database configured: pass --db or set SAFEWRITE_DB")
    if _engine is not None:
        _engine.close()
    _engine = GuardedDB(path, home=home or os.environ.get("SAFEWRITE_HOME"), policy=policy)
    return _engine


def eng() -> GuardedDB:
    return _engine or configure()


def _err(e: SafeWriteError) -> dict[str, Any]:
    if isinstance(e, Blocked):
        return {"status": "blocked", "reasons": e.reasons}
    if isinstance(e, PlanInvalid):
        return {"status": "invalid_plan", "error": str(e)}
    return {"status": "error", "error": str(e)}


class Approval(BaseModel):
    approve: bool = Field(description="Apply this change to the database?")


def _approval_message(view: dict[str, Any]) -> str:
    imp = view["impact"]
    lines = [
        view["summary"],
        "",
        f"Approve this {view['risk'].upper()}-risk change?",
        f"SQL: {view['statement']}",
        f"Why: {view['intent'] or '(none given)'}",
        f"Rows affected: {imp['rows_affected']} (of {imp['table_rows_before']} in {imp['target_table']})",
    ]
    if imp["collateral_changes"]:
        lines.append(f"Also changes other tables: {imp['collateral_changes']}")
    lines += [f"- {r}" for r in view["reasons"]]
    return "\n".join(lines)


# ----------------------------------------------------------------------- tools
@mcp.tool()
def list_tables() -> list[dict[str, Any]]:
    """Tables with row counts, columns, and whether each is protected (read-only)."""
    return eng().list_tables()


@mcp.tool()
def query(sql: str) -> dict[str, Any]:
    """Run ONE read-only SELECT. Runs on a read-only connection with a row limit and timeout."""
    try:
        return {"status": "ok", **eng().read(sql)}
    except SafeWriteError as e:
        return _err(e)


@mcp.tool()
def plan_change(sql: str, intent: str) -> dict[str, Any]:
    """Preview a write (INSERT/UPDATE/DELETE) WITHOUT changing anything.

    Runs it in a transaction that is always rolled back and reports exact rows affected, cascades into
    other tables, and a before/after sample. `intent` (one sentence on why) is required and is audit-logged.
    Returns a plan_id to pass to apply_change.
    """
    if not intent or not intent.strip():
        return {"status": "error", "error": "intent is required: say in one sentence why this change is needed"}
    return eng().plan(sql, intent.strip())


@mcp.tool()
async def apply_change(plan_id: str, ctx: Context) -> dict[str, Any]:
    """Apply a previewed change. Low-risk plans apply immediately; others need the user's approval.

    You cannot approve a plan yourself. If approval is needed, the user is asked directly, or told how to
    approve from their terminal.
    """
    e = eng()
    try:
        return e.apply(plan_id)
    except ApprovalRequired:
        pass
    except SafeWriteError as err:
        return _err(err)

    view = e.plan_view(plan_id)
    caps = ctx.client_capabilities
    can_elicit = bool(caps and caps.elicitation) and e.policy.approval_mode == "elicit"
    if can_elicit and view:
        try:
            res = await ctx.elicit(_approval_message(view), Approval)
        except Exception:  # noqa: BLE001 - a client that mishandles elicitation falls back to the terminal
            res = None
        if res is not None:
            if res.action == "accept" and res.data.approve:
                try:
                    return e.apply(plan_id, approved_via="elicitation")
                except SafeWriteError as err:
                    return _err(err)
            e.audit.append("declined", plan_id=plan_id, action=res.action)
            return {"status": "declined", "message": "The user did not approve this change. Nothing was modified."}
    return {
        "status": "approval_required",
        "message": "This change needs the user's approval. Show them the plan, then ask them to run the command "
                   "below in their terminal and tell you when it's done. Then call apply_change again.",
        "command": f"safewrite-mcp approve {plan_id} --home {e.home}",
    }


@mcp.tool()
def undo_last_change() -> dict[str, Any]:
    """Undo the most recent applied change. Refused if the database has changed since, so newer data is safe."""
    try:
        return eng().undo_last()
    except SafeWriteError as err:
        return _err(err)


@mcp.tool()
def pending_changes() -> list[dict[str, Any]]:
    """Plans that were previewed but not yet applied (and have not expired)."""
    return eng().pending()


@mcp.tool()
def audit_tail(n: int = 20) -> list[dict[str, Any]]:
    """The last n audit-log entries (reads, plans, blocks, applies, undos)."""
    return eng().audit.tail(n)


@mcp.tool()
def verify_audit() -> dict[str, Any]:
    """Verify the audit log's hash chain. ok=false means an entry was edited, removed, or reordered."""
    return eng().audit.verify()


# ------------------------------------------------------------------- resources
@mcp.resource("db://schema", mime_type="text/plain")
def schema_resource() -> str:
    """CREATE statements for every table."""
    return eng().schema()


@mcp.resource("policy://current", mime_type="application/json")
def policy_resource() -> str:
    """The active safety policy (what is protected, what needs approval, limits)."""
    return json.dumps(eng().policy.to_dict(), indent=2)


# --------------------------------------------------------------------- prompts
@mcp.prompt()
def safe_cleanup(goal: str) -> str:
    """A careful workflow for a data change such as 'archive inactive customers'."""
    return (
        f"Goal: {goal}\n\n"
        "1. Read the schema (db://schema) and the policy (policy://current).\n"
        "2. Use query() to find exactly which rows match; count them before proposing anything.\n"
        "3. Call plan_change() with the narrowest possible WHERE clause and a one-sentence intent.\n"
        "4. Explain the preview to the user in plain language: how many rows, what changes, any cascades "
        "into other tables, and why the risk level is what it is.\n"
        "5. Only then call apply_change(). If approval is required, wait for the user; never try to "
        "work around a block or rephrase a statement to avoid the policy.\n"
        "6. Offer undo_last_change() if the user is unhappy with the result."
    )
