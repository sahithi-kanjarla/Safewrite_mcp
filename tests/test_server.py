"""In-process tests: a real MCP client talking to the server object."""

import json
import os
from pathlib import Path

import pytest
from mcp import Client

from safewrite_mcp import server
from safewrite_mcp.demo import create_demo_db
from safewrite_mcp.policy import Policy

from .conftest import scalar

CASCADE = "DELETE FROM customers WHERE id=1"


@pytest.fixture
def srv(tmp_path):
    db = create_demo_db(tmp_path / "demo.db")
    engine = server.configure(db, policy=Policy(protected_tables=["settings"]))
    engine.test_db = db
    yield engine
    engine.close()


async def call(c, name, **args):
    res = await c.call_tool(name, args)
    assert not res.is_error, res.content
    return res.structured_content


async def test_tool_surface(srv):
    async with Client(server.mcp) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert {"query", "plan_change", "apply_change", "undo_last_change", "list_tables",
                "pending_changes", "audit_tail", "verify_audit"} <= set(tools)
        # The agent-facing schema offers no way to approve: apply_change takes only a plan id.
        props = tools["apply_change"].input_schema["properties"]
        assert set(props) == {"plan_id"}
        assert "approve" not in json.dumps(tools["apply_change"].input_schema).lower()


async def test_intent_is_required(srv):
    async with Client(server.mcp) as c:
        out = await call(c, "plan_change", sql="UPDATE customers SET status='x' WHERE id=1", intent="  ")
        assert out["status"] == "error" and "intent" in out["error"]


async def test_low_risk_flow_and_undo(srv):
    async with Client(server.mcp) as c:
        plan = await call(c, "plan_change", sql="UPDATE customers SET status='vip' WHERE id=7", intent="promote")
        assert plan["risk"] == "low"
        applied = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert applied["status"] == "applied"
        assert scalar(srv.test_db, "SELECT status FROM customers WHERE id=7") == "vip"
        assert (await call(c, "undo_last_change"))["status"] == "undone"
        assert scalar(srv.test_db, "SELECT status FROM customers WHERE id=7") != "vip"


async def test_high_risk_without_elicitation_falls_back_to_terminal_approval(srv):
    async with Client(server.mcp) as c:
        plan = await call(c, "plan_change", sql=CASCADE, intent="remove test customer")
        first = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert first["status"] == "approval_required"
        assert plan["plan_id"] in first["command"] and " approve " in first["command"]
        assert scalar(srv.test_db, "SELECT COUNT(*) FROM customers WHERE id=1") == 1     # untouched
        srv.approve(plan["plan_id"])                                                      # the human, in a terminal
        second = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert second["status"] == "applied" and second["approved_via"] == "out-of-band"


async def test_blocked_statements_surface_as_blocked_not_errors(srv):
    async with Client(server.mcp) as c:
        q = await call(c, "query", sql="DROP TABLE customers")
        p = await call(c, "plan_change", sql="UPDATE settings SET value='x'", intent="try")
        assert q["status"] == "blocked" and p["status"] == "blocked"
        assert any("protected" in r for r in p["reasons"])


async def test_invalid_plan_ids_come_back_as_statuses(srv):
    async with Client(server.mcp) as c:
        out = await call(c, "apply_change", plan_id="../../etc/passwd")
        assert out["status"] == "invalid_plan"


async def test_undo_with_nothing_to_undo(srv):
    async with Client(server.mcp) as c:
        assert (await call(c, "undo_last_change"))["status"] == "invalid_plan"


async def test_query_and_listing(srv):
    async with Client(server.mcp) as c:
        out = await call(c, "query", sql="SELECT * FROM orders")
        assert out["status"] == "ok" and out["row_count"] == 200 and out["truncated"]
        tables = (await call(c, "list_tables"))["result"]
        assert {t["table"] for t in tables} == {"customers", "orders", "products", "settings"}


async def test_pending_and_audit_tools(srv):
    async with Client(server.mcp) as c:
        plan = await call(c, "plan_change", sql=CASCADE, intent="x")
        pending = (await call(c, "pending_changes"))["result"]
        assert [p["plan_id"] for p in pending] == [plan["plan_id"]]
        tail = (await call(c, "audit_tail", n=5))["result"]
        assert tail[-1]["event"] == "plan"
        assert (await call(c, "verify_audit"))["ok"] is True


async def test_resources_and_prompt(srv):
    async with Client(server.mcp) as c:
        schema = await c.read_resource("db://schema")
        assert "CREATE TABLE customers" in schema.contents[0].text
        policy = json.loads((await c.read_resource("policy://current")).contents[0].text)
        assert policy["protected_tables"] == ["settings"] and policy["approval_mode"] == "elicit"
        prompt = await c.get_prompt("safe_cleanup", {"goal": "archive inactive customers"})
        text = prompt.messages[0].content.text
        assert "archive inactive customers" in text and "never try to work around" in text


async def test_plan_has_summary_and_approval_message_leads_with_it(srv):
    async with Client(server.mcp) as c:
        plan = await call(c, "plan_change", sql=CASCADE, intent="x")
    assert plan["summary"].startswith("This will delete 1 row from customers and ")
    msg = server._approval_message(srv.plan_view(plan["plan_id"]))
    assert msg.splitlines()[0] == plan["summary"]


def test_approve_command_runs_in_fresh_powershell(tmp_path):
    """The printed command, pasted into PowerShell with no venv activated, approves the plan."""
    import shutil
    import subprocess
    import sys

    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        pytest.skip("PowerShell not available")
    folder = tmp_path / "with space's"
    folder.mkdir()
    engine = server.configure(create_demo_db(folder / "demo.db"), policy=Policy())
    try:
        plan = engine.plan(CASCADE, "x")
        cmd = server._approve_command(plan["plan_id"], engine.home)
        assert cmd.startswith("& ") and sys.executable in cmd
        env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "PYTHONPATH")}
        env["PYTHONPATH"] = str(Path(server.__file__).resolve().parent.parent)
        run = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd], input="y\n",
                             capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)
        assert run.returncode == 0, run.stderr
        assert engine.apply(plan["plan_id"])["approved_via"] == "out-of-band"
    finally:
        engine.close()
