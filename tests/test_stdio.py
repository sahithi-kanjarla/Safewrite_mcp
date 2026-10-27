"""End-to-end over real stdio: the server runs as a subprocess, exactly as Claude Desktop launches it.

Observed with mcp 2.2.0: server->client elicitation works when the test client connects in mode="legacy",
but raises NoBackChannelError in the default mode="auto". The server therefore falls back to terminal
approval whenever elicitation is unavailable. Both paths are tested.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters, types

from safewrite_mcp.demo import create_demo_db

from .conftest import scalar

ROOT = Path(__file__).resolve().parent.parent
CASCADE = "DELETE FROM customers WHERE id=1"


def launch(db: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "safewrite_mcp", "serve", "--db", str(db)], cwd=ROOT)


def set_policy(db: Path, **policy):
    home = db.parent / ".safewrite"
    home.mkdir(exist_ok=True)
    (home / "policy.json").write_text(json.dumps(policy))


@pytest.fixture
def db(tmp_path):
    path = create_demo_db(tmp_path / "demo.db")
    set_policy(path, protected_tables=["settings"])
    return path


async def call(c, name, **args):
    res = await c.call_tool(name, args)
    assert not res.is_error, res.content
    return res.structured_content


async def test_terminal_approval_with_the_real_cli(db):
    async with Client(launch(db)) as c:
        plan = await call(c, "plan_change", sql=CASCADE, intent="remove test customer")
        assert plan["risk"] == "high"
        first = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert first["status"] == "approval_required"
        assert scalar(db, "SELECT COUNT(*) FROM customers") == 200

        # the human runs the printed command in their own terminal
        done = subprocess.run(
            [sys.executable, "-m", "safewrite_mcp", "approve", plan["plan_id"], "--db", str(db), "--yes"],
            cwd=ROOT, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        assert "DELETE FROM customers WHERE id = 1" in done.stdout

        second = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert second["status"] == "applied" and second["approved_via"] == "out-of-band"
        assert scalar(db, "SELECT COUNT(*) FROM customers") == 199
        assert (await call(c, "undo_last_change"))["status"] == "undone"
        assert scalar(db, "SELECT COUNT(*) FROM customers") == 200
        assert (await call(c, "verify_audit"))["ok"]


async def test_state_is_durable_across_server_restarts(db):
    async with Client(launch(db)) as c:
        plan = await call(c, "plan_change", sql="UPDATE customers SET status='vip' WHERE id=7", intent="x")
        await call(c, "apply_change", plan_id=plan["plan_id"])
    async with Client(launch(db)) as c:
        rows = (await call(c, "query", sql="SELECT status FROM customers WHERE id=7"))["rows"]
        assert rows == [["vip"]]
        assert (await call(c, "verify_audit"))["entries"] >= 3      # the audit chain continued across processes


async def test_elicitation_accept_and_decline(db):
    answers, prompts = [], []

    async def human(context, params):
        prompts.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": answers.pop(0)})

    async with Client(launch(db), elicitation_callback=human, mode="legacy") as c:
        plan = await call(c, "plan_change", sql=CASCADE, intent="remove test customer")
        answers.append(False)
        declined = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert declined["status"] == "declined" and scalar(db, "SELECT COUNT(*) FROM customers") == 200
        answers.append(True)
        applied = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert applied["status"] == "applied" and applied["approved_via"] == "elicitation"
        assert scalar(db, "SELECT COUNT(*) FROM customers") == 199

    assert len(prompts) == 2
    assert "HIGH-risk" in prompts[0] and "DELETE FROM customers WHERE id = 1" in prompts[0]
    assert "orders" in prompts[0]        # the cascade is shown to the human


async def test_out_of_band_mode_never_asks_the_client(db):
    set_policy(db, protected_tables=["settings"], approval_mode="out_of_band")
    asked = []

    async def agent_that_says_yes(context, params):       # an autonomous client that would auto-approve
        asked.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": True})

    async with Client(launch(db), elicitation_callback=agent_that_says_yes, mode="legacy") as c:
        plan = await call(c, "plan_change", sql=CASCADE, intent="x")
        out = await call(c, "apply_change", plan_id=plan["plan_id"])
        assert out["status"] == "approval_required"
    assert asked == []
    assert scalar(db, "SELECT COUNT(*) FROM customers") == 200
