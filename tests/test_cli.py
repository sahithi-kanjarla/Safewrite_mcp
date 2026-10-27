import json

import pytest

from safewrite_mcp.cli import main
from safewrite_mcp.engine import GuardedDB
from safewrite_mcp.policy import Policy

CASCADE = "DELETE FROM customers WHERE id=1"


def test_demo_db_command(tmp_path, capsys):
    main(["demo-db", str(tmp_path / "x.db")])
    assert (tmp_path / "x.db").exists() and "created" in capsys.readouterr().out


def test_pending_show_and_approve_flow(db, capsys):
    g = GuardedDB(db, policy=Policy())
    plan = g.plan(CASCADE, "remove test customer")

    main(["pending", "--db", str(db)])
    assert plan["plan_id"] in capsys.readouterr().out

    main(["show", plan["plan_id"], "--db", str(db)])
    shown = capsys.readouterr().out
    assert "DELETE FROM customers WHERE id = 1" in shown and "orders" in shown

    main(["approve", plan["plan_id"], "--db", str(db), "--yes"])
    assert g.apply(plan["plan_id"])["approved_via"] == "out-of-band"
    g.close()


def test_approve_prompt_can_be_declined(db, monkeypatch):
    g = GuardedDB(db, policy=Policy())
    plan = g.plan(CASCADE, "x")
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(SystemExit, match="not approved"):
        main(["approve", plan["plan_id"], "--db", str(db)])
    assert not (g.home / "approvals" / plan["plan_id"]).exists()
    g.close()


def test_approve_unknown_plan_fails(db):
    GuardedDB(db, policy=Policy()).close()
    with pytest.raises(SystemExit, match="no pending plan"):
        main(["approve", "0" * 16, "--db", str(db), "--yes"])


def test_pending_when_empty(db, capsys):
    GuardedDB(db, policy=Policy()).close()
    main(["pending", "--db", str(db)])
    assert "no pending plans" in capsys.readouterr().out


def test_verify_exit_codes(db, capsys):
    g = GuardedDB(db, policy=Policy())
    for i in range(4):
        g.plan(f"UPDATE customers SET status='s{i}' WHERE id=7", "x")
    with pytest.raises(SystemExit) as ok:
        main(["verify", "--db", str(db)])
    assert ok.value.code == 0 and json.loads(capsys.readouterr().out)["ok"]

    lines = g.audit.path.read_text().splitlines()
    e = json.loads(lines[1])
    e["event"] = "forged"
    lines[1] = json.dumps(e, sort_keys=True)
    g.audit.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(SystemExit) as bad:
        main(["verify", "--db", str(db)])
    assert bad.value.code == 1
    g.close()


def test_home_is_required_when_nothing_identifies_it(monkeypatch):
    monkeypatch.delenv("SAFEWRITE_HOME", raising=False)
    with pytest.raises(SystemExit, match="--home"):
        main(["pending"])
