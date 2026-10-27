"""Command line: run the server, and give the human their side of the approval flow."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .audit import AuditLog
from .demo import create_demo_db


def _home(args: argparse.Namespace) -> Path:
    if getattr(args, "home", None):
        return Path(args.home).expanduser()
    if getattr(args, "db", None):
        return Path(args.db).expanduser().resolve().parent / ".safewrite"
    if os.environ.get("SAFEWRITE_HOME"):
        return Path(os.environ["SAFEWRITE_HOME"]).expanduser()
    cwd = Path.cwd().resolve()
    for folder in (cwd, *cwd.parents):
        if (folder / ".safewrite").is_dir():
            return folder / ".safewrite"
    sys.exit("error: no state folder found: pass --home or --db, set SAFEWRITE_HOME, "
             "or run from a folder that contains .safewrite")


def _choose_plan(files: list[Path]) -> Path:
    """Pick the plan to approve when the human did not name one."""
    if not files:
        sys.exit("no pending plans")
    if len(files) == 1:
        return files[0]
    plans = [json.loads(f.read_text(encoding="utf-8")) for f in files]
    print(f"{len(plans)} plans are pending:\n")
    for i, p in enumerate(plans, 1):
        print(f"  {i}. {p['plan_id']}  {p['risk'].upper():6}  {p.get('summary') or p['statement']}")
    try:
        answer = input("\nWhich one? (number or plan id) ").strip()
    except EOFError:
        answer = ""
    for i, p in enumerate(plans, 1):
        if answer in (str(i), p["plan_id"]):
            return files[i - 1]
    sys.exit("not approved: no plan chosen")


def _print_plan(plan: dict) -> None:
    imp = plan["impact"]
    if plan.get("summary"):
        print(f"\n  {plan['summary']}")
    print(f"\n  plan      {plan['plan_id']}   risk: {plan['risk'].upper()}")
    print(f"  SQL       {plan['statement']}")
    print(f"  intent    {plan.get('intent') or '(none)'}")
    print(f"  rows      {imp['rows_affected']} of {imp['table_rows_before']} in '{imp['target_table']}'")
    if imp["collateral_changes"]:
        print(f"  cascades  {imp['collateral_changes']}")
    for r in plan["reasons"]:
        print(f"  - {r}")
    diff = imp.get("diff")
    if diff:
        key = next(k for k in diff if k.startswith("rows_"))
        print(f"  sample    {json.dumps(diff[key][:3], default=str)}")
    print()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="safewrite-mcp", description="Previewed, approved, undoable database writes for AI agents.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server")
    s.add_argument("--db", help="SQLite database file (or set SAFEWRITE_DB)")
    s.add_argument("--home", help="state directory (default: <db dir>/.safewrite)")
    s.add_argument("--http", action="store_true", help="serve over streamable HTTP instead of stdio")

    d = sub.add_parser("demo-db", help="create a demo database")
    d.add_argument("path")

    for name, help_ in (("pending", "list plans awaiting a decision"), ("show", "show one plan"),
                        ("approve", "approve a plan (the human step)"), ("verify", "verify the audit log chain")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--home")
        p.add_argument("--db")
        if name in ("show", "approve"):
            p.add_argument("plan_id", nargs="?" if name == "approve" else None,
                           help="plan to approve (optional: omit to pick from the pending plans)" if name == "approve" else None)
        if name == "approve":
            p.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        from .server import configure, mcp

        configure(args.db, args.home)
        mcp.run("streamable-http" if args.http else "stdio")
    elif args.cmd == "demo-db":
        print(f"created {create_demo_db(args.path)}")
    elif args.cmd == "verify":
        res = AuditLog(_home(args) / "audit.jsonl").verify()
        print(json.dumps(res))
        sys.exit(0 if res["ok"] else 1)
    else:
        home = _home(args)
        pending = home / "pending"
        if args.cmd == "pending":
            files = sorted(pending.glob("*.json")) if pending.exists() else []
            if not files:
                print("no pending plans")
            for f in files:
                _print_plan(json.loads(f.read_text(encoding="utf-8")))
            return
        if args.cmd == "approve" and not args.plan_id:
            if args.yes:
                sys.exit("error: --yes needs an explicit plan id")
            f = _choose_plan(sorted(pending.glob("*.json")) if pending.exists() else [])
            args.plan_id = f.stem
            confirm = True
        else:
            f = pending / f"{args.plan_id}.json"
            confirm = not getattr(args, "yes", False)
        if not f.exists():
            sys.exit(f"error: no pending plan {args.plan_id} in {home} (expired or already applied?)")
        plan = json.loads(f.read_text(encoding="utf-8"))
        _print_plan(plan)
        if args.cmd == "approve":
            if confirm and input("Approve this change? [y/N] ").strip().lower() != "y":
                sys.exit("not approved")
            (home / "approvals").mkdir(parents=True, exist_ok=True)
            (home / "approvals" / args.plan_id).write_text("approved", encoding="utf-8")
            print("approved. Tell your assistant to call apply_change again.")


if __name__ == "__main__":
    main()
