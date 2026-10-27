"""Policy: the knobs that decide what an agent may do. Defaults are conservative."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Policy:
    # Tables an agent may read but never write (matched case-insensitively).
    protected_tables: list[str] = field(default_factory=list)
    # CREATE / ALTER are blocked unless enabled; DROP / TRUNCATE are blocked unless enabled.
    allow_ddl: bool = False
    allow_drop: bool = False
    # Writes touching at most this many rows, with no collateral changes, need no human approval.
    auto_approve_max_rows: int = 10
    # Writes that would touch more rows than this are refused outright.
    hard_max_rows: int = 1000
    # A write touching at least this fraction of a table is high risk...
    max_table_fraction: float = 0.5
    # ...but only for tables with at least this many rows (so tiny tables don't trip it).
    min_rows_for_fraction: int = 5
    # Read limits.
    read_row_limit: int = 200
    query_timeout_ms: int = 2000
    # "elicit": ask the human through the MCP client, falling back to the terminal if unsupported.
    # "out_of_band": only the terminal (`safewrite-mcp approve`) can approve. Use this when the
    # client is an autonomous agent, because a client may answer an elicitation by itself.
    approval_mode: str = "elicit"
    # Plan tokens expire; undo snapshots are bounded.
    plan_ttl_s: int = 300
    snapshot_max_mb: int = 100
    keep_snapshots: int = 3

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        unknown = set(data) - set(known)
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        pol = cls(**known)
        pol.protected_tables = [t.lower() for t in pol.protected_tables]
        if pol.approval_mode not in ("elicit", "out_of_band"):
            raise ValueError("approval_mode must be 'elicit' or 'out_of_band'")
        return pol

    @classmethod
    def load(cls, path: Path) -> "Policy":
        if not path.exists():
            return cls()
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
