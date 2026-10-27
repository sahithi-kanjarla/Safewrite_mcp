"""Append-only, hash-chained audit log (JSON Lines).

Each entry embeds the SHA-256 of the previous entry, so editing, deleting or
reordering any past line breaks every hash after it. `verify()` finds the
first broken link. This makes the log tamper-evident (not tamper-proof: someone
who can rewrite the whole file can rebuild the chain, so ship it off-box if
that matters to you).
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._last = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last_line = ""
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return 0, GENESIS
        e = json.loads(last_line)
        return e["seq"], e["hash"]

    def append(self, event: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "event": event,
                **data,
                "prev": self._last,
            }
            entry["hash"] = _digest(entry)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            self._last = entry["hash"]
            return entry

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()]
        return [json.loads(ln) for ln in lines[-max(1, n):]]

    def verify(self) -> dict[str, Any]:
        prev, count = GENESIS, 0
        if not self.path.exists():
            return {"ok": True, "entries": 0, "broken_at": None}
        with self.path.open(encoding="utf-8") as f:
            for ln, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    return {"ok": False, "entries": count, "broken_at": ln, "why": "unparseable line"}
                if e.get("prev") != prev:
                    return {"ok": False, "entries": count, "broken_at": e.get("seq", ln), "why": "chain link mismatch"}
                if e.get("hash") != _digest(e):
                    return {"ok": False, "entries": count, "broken_at": e.get("seq", ln), "why": "entry was modified"}
                prev, count = e["hash"], count + 1
        return {"ok": True, "entries": count, "broken_at": None}
