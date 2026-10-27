import json

import pytest

from safewrite_mcp.audit import AuditLog
from safewrite_mcp.policy import Policy


# ---------------------------------------------------------------------- policy
def test_defaults_are_conservative():
    p = Policy()
    assert not p.allow_ddl and not p.allow_drop
    assert p.approval_mode == "elicit" and p.auto_approve_max_rows == 10


def test_load_missing_file_gives_defaults(tmp_path):
    assert Policy.load(tmp_path / "nope.json") == Policy()


def test_load_normalises_and_validates(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps({"protected_tables": ["Settings"], "hard_max_rows": 50}))
    p = Policy.load(f)
    assert p.protected_tables == ["settings"] and p.hard_max_rows == 50


def test_unknown_key_is_rejected():
    with pytest.raises(ValueError, match="unknown policy keys"):
        Policy.from_dict({"allow_everything": True})


def test_bad_approval_mode_is_rejected():
    with pytest.raises(ValueError, match="approval_mode"):
        Policy.from_dict({"approval_mode": "trust_me"})


def test_roundtrip_to_dict():
    assert Policy.from_dict(Policy(protected_tables=["a"]).to_dict()).protected_tables == ["a"]


# ----------------------------------------------------------------------- audit
def make_log(tmp_path, n=8):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(n):
        log.append("event", i=i)
    return log


def test_fresh_and_populated_logs_verify(tmp_path):
    assert AuditLog(tmp_path / "empty.jsonl").verify() == {"ok": True, "entries": 0, "broken_at": None}
    assert make_log(tmp_path).verify()["entries"] == 8


def test_chain_continues_across_instances(tmp_path):
    make_log(tmp_path, 3)
    again = AuditLog(tmp_path / "audit.jsonl")
    again.append("event", i=99)
    res = again.verify()
    assert res["ok"] and res["entries"] == 4
    assert again.tail(1)[0]["seq"] == 4


def test_editing_an_entry_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()
    e = json.loads(lines[3])
    e["i"] = 12345
    lines[3] = json.dumps(e, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n")
    res = log.verify()
    assert not res["ok"] and res["broken_at"] == e["seq"] and res["why"] == "entry was modified"


def test_deleting_an_entry_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()
    del lines[2]
    log.path.write_text("\n".join(lines) + "\n")
    assert not log.verify()["ok"]


def test_reordering_entries_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()
    lines[2], lines[3] = lines[3], lines[2]
    log.path.write_text("\n".join(lines) + "\n")
    assert not log.verify()["ok"]


def test_garbage_line_is_detected(tmp_path):
    log = make_log(tmp_path)
    with log.path.open("a") as f:
        f.write("not json\n")
    res = log.verify()
    assert not res["ok"] and res["why"] == "unparseable line"


def test_truncating_the_tail_is_NOT_detected(tmp_path):
    # Documented limitation: a hash chain alone cannot see removal of the newest entries.
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()[:-2]
    log.path.write_text("\n".join(lines) + "\n")
    assert log.verify()["ok"]


def test_tail_returns_last_n(tmp_path):
    log = make_log(tmp_path, 10)
    assert [e["i"] for e in log.tail(3)] == [7, 8, 9]
