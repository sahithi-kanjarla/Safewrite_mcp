# Changelog

## 0.2.0 - 2026-10-28

### Added
- Plain-English impact summary on every plan. `plan_change` now returns a `summary` field built only from the
  measured dry-run data (inserts, updates, deletes including cascades, overwrites, or the reason a statement was
  blocked). It appears first in the elicitation approval message and in the CLI `show` and `approve` output.
  Risk decisions and thresholds are unchanged.
- `docs/THREAT_MODEL.md` (what safewrite-mcp does and does not defend against) and `docs/COMPARISON.md` (how it
  differs from other categories of database MCP servers, and what it trades off).

### Changed
- `safewrite-mcp approve` no longer needs a plan id. With one pending plan it asks for confirmation; with several
  it lists them and asks which; with none it says so. `--yes` still requires an explicit plan id.
- `--home` and `--db` are optional for the CLI. The state folder is found from `SAFEWRITE_HOME`, then a
  `.safewrite` folder in the current directory or any parent.
- The approval command returned by `apply_change` now uses the absolute interpreter path
  (`python -m safewrite_mcp approve ...`) with PowerShell quoting, so it runs in a fresh terminal without
  activating the virtual environment.
- Package metadata now links to the GitHub repository and issue tracker.

### Fixed
- Benchmark harness: a dry run that failed (for example a timeout on a slow machine) was counted as "harmless".
  It is now labelled `plan_error`, reported separately in `bench/RESULTS.md`, and the corpus test accepts it only
  if the database is unchanged. No timeout or policy value changed, and the headline attack numbers are the same.

### Tests
- 263 tests passing in this release (run with `pytest` in the project virtual environment).

## 0.1.0 - 2026-10-27

Initial release: a guarded SQLite MCP server where agent writes are previewed with a dry run, gated by risk and
human approval, recorded in a hash-chained audit log, and undoable. Includes the red-team benchmark (`bench/`).
