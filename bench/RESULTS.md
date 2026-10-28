# Benchmark results

Generated 2026-10-27 · Python 3.13.8 · SQLite 3.50.4 · sqlglot 30.25.0 · seed 1234

Reproduce: `python -m bench.run`. The corpora are written by the project author (see `bench/corpus.py`), so these numbers measure this design against these cases; they are not a security guarantee.

## 1. Red team: 72 attacks, no human approval granted

| System | Reached the data or ran unbounded | Blocked | Held for approval | Contained by timeout | Harmless |
|---|---|---|---|---|---|
| No guard (executes anything) | **60/72** | 0 | 0 | 0 | 12 |
| Keyword filter | **31/72** | 37 | 0 | 0 | 4 |
| safewrite-mcp | **0/72** | 32 | 37 | 3 | 0 |

safewrite plan_error outcomes (dry run failed, e.g. timed out; database unchanged, counted neither as stopped nor as got through): **0**

Of the 37 attacks safewrite held for approval, **10** looked low-risk to static analysis, which would have let them run without approval. Only the dry run revealed their real effect.

| Category | Attacks | No guard got through | Keyword filter got through | safewrite got through |
|---|---|---|---|---|
| ddl | 8 | 8 | 2 | 0 |
| unbounded | 10 | 10 | 2 | 0 |
| tautology | 11 | 11 | 11 | 0 |
| stacked | 6 | 6 | 0 | 0 |
| obfuscation | 10 | 10 | 3 | 0 |
| system | 11 | 0 | 0 | 0 |
| protected | 4 | 4 | 3 | 0 |
| cascade | 4 | 4 | 4 | 0 |
| overwrite | 4 | 4 | 3 | 0 |
| resource | 4 | 3 | 3 | 0 |

## 2. Everyday workload: 36 legitimate statements (31 routine, 5 legitimate bulk operations)

- Routine statements that ran with no friction: **31/31**
- Legitimate bulk operations held for one approval (by design): **5/5**; blocked or errored: 0
- Reads returning results identical to direct SQL: **10/10**
- Writes leaving the database byte-identical to direct execution: **26/26**
- Writes undone back to the exact original state: **26/26**
- Keyword filter false positives: 1/36

## 3. Write → undo round-trips (200 randomized statements)

- 196 statements changed the database (94 needed approval, 0 refused)
- **196/196** restored a byte-identical database after undo

## 4. Latency (median unless noted)

| Orders | DB size | Preview, 1 row | Preview, 1 row p95 | Preview, 10% of table | Apply incl. snapshot | Raw UPDATE |
|---|---|---|---|---|---|---|
| 1,000 | 0.07 MB | 5.73 ms | 9.07 ms | 11.43 ms | 14.95 ms | 3.908 ms |
| 10,000 | 0.43 MB | 5.6 ms | 11.01 ms | 7.86 ms | 18.44 ms | 4.388 ms |
| 100,000 | 4.17 MB | 23.32 ms | 65.41 ms | 28.34 ms | 70.33 ms | 3.773 ms |

## 5. Audit-log tamper detection (600 entries)

- Edited entry: **50/50** detected
- Deleted entry: **50/50** detected
- Reordered entries: **50/50** detected
- Known limit: truncating the end of the log is not detectable by a hash chain alone.

## Metric definitions and caveats

- *Reached the data or ran unbounded*: the database's schema/contents changed, or a read ran until the harness stopped it at 2 s. Writes to files outside the database (e.g. ATTACH creating a file) are not counted as damage.
- *Keyword filter* is a baseline written for this benchmark; real filters vary.
- The corpus is small and author-written. Thresholds were set before the first run (see `policy.py`).
