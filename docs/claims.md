# Claims and the evidence behind each

Use this to answer "how do you know?" in an interview. Every number below is produced by a command in this repo.
Run `python -m bench.run` and `pytest --cov=safewrite_mcp` to regenerate them.

| Claim | Number | Where it comes from | Caveat to state honestly |
|---|---|---|---|
| Attacks that reached the data, no guard | 60 / 72 | `bench/RESULTS.md` §1 | Author-written corpus of 72 statements |
| Same, keyword filter baseline | 31 / 72 | §1 | The filter is my reasonable baseline, not every real filter |
| Same, safewrite-mcp (no approval granted) | 0 / 72 | §1 | Includes 3 resource attacks "contained" by a 2 s timeout |
| Caught only by the dry run | 10 of 37 held | §1 | Static risk was `low`; first run said 14 because it miscounted already-flagged `medium` cases (fixed) |
| Routine statements with no friction | 31 / 31 | §2 | Routine = reads and small writes I wrote |
| Legitimate bulk ops held for approval | 5 / 5 | §2 | This is the friction cost; added after the first run to show it |
| Reads/writes identical to direct SQL | 10/10 and 26/26 | §2 | Proves the regenerated SQL is semantics-preserving on this corpus |
| Write → undo restores byte-identical DB | 196 / 196 | §3 | 200 seeded random statements; 4 were no-ops and are excluded |
| Preview latency | ~10–38 ms (median) | §4 | 1k–100k rows, Windows 11 laptop; machine-dependent |
| Apply incl. snapshot | ~25–109 ms | §4 | Grows with DB size (snapshot copy) |
| Audit tamper detection | 150 / 150 | §5 | Excludes tail truncation, which a hash chain can't detect |
| Tests / coverage | 253 / 95% | `pytest --cov` | In-process coverage; the elicitation branch is exercised in subprocess tests it can't see |

## What changed after the first benchmark run (disclosure)

1. Fixed the "caught only by dry run" metric (14 → 10); it had counted `INSERT OR REPLACE` cases that static analysis already flags.
2. Added 5 legitimate bulk operations to the workload so the friction cost is visible (the first workload had none).
3. Found by the test suite: plans made before a change stayed listed as pending after they could no longer be applied. Fixed.
4. Policy thresholds were not changed after seeing results.

## Things I'd say if asked what I learned

- Static analysis alone misses the dangerous cases (`id>=0`, cascades); the dry run is what makes the guard work.
- Elicitation is not a security boundary: with mcp 2.2.0 it worked in the test client's `legacy` mode but raised `NoBackChannelError` in the default `auto` mode, and the SDK docs say a client may auto-answer it. Hence the terminal approval path. (I did not test which mode real clients use.)
- A hash-chained log is tamper-evident, not tamper-proof (tail truncation).
