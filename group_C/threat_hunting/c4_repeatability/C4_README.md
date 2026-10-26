# C4: Compare C2 hunt runs

Files: `compare_c2_results.py`, `test_compare_c2_results.py`, `c4_sample_comparison.md`.

## Run the new C2 samples
Extract `sample_runs(1).zip` next to your repository (so `sample_runs/runs/` exists), then from the repository root:

```bash
python group_C/threat_hunting/c4_repeatability/compare_c2_results.py sample_runs/runs/pytest-primary/result.json sample_runs/runs/pytest-primary-2/result.json --output group_C/threat_hunting/c4_repeatability/c4_sample_comparison.md
```

## Run automated tests
```bash
python -m unittest discover -s group_C/threat_hunting/c4_repeatability -p 'test_*.py' -v
```

Exit codes: 0 = MATCH; 1 = DIFFERENT; 2 = INVALID INPUT. Missing required fields cannot be MATCH. Claims, evidence links/contents, coverage, queries, event timestamps, and all other output fields are compared. Only execution IDs, manifest duration/audit paths, and per-run output-directory prefixes for action files are normalized. Query values and event timestamps are preserved.

## Integration follow-up
Run the same hypothesis twice with the same dataset snapshot, time window, settings, and code version. Save both C2 result.json files, compare, investigate any differences, and document fixes. C3 JSON report comparison comes later.
