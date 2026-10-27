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


## Negative results and execution timing

Zero claims/evidence are valid for NOT_SUPPORTED, INCONCLUSIVE and
INSUFFICIENT_DATA results. Required fields and query records are still
validated; a SUPPORTED verdict without claims is invalid.

Only top-level manifest execution durations, phase_seconds and audit-file
paths are omitted from comparison. Nested settings, model/configuration
fields, event timestamps, evidence and queries remain meaningful.

Regression tests: `python -m pytest -q group_C/threat_hunting/c4_repeatability`.

## C3 integration (actual C2/C3 attack runs)

The C2 comparison remains in `compare_c2_results.py`. C3 JSON reports are compared
by the new `compare_c3_reports.py`; it can generate one combined C2/C3 report.
Run from the repository root:

```bash
python group_C/threat_hunting/c4_repeatability/compare_c3_reports.py \
  group_B/tests/c2_c3_evidence/attack/c3/hunt_report_attack.json \
  group_B/tests/c2_c3_evidence/attack-repeat/c3/hunt_report_attack-repeat.json \
  --c2-a group_B/tests/c2_c3_evidence/attack/result.json \
  --c2-b group_B/tests/c2_c3_evidence/attack-repeat/result.json \
  --output group_C/threat_hunting/c4_repeatability/c4_c2_c3_comparison.md
```

The combined report is `c4_c2_c3_comparison.md`. The `attack` pair matched
**16/16 C2 checks and 25/25 C3 checks** with this comparator. Both C2 verdicts
were `SUPPORTED`, while both C3 verdicts were `Inconclusive` (low confidence).
C3 verified one of two claims, contradicted one, and reported 15/15 identical
query replays in each run. Consistency is not proof of correctness.

To test both comparators:

```bash
python -m unittest discover -s group_C/threat_hunting/c4_repeatability -p 'test_*.py' -v
```

This version has **23 passing tests** (13 C2 + 10 C3).
C3 comparison ignores only report/run/call IDs, report generation time,
audit-call execution time, and metadata execution timing/audit-file paths.
It retains event timestamps, audit DSL/parameters, result hashes, claim
verification and evidence relationships. Exit codes: 0 match, 1 difference,
2 invalid input. C3's Markdown, HTML and PDF exports are human-readable
renderings; the structured JSON is used for automated comparison.

**Review note:** These are saved actual executions. Confirm identical dataset
snapshot, model/settings, and code revision before treating them as a fully
controlled repeatability experiment.
