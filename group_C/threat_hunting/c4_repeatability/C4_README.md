# C4 C2 Repeatability Comparison

## Run on the existing sample outputs

From the repository root:

```bash
python group_C/threat_hunting/c4_repeatability/compare_c2_results.py \
  group_B/tests/c2_c3_evidence/attack/result.json \
  group_B/tests/c2_c3_evidence/attack-repeat/result.json \
  --output group_C/threat_hunting/c4_repeatability/sample_comparison.md
```

The script uses only the Python standard library. It checks the hypothesis, time range, verdict, coverage, evidence IDs, cited event IDs, and ordered queries. It ignores run IDs and common execution metadata, but keeps evidence and query contents. Differences are shown in the Markdown report.

## Later integration test

Run the same hypothesis twice with an identical dataset snapshot, time window, settings, and code version. Save both `result.json` files under separate folders and compare them using the command above. Record causes of differences and rerun after fixes.

## PR steps

```bash
git checkout -b feature/c4-repeatability
mkdir -p group_C/threat_hunting/c4_repeatability
# Copy compare_c2_results.py, C4_README.md, sample_comparison.md into the folder
git add group_C/threat_hunting/c4_repeatability
git commit -m "Add C4 C2 repeatability comparison and sample report"
git push -u origin feature/c4-repeatability
```

Open a pull request from `feature/c4-repeatability` to your team's target branch. Do not claim the integrated two-run test is complete until it has been executed.
