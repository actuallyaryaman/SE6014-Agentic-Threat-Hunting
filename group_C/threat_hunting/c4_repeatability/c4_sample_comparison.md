# C4 C2 Repeatability Comparison

- Run A: `/mnt/data/c4_sample_runs/attack.json`
- Run B: `/mnt/data/c4_sample_runs/attack-repeat.json`

| Check | Result |
|---|---|
| Hypothesis | MATCH |
| Time Range | MATCH |
| Verdict | MATCH |
| Coverage | MATCH |
| Evidence Ids | MATCH |
| Cited Event Ids | MATCH |
| Queries | MATCH |

**Matched checks:** 7/7

## Differences

No differences in the compared fields. Run IDs and execution metadata are ignored.

## Interpretation

This compares saved C2 results only. Matching outputs indicate agreement in the checked fields, not correctness of the underlying threat-hunting conclusion.

## Recommended repeatability controls

Use the same dataset snapshot, hypothesis, time window, model settings, code version, and tool configuration. Save both original result files and investigate any changed query, evidence, coverage, or verdict.
