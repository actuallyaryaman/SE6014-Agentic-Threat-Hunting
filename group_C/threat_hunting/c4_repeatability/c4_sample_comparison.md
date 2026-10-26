# C4 C2 Repeatability Comparison

- Run A: `sample_runs/runs/pytest-primary/result.json`
- Run B: `sample_runs/runs/pytest-primary-2/result.json`

| Check | Result |
|---|---|
| hypothesis | MATCH |
| time_range | MATCH |
| verdict | MATCH |
| coverage | MATCH |
| claims_and_evidence_links | MATCH |
| evidence_contents | MATCH |
| queries_and_values | MATCH |
| actions | MATCH |
| agent | MATCH |
| candidates | MATCH |
| dynamic_steps | MATCH |
| findings | MATCH |
| intake | MATCH |
| lesson_flags | MATCH |
| lessons_used | MATCH |
| limitations | MATCH |
| manifest | MATCH |
| notes | MATCH |
| question | MATCH |
| schema_version | MATCH |
| self_check | MATCH |
| skeptic | MATCH |
| step_results | MATCH |
| techniques | MATCH |

**Matched checks: 24/24**

## Differences

No meaningful differences detected in the compared C2 fields.

## Notes

Only execution IDs (run_id, call_id, query_id) and manifest execution duration/audit-file paths are ignored. Event timestamps, claim facts, evidence links, evidence contents, and query requests/values are preserved.
This compares saved C2 outputs; it does not rerun hunts or establish correctness.
