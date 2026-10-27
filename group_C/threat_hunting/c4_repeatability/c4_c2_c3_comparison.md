# C4 Combined C2/C3 Repeatability Comparison

- C3 A: `group_B/tests/c2_c3_evidence/attack/c3/hunt_report_attack.json`
- C3 B: `group_B/tests/c2_c3_evidence/attack-repeat/c3/hunt_report_attack-repeat.json`

## C3 verification report comparison

| Check | Result |
|---|---|
| hypothesis | MATCH |
| plan | MATCH |
| decision | MATCH |
| verification | MATCH |
| coverage | MATCH |
| data_sources | MATCH |
| findings | MATCH |
| rejected | MATCH |
| unverified | MATCH |
| audit | MATCH |
| claim_queries | MATCH |
| baselines | MATCH |
| context_findings | MATCH |
| dated | MATCH |
| entity_missing | MATCH |
| flags | MATCH |
| generator | MATCH |
| limitations | MATCH |
| meta | MATCH |
| schema_version | MATCH |
| selected_sources | MATCH |
| steps_ok | MATCH |
| summary | MATCH |
| summary_source | MATCH |
| verification_mode | MATCH |

**Matched: 25/25 checks**


## C2 hunt result comparison

| Check | Result |
|---|---|
| hypothesis | MATCH |
| time_range | MATCH |
| verdict | MATCH |
| coverage | MATCH |
| claims_and_evidence_links | MATCH |
| evidence_contents | MATCH |
| queries_and_values | MATCH |
| dynamic_steps | MATCH |
| findings | MATCH |
| limitations | MATCH |
| manifest | MATCH |
| notes | MATCH |
| schema_version | MATCH |
| self_check | MATCH |
| step_results | MATCH |
| techniques | MATCH |

**Matched: 16/16 checks**


## Cross-component interpretation

- C2 A verdict: `SUPPORTED`; C2 B verdict: `SUPPORTED`
- C3 A verdict: `Inconclusive`; C3 B verdict: `Inconclusive`
- C3 A replay: `15/15` identical; C3 B replay: `15/15` identical


## Interpretation and limits

- A MATCH indicates equality after excluding documented execution-only identifiers and timestamps; it does not prove that a verdict is correct.
- `generated_at`, audit call `ts`, run/report/call IDs, and meta execution timings/audit-file paths are excluded.
- Event timestamps, query DSL/parameters, audit result hashes, evidence contents, verification decisions, and claim links are retained.
- A DIFFERENT result requires investigation, including whether differences are meaningful or execution-specific.
