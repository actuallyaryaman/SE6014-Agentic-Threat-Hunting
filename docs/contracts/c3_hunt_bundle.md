# Contract: hunt bundle (C2 to C3)

Status: proposal 1.0.0, written to match the C2 playbook hunter.
The source of truth is `group_C/threat_hunting/evidence/contracts.py`. The JSON Schemas are in
`group_C/threat_hunting/evidence/schemas/`.

## 1. What C1 records (audit log, one JSON line per tool call)

```json
{"call_id": "hunt-lsass-001-0006", "ts": "...", "tool": "aggregate",
 "params": {"index": "logs-firewall-fw-edge", "time_from": "...", "time_to": "...", "agg": "terms", "field": "destination.ip",
            "filters": [{"field": "source.ip", "op": "eq", "value": "10.0.1.15"}]},
 "dsl": {"query": {...}, "size": 0, "aggs": {"a": {...}}},
 "total": 6, "returned_ids": ["..."], "result_hash": "7f381c4fa26e2f3b", "ok": true, "error": "", "digest": "{...}"}
```

`result_hash = sha256(json.dumps([sorted(ids), total]))[:16]`, where ids are
`"<index>/<_id>"` for search, the JSON of the bucket list for aggregate, the JSON
of per-index totals for coverage_check, the IOC values for check_ioc, and none for count.
C3 computes it again on replay, so the formula must not change.

Tools C3 calls on its own connection: `get_event(index, event_id)`, plus re-runs of
`search`, `aggregate`, `count`, `coverage_check` and `check_ioc` with the recorded params.

## 2. What C2 hands over (`HuntBundle`)

| Field | Content |
|---|---|
| `run_id` | hunt id |
| `plan` | `HuntPlan`: hypothesis, techniques, required and context techniques, `entities` (hosts, technique_names, `requirement_groups`), required_sources, time_range, steps, success and refutation criteria, planner |
| `evidence` | `Evidence`: evidence_id, call_id, step_id, index, event_ids, total_hits, excerpt |
| `claims` | `Claim`: claim_id, text, technique, evidence_ids, facts, step_id, kind (events / aggregate / ioc), first_seen, event_ids `"<index>/<_id>"`, replay, context_only, origin (playbook or llm), status |
| `audit` | The audit records of the hunt |
| `step_results` | Maps each step_id to `{"status": "ok" | ...}` |
| `dynamic_steps`, `weak_signals` | Steps added during the hunt, and below-threshold activity per technique |
| `notes` | `HuntNotes`: entity_missing, untested, coverage, coverage_gaps, gaps, dated, data_sources, selected_sources, out_of_scope, min_support |
| `baselines`, `limitations`, `meta` | Text for the report, and run metadata (model, controls, playbooks hash and so on) |
| `c2_verdict` | C2's own draft: `label` (SUPPORTED, NOT_SUPPORTED, INCONCLUSIVE or INSUFFICIENT_DATA), `confidence`, `requires_analyst_review`, `reasons`. C3 reviews it and can only keep or lower it |
| `c2_self_check`, `trace`, `queries` | C2's summary of its structural self-check, and every MCP call as a `TraceCall`. C3 builds the calls from `result.json` `queries[]` (`server`, `tool`, `args`, `call_id`, `total`, `phase`, `step_id`), or from `trace.jsonl` for schema 0.1 runs |
| `analytics_audit`, `c2_findings` | The calls to C2's analytics server (`audit/<run_id>-analytics.jsonl`), and `result.json` `findings`, for example `prompt_injection` (which becomes the flag `c2_prompt_injection`) |

C2 sets a claim's `status` to `unverified` or `self_checked`. C3 always answers with `verified`, `unsupported`,
`contradicted` or `unverified`, and keeps C2's value in `c2_status`. `bundle_from_run_dir()` builds the whole bundle from
`runs/<id>/{plan,result}.json` (schema 0.2), `audit/<id>.jsonl` and `audit/<id>-analytics.jsonl`. It reads `trace.jsonl`
only for schema 0.1 runs.

A requirement group looks like `{"label": "T1003.001", "kind": "technique" | "tactic" | "llm", "techniques": [...]}`.
The `replay` field of an aggregate claim looks like `{"tool": "aggregate", "params": {...}, "bucket_key": "10.0.2.10", "count": 6,
"sum": null, "distinct": null, "event_field": "destination.ip"}`.

## 3. What C3 returns (`HuntReport`)

The report holds the verdict (Confirmed, Refuted or Inconclusive), confidence, reasons, next steps,
analyst_review, technique rows, findings, context findings, rejected claims, the
verification summary (including replay), flags, coverage, limitations and the full audit
trail.

## 4. Open points

- [x] Confidence policy, agreed with C2 (DESIGN §4.1): `high` means supported, fully covered, and at least two independent verified
      steps. C3 applies the same rule. `C3_MIN_LOG_SOURCES=2` is an optional stricter rule. INTERFACES v0.4 §4.3 records the policy and C3 follows it
      (review reasons, 95% coverage threshold, optional two-source rule). One small difference: C3 gives a Refuted verdict `low` instead of `medium` when some requirement could not be tested with the data.
- [x] `result.json` lists the steps created at run time in `dynamic_steps` (C2 PR #22).
- [x] Analytics-server calls are audited in `audit/<run_id>-analytics.jsonl` (C2 PR #22).
- [x] The contract is `result.json` schema 0.2 (INTERFACES §4.1, C2 PR #22).
- [ ] Analytics audit records use C2's own hash formula, so C3 compares their totals only.
- [ ] Final index names (the sample uses `logs-<type>-<source>`).
- [ ] MCP SDK version (C3 works with 1.x and 2.x).
