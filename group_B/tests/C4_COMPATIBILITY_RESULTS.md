# C4 API compatibility — 2026-10-26

The onboarding/hunting harness supports both pinned C4 APIs:

- `ae8b316`: `compare` returns a check dictionary; `report` takes three arguments.
- `5e76ccf`: `compare` returns `(checks, errors)`; `report` takes four arguments.

The number of checks comes from C4 rather than a fixed seven. Invalid inputs
retain both JSON and Markdown diagnostics and fail execution. Valid comparisons
retain every differing field, regardless of rules or live-agent mode.
`--require-c4-match` explicitly makes any difference fail the harness; without
it, completing a comparison is distinct from all comparison fields matching.

`c4-comparison.json` now contains `checks` and `errors`. The run summary contains
`matched`, `checks`, `all_match` and `differing_fields`.

## Recompared retained end-to-end evidence

No services were restarted and no LLM calls were made. Original results and
historical 7/7 and 5/7 comparisons remain unchanged.

| Input | Latest C4 matches | Difference |
|---|---:|---|
| Final A3 rules run | 23/24 | `manifest` only: six `phase_seconds` execution timings |
| Live DeepSeek attack/repeat | 14/24 | Confidence, evidence contents, queries, agent/actions, dynamic steps, intake, skeptic, step results and manifest |

Latest C4 checks more fields, so these counts cannot be compared directly to
the older seven-check scores. Rules-mode semantic outputs remain stable;
execution timing is still counted by C4's current manifest comparison. No
normalization was added by the harness to hide that difference.

[Machine-readable summaries](C4_LATEST_COMPARISON_RESULTS.json) include the
pinned comparator commit/hash and every differing-field name. Full comparisons
are retained under the git-ignored local directory
`group_B/agentic_ingestion/runtime/deadline-e2e-20261026/c4-5e76ccf/`.

Four compatibility tests exercise both real pinned scripts, input-validation
failure retention, difference reporting and explicit strict-mode failure.
Fixtures are test-only snapshots so CI does not require fetching unrelated
branch history. Group C production files are unchanged.

C4 still rejects empty claim lists, including valid benign results. This is
an upstream validation issue, separate from API compatibility; this harness
compares the nonempty attack/repeated-attack results. The live-agent
expected-verdict acceptance weakness identified in review is also separate
and is not changed by this fix.
