# C4 corrections and seeded-scenario acceptance — 2026-10-26

The integration branch includes the current C4 author's history and adds:

- Valid zero-claim/evidence negative results are accepted; required fields,
  queries and evidence links remain validated. SUPPORTED without claims fails.
- Top-level `manifest.phase_seconds` is treated as execution timing, alongside
  duration and audit-file paths. Nested controls, model/settings, timestamps,
  claim facts, evidence and query values remain compared.
- Live and rules runs use the same seeded C2 labels and exact attack citation
  set. C3's expected verdict is fixed by scenario, never derived from C2.

## Re-evaluation of retained outputs

No Elasticsearch services or LLMs were called. Eight saved scenarios passed
the strengthened verdict/evidence checks: five rules scenarios and three
DeepSeek scenarios. Citation sets were checked against each run's previously
live-verified 31-event attack baseline; this was not a fresh ES fetch.

| Comparison | Corrected C4 |
|---|---:|
| Rules attack / repeat | 24/24 |
| Rules benign / itself (valid zero claims) | 24/24 |
| DeepSeek attack / repeat | 14/24 |
| DeepSeek benign / itself (valid zero claims) | 24/24 |

The benign self-comparisons test input acceptance, not an independent repeated
hunt. Live DeepSeek differences remain visible: verdict confidence, evidence
contents, queries, actions, agent decisions, dynamic steps, intake, manifest,
skeptic and step results. Model behavior was not changed to improve the score.

[Machine-readable recheck](C4_CORRECTED_RECHECK_RESULTS.json) pins C4 source
commit `315cb6c784d32fdeabfa41546c285d329f556d3e`. Historical upstream scores
remain in [the compatibility record](C4_COMPATIBILITY_RESULTS.md).
Full comparisons: git-ignored local
`group_B/agentic_ingestion/runtime/deadline-e2e-20261026/corrected-c4-315cb6c/`.

13 C4 unit tests plus three subtests pass, including empty-negative handling,
invalid positive/required input, timing-only variance, nested setting changes
and event/query tampering. Five ground-truth tests exercise wrong verdicts,
missing or extra attack citations and unexpected negative claims. C4 tests
are also included in repository CI. No new coauthor trailers were added.

Fresh combined Group B/C4 suite: **287 passed, 18 opt-in live tests skipped,
11 subtests passed**.
