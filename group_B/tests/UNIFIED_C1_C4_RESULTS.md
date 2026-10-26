# Unified local C1–C4 integration — 2026-10-26

**Passed: 23 checkpoints.** Actual B3 onboarding → unchanged A2 push → real
B1 parser → authenticated HTTPS Elasticsearch 8.19.23 → delivered C1 MCP →
updated C2 → independent C3 verification/report → C4 repeatability comparison.
No live LLM was configured or called.

## Pinned code

- B3/main baseline: `c04b75390ddc594000fc3cd668cf9f117a32fc96`.
- C1/C2 (#22): `676c21b73c46e4a2632d0d855a922497cc0b9c15`.
  This includes the delivered C1 package and #22's compatibility/limit changes.
- C3 (#23): `5d8ced350259c3727d9c1bddabf292194518797e`.
- C4 (#25): `ae8b316730fdabcbe90929b6869c1a8f8bf0eef4`.

Only committed Group C files were copied into temporary snapshots; private
`.env` files were excluded. Group C source in this branch is unchanged.
The harness checks C2's manifest selects `es_mcp_server.server` and starts
that same server independently for C3. Offline verification fallback fails.

## Observed results

35 synthetic SSH events were indexed and independently checked: 31 attack
and four benign events. Re-onboarding reused 35 and submitted zero records.
All 31 attack citations matched ground truth exactly (precision/recall 1.0
for this planted scenario).

| Case | C2 | C3 | Verified claims | Identical replayed queries |
|---|---|---|---:|---:|
| Attack | SUPPORTED | Confirmed | 2 | 15/15 |
| Benign host | NOT_SUPPORTED | Refuted | 0 | 12/12 |
| Missing host | INCONCLUSIVE | Inconclusive | 0 | 12/12 |
| Empty date | INSUFFICIENT_DATA | Inconclusive | 0 | 8/8 |
| Attack repeated | SUPPORTED | Confirmed | 2 | 15/15 |

C3 agreed with C2 in all five cases. No claims were unsupported, contradicted
or unverified. All **62/62** replayed queries matched; none were skipped.
Confirmed results require analyst review.

C4 matched all **7/7** compared fields: hypothesis, time range, verdict,
coverage, evidence IDs, cited event IDs and ordered queries. The harness also
compares claim texts and request hashes directly between attack runs.
See [C4's report](UNIFIED_C4_COMPARISON.md).

This replaces the earlier claim-mismatch finding only for the new pinned
snapshots. Earlier [results](C2_C3_INTEGRATION_RESULTS.md) remain historical.

## Reproduction and evidence

Follow [the unified runbook section](../DEMO_RUNBOOK.md#delivered-c1-with-updated-c2c3-and-c4).
The [machine-readable summary](UNIFIED_C1_C4_RESULTS.json) records Git commits,
executed-script hashes, dependency versions, image digests and every checkpoint.
Full synthetic results, traces, both MCP audit streams, C3 bundles and
JSON/Markdown/HTML reports are retained locally under
`group_B/agentic_ingestion/runtime/unified-c1-c4-20261026/` (git-ignored).
`artifact-sha256.json` records hashes of those original output files.

Fresh Group B regression: **259 passed, 17 opt-in live tests skipped,
8 subtests passed**. The separate live harness above passed all 23 checkpoints.
Cleanup removed all owned containers/network/data, certificates and keys.

## Limits

This verifies the bounded SSH scenario in a dedicated local index. It does
not test A3 streaming, yearless firewall policy, mixed-date index behavior,
all playbooks, PDF rendering, live LLMs or broad accuracy/completeness.
C2's documented time-window caveat remains open. The selected Group C PRs
were tested as snapshots; this run does not merge or publish them.
