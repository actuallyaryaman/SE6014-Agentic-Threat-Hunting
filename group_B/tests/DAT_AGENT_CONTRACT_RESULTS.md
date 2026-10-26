# Agent-mode contract alignment and live verification

Date: 2026-10-26. Harness commit `54719612323dfad26e0efd190405c627e6b9ca0f`;
C2 PR #31 `3a0ebbe0d0cbc6f43b4a416aefa920373f7788ba`;
C3 `5d8ced350259c3727d9c1bddabf292194518797e`;
C4 `315cb6c784d32fdeabfa41546c285d329f556d3e`.

## Correction to the earlier benign failure diagnosis

Dat confirmed the intended agent-mode contract. C2 INTERFACES sections 4.2–4.3
explicitly say LLM-origin findings are leads, never vetted support, and leads on
a required technique block NOT_SUPPORTED. The earlier BENIGN-SSH INCONCLUSIVE
result was consistent with that contract. Our harness incorrectly required
rules-mode NOT_SUPPORTED/no claims in both modes; calling this a C2 blocker was
incorrect. The earlier aborted run remains historical, not a completed pass.

The harness now independently fetches the four benign ground-truth IDs and
accepts agent INCONCLUSIVE only with nonempty self-checked LLM leads, citations
inside that benign set, exact lead attribution, low confidence, required analyst
review, and no vetted technique support. Rules mode still requires NOT_SUPPORTED
with no claims. Agent NOT_SUPPORTED with no leads remains valid too. Both attack
runs still require exactly the 31 attack IDs. C3 expectations follow these
explicitly validated contract branches, not unrestricted agreement with C2.

## Fresh live result: passed

Actual B3 -> A3 UDP -> A2 HTTP -> B1 -> HTTPS Elasticsearch -> C1 MCP -> C2 ->
C3 -> C4; DeepSeek Flash, 17 live calls across three bounded hunts. No fallback
to rules or offline C3 verification was accepted.

| Case | C2 | Claims | Cited IDs | C3 | Identical query replays |
| --- | --- | --- | --- | --- | --- |
| Attack | SUPPORTED | 4 | exactly 31 attack IDs | Confirmed; 4/4 verified | 24/24 |
| Benign | INCONCLUSIVE | 1 LLM lead | 1 of 4 allowed benign IDs | Inconclusive; 1/1 verified | 15/15 |
| Attack repeat | SUPPORTED | 3 | exactly 31 attack IDs | Confirmed; 3/3 verified | 24/24 |

All eight claims were independently verified, no unsupported/contradicted/
unverified claims, no cross-host IDs, and 63/63 identical query replays.
C4 comparison completed: **11/24 fields match**, with real agent/query/claim and
verdict review-detail differences preserved. Attack confidence stayed high in both runs. This establishes bounded end-to-end operation
and evidence validation, not deterministic LLM behavior. Rules repeatability is
a separate check. Full comparison: [DAT_AGENT_C4_COMPARISON.md](DAT_AGENT_C4_COMPARISON.md).

Regression: Group B/C4 311 passed, 23 opt-in live cases skipped, 11 subtests.
C2 pinned offline suite 120 passed, 27 ES/LLM cases deselected. Nine additional
contract tests reject cross-host IDs, playbook-origin benign claims, missing
lead attribution/review, high confidence, vetted support and benign SUPPORTED;
rules mode rejects the agent-specific inconclusive branch.

Full live summary: [DAT_AGENT_CONTRACT_RESULTS.json](DAT_AGENT_CONTRACT_RESULTS.json).
Synthetic traces/reports/audits retained under ignored
`group_B/agentic_ingestion/runtime/dat-contract-aligned-20261026/`.
All owned services/data/certificates/credentials were cleaned up. Provider key
stays local and is absent from the evidence. PR #31 was tested as a pinned snapshot and was not merged into this branch.

Reproduction commands are in [DEMO_RUNBOOK.md](../DEMO_RUNBOOK.md): use the pins
above, `--a3-stream --require-c3-agreement`, and `--llm-env` pointing to a private
provider file. Omit `--llm-env` for the strict rules-mode ingestion baseline.

## Same-harness strict rules rerun

The final rules run used the same committed harness `5471961` and the same C2,
C3 and C4 pins. All 31 checkpoints passed, including the 24-test live B1 suite,
112 raw plus three legacy documents, replay zero, year/timezone checks and
unapproved-pipeline rejection. BENIGN-SSH stayed NOT_SUPPORTED with zero claims.
C3 replayed 66/66 queries identically; C4 matched 24/24 rules fields.
[Complete rules summary](DAT_CONTRACT_RULES_RESULTS.json).
