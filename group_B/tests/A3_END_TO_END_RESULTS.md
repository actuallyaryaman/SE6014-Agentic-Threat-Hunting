# Latest A3 → hunting/reporting integration — 2026-10-26

The bounded raw-stream chain passed against actual services:

`B3 → A3 UDP receiver → A2 HTTP → B1/B2 ES pipelines → HTTPS Elasticsearch → C1 MCP → C2 → C3 → C4`.

A3's existing parsing flow is preserved. Raw envelopes are a separate opt-in
receiver path. No external deployment or shared credentials are needed.

## Inputs and provenance

- Elasticsearch/Logstash 8.19.23 over verified HTTPS, isolated local services,
  temporary CA/certificates and scoped keys. Pipeline/image hashes are in JSON.
- B1 PR #26 `ff91812` and A3 PR #28 `218153a` were merged into this local
  integration branch, preserving their authors' history.
- C1/C2 PR #27 snapshot `fd9995af15804a7e2fe33b13d90f39911ef6ee36` (includes #22).
- C3 PR #23 `5d8ced350259c3727d9c1bddabf292194518797e`.
- C4 PR #25 `ae8b316730fdabcbe90929b6869c1a8f8bf0eef4`.
- Group C files are unchanged in this branch; pinned snapshots are temporary.
- [Implementation hashes](A3_IMPLEMENTATION_SHA256.json) identify the new
  B3/A3 code. The executed harness hash is in each summary.

## Rules mode: 28 checkpoints passed

35 SSH events were indexed via actual A3, with 31 planted attack events and
four benign events. Every attack citation was fetched independently from ES;
precision/recall are 1.0 for this scenario. Replay submitted zero records.

| Case | C2 | C3 | C3 identical query replays |
|---|---|---|---:|
| Attack | SUPPORTED | Confirmed | 15/15 |
| Benign | NOT_SUPPORTED | Refuted | 12/12 |
| Missing host | INCONCLUSIVE | Inconclusive | 12/12 |
| Empty date | INSUFFICIENT_DATA | Inconclusive | 8/8 |
| Repeated attack | SUPPORTED | Confirmed | 15/15 |

C3 verified every claim, with no unsupported/contradicted/unverified claims.
All **62/62** replayed queries matched; **C4 matched 7/7** fields.

Additional raw stream cases passed: **6 Apache records**, including a malformed
`TRACE /` request tagged `malformed_request`; **61 unknown JSON records** and
**6 unknown CSV records** using actual B2-generated pipelines. Each replay
submitted zero records and had no parse failures. Together with SSH, these
are **108 raw records** across four formats.

The original normalized A3 path forwarded three fixture events twice, retaining
only three indexed documents and preserving source/event IDs and originals.
An unapproved raw pipeline was rejected by A3 and B3 reported verification
failure, with zero indexed records. UDP sending alone never becomes success.

## Live DeepSeek agent: three hunts passed

DeepSeek `deepseek-flash` was used through its OpenAI-compatible endpoint,
with at most two investigator steps and an 8-call LLM budget per hunt.
The actual run completed **16 LLM calls**, using 23,096 input and 27,120 output
tokens across intake, investigator, skeptic and responder roles.

| Case | C3 verdict | Confidence | Claims verified | Identical replays |
|---|---|---|---:|---:|
| Attack | Confirmed | high | 2/2 | 21/21 |
| Benign | Refuted | medium | 0/0 | 13/13 |
| Repeated attack | Confirmed | medium | 2/2 | 21/21 |

All **55/55** query replays matched; no claims failed verification. C3 agreed
with C2 in every run. This was a live model run, not a rules fallback.

**Live-agent repeatability is partial: C4 matched 5/7.** The verdict label,
evidence and event IDs stayed stable, while the chosen queries and verdict
confidence differed. The skeptic lowered confidence on the repeated attack.
Do not present this as deterministic agent output. See
[the full C4 comparison](A3_DEEPSEEK_C4_COMPARISON.md),
[usage/agent decisions](A3_DEEPSEEK_USAGE.json), and
[the live summary](A3_DEEPSEEK_RESULTS.json).

## Tests, reproduction and cleanup

- Group B: 265 passed, 18 opt-in ES tests skipped, 8 subtests passed.
- Existing A3 normalized/UDP suite: 23 passed.
- Latest C2 offline/MCP suite: 116 passed, 25 ES/LLM tests deselected.
- A setup-only first attempt failed because an older temporary C2 interpreter
  had expired. The pinned environment was recreated; the subsequent complete
  runs above passed. No application failure was hidden by that retry.

Follow [the runbook](../DEMO_RUNBOOK.md#latest-bounded-a3-and-deepseek-chain)
and [the transport contract](../B3_A3_CONTRACT.md). Rules results are in
[A3_RULES_RESULTS.json](A3_RULES_RESULTS.json). Full synthetic traces, C3 reports,
LLM audits and file hashes are retained in the git-ignored local directory
`group_B/agentic_ingestion/runtime/deadline-e2e-20261026/`.
Provider keys are excluded from Git and evidence. Final code passes the key
only to C2's child environment; C3 verification receives no provider key.
All owned containers, networks, data, certificates and credentials were removed.

## Remaining scope

This completes a bounded local integration, not a lossless production stream.
Continuous UDP capture remains blocked. The later
[confirmed-year verification](YEAR_POLICY_E2E_RESULTS.md) completes yearless
Linux/firewall onboarding with explicit policy. Windows/Sysmon
playbooks, mixed-date behavior, broad accuracy/completeness, PDF rendering and
full-budget agent behavior were not established by these SSH-focused runs.
The existing C1 mapping-permission caveat is separate; these runs used the
required read plus view_index_metadata privileges. Cross-team review and
merging the tested Group C PRs are still needed.
