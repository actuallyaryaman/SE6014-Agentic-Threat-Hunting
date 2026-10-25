# C2/C3 live integration — 2026-10-25

The integration ran against real Elasticsearch 8.19.23, unchanged A2 push,
real B1 parsing and the B3 executor. C2 #22 and C3 #23 were temporary snapshots;
Group C source files in this branch were not changed. C1 was C2's development
MCP stand-in, and no LLM was called.

- C2 commit: `a8b4a58bb9febab48b57279b09865368859dc887` (result schema 0.2).
- C3 commit: `e98599eb3b5309c4655124cc25265fe6a9d9f230`.
- Separate C2 environment; Jinja2 3.1.6/MarkupSafe 3.0.4 added for C3 reports.
- 35 SSH events indexed and independently checked; replay submitted zero.
- C2 cited exactly the 31 planted attack events. Its five outcomes were
  SUPPORTED, NOT_SUPPORTED, INCONCLUSIVE, INSUFFICIENT_DATA, SUPPORTED.
- C3 produced JSON/Markdown/HTML reports over a separate live MCP connection.
  Query replay matched **62/62**, with no mismatches or skipped replayable calls.
- All five C3 final verdicts were **Inconclusive**. This is transport/report
  integration evidence, not confirmation that the positive scenario is ready.

## Unresolved claim/evidence contract

On both attack runs, C3 verified C-001 (30 failed SSH logins) but contradicted
C-002 (successful login after those failures). C-002 includes
`facts.failed_logins="30"`, yet its evidence and event IDs cite only the
single successful-login event. C3 reports:

> failed_logins='30' not present in 1 of 1 cited events

The underlying aggregate and successful-login queries replay identically.
C2/C3 owners should agree how a correlation claim cites both the failure
aggregate and success event, or split the derived count into its own claim.
Do not weaken independent verification to make the demo appear confirmed.

C3 also downgrades the benign NOT_SUPPORTED result to Inconclusive because
it considers T1078 untestable without a selected step. Missing-host and
empty-window retain cautious verdicts. These are recorded findings for owner
review, not silently normalized by this harness.

## Evidence and reproduction

[Machine-readable summary](C2_C3_INTEGRATION_RESULTS.json) records provenance,
all 22 passed execution checkpoints, hunt outcomes and C3 verification counts.
[Full synthetic run artifacts](c2_c3_evidence/attack/c3/hunt_report_attack.json)
include original C2 outputs, queries/audit, C3 bundle and reports for every run.
The harness file hash identifies the executed version; its docstring was
subsequently clarified to mention optional C3 verification.

Follow [the runbook](../DEMO_RUNBOOK.md#test-the-proposed-c2c3-contracts).
Credentials, certificates, data and owned containers/network were deleted.
No final C1 server, PDF renderer, A3 stream or paid LLM was tested.
