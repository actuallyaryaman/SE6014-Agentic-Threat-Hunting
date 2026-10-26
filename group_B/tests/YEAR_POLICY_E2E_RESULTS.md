# Confirmed-year onboarding and final integration verification

Date: 2026-10-26. Implementation: `59b283127c17b55831a3348750b3a15fcc1b3d32`
on `codex/b3-unified-c1-c4-validation`, PR #29.

B3 now requires a confirmed year and IANA timezone for yearless Linux/firewall
sources. A3/A2 preserve `labels.log_year`, `labels.log_timezone`, source/pipeline
metadata and stable position-based IDs. B1 parses the original text inside
Elasticsearch and normalizes the result to UTC. B3 independently checks the
exact timestamp and metadata, including before replay.

## Rules verification

The actual chain was exercised with Elasticsearch/Logstash 8.19.23, A3 receiver,
B1/B2 pipelines, delivered C1 MCP, pinned C2/C3 and corrected C4. All **30 live
checkpoints passed**. The run indexed 112 raw records (35 SSH, six Apache,
61 generated JSON, six generated CSV, two yearless Linux and two yearless
firewall), plus three legacy normalized documents after six legacy sends.
All raw replay submissions were zero. Unapproved raw pipelines did not verify.

| Case | Confirmed policy | Expected UTC result |
| --- | --- | --- |
| Linux leap day `Feb 29 00:15:00` | 2024, UTC | `2024-02-29T00:15:00Z` |
| Firewall `Jan 1 00:15:00` | 2024, Asia/Singapore | `2023-12-31T16:15:00Z` |

Both cases preserve two identical records under distinct logical IDs, original
text, source/pipeline labels and event IDs. Missing onboarding year is blocked;
direct pipeline simulation without policy is tagged `_parse_failure`. Changed
year on existing IDs fails with `EXISTING_DOCUMENT_CONFLICT` and no submission.
The exact UTC check caught an initial ES local-offset output; a second date
processor now normalizes that instant to UTC. The failed diagnostic run was
not counted as a pass.

Attack/benign/missing-host/empty-window/repeated-attack results match seeded
expectations. C3 independently verifies all positive claims and replays all
queries identically (66/66). Corrected C4 matches **24/24** rules comparison fields.
The complete summary is [YEAR_POLICY_RULES_RESULTS.json](YEAR_POLICY_RULES_RESULTS.json).

The rules run used the implementation worktree before it was committed; its
raw `code_head` records parent `640af07`. The committed executed-source hashes
are retained in [YEAR_POLICY_IMPLEMENTATION_SHA256.json](YEAR_POLICY_IMPLEMENTATION_SHA256.json).
No production implementation bytes changed between this run and `59b2831`.

## Fresh live-agent attempt

The fresh DeepSeek run on `59b2831` failed the attack gate: cited IDs differed
from the independent 31-event attack set. This is a failed run, regardless of
the earlier passing live results. The original harness discarded the failing
hunt before copying its output; `876e562` moves evidence retention before
acceptance and records missing/unexpected IDs without weakening the gate.
The failed attempt is recorded in
[YEAR_POLICY_LIVE_ATTEMPTS.json](YEAR_POLICY_LIVE_ATTEMPTS.json).

The single diagnostic rerun on `876e562` failed the same strict gate and
retained the cause: **31/31 attack IDs were present, plus one BENIGN-SSH login**.
Agent query AG-01 searched successful Linux logins without a `host.name` filter.
C2 generated claim C-003 about BENIGN-SSH (`origin=llm`, `context_only=false`).
This is scope leakage in C2's agent/claim path, not missing or duplicated input.
C3/C4 were not reached in either fresh live attempt; their earlier passing
results do not establish that this fresh agent output is acceptable.

The targeted follow-up is to enforce hypothesis entity scope on C2's follow-up
queries/claim promotion, retain broad results only as explicit context, and
add an offline regression containing this exact two-host response. Then rerun
attack, benign and repeat through independent C3 verification. The strict
expected-ID gate stays unchanged. This C2 change is not implemented here;
#27 remains the tested external snapshot owned by Group C.

## Regression checks

- Group B plus C4: **302 passed, 19 opt-in live tests skipped, 11 subtests passed**.
- Existing A3 UDP/parser/forwarding suite: **23 passed**, one existing optional-field warning.
- All five GitHub checks on `59b2831` passed, including B1's live ES suite with
  missing-policy and timezone tests. PR was clean/mergeable at that check.
- Invalid non-leap dates beyond the 50-record inspection sample and ambiguous
  or nonexistent DST wall times fail before transport.

## Reproduce

Prepare the separate Group C environment as in [DEMO_RUNBOOK.md](../DEMO_RUNBOOK.md),
including Jinja2 3.1.6. Fetch PR #29 and the component refs so these commits exist.
Run from the repository root with Docker access:

```bash
group_B/.venv/bin/python group_B/scripts/check_onboarding_hunt_demo.py \
  --hunt-python /absolute/path/to/hunt-venv/bin/python \
  --c2-ref fd9995af15804a7e2fe33b13d90f39911ef6ee36 \
  --c3-ref 5d8ced350259c3727d9c1bddabf292194518797e \
  --es-mcp-module es_mcp_server.server --require-c3-agreement \
  --c4-ref 315cb6c784d32fdeabfa41546c285d329f556d3e \
  --a3-stream --output-dir /tmp/smtd-final-rules-new
```

For bounded live DeepSeek hunts, add
`--llm-env /absolute/path/to/private-provider.env` and choose a different new
output directory. The provider file stays local; credentials are never shared.
The rules command additionally exercises the year-policy and transport cases.

## Scope and remaining coordination

This establishes bounded local integration. Continuous UDP capture, lossless
transport, year-spanning source inference, Windows/Sysmon hunting coverage and
PDF rendering are outside these checks. A3 raw envelopes remain opt-in and
allowlisted; deploy the changed B1 pipeline definitions before yearless onboarding.
C2/C3 are tested pinned snapshots, not merged into this branch. Ay/Dat still
need to review/reproduce locally and coordinate the reviewed component merges.
