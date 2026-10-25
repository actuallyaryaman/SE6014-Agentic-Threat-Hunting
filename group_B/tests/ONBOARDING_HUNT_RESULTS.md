# Onboarding-to-hunt demo — 2026-10-25

Completed locally using the real B3 executor, unchanged A2 HTTP pipeline,
authenticated HTTPS Elasticsearch, real B1 Linux parser, C2's existing MCP
servers and rules-based hunt engine. No live LLM calls or changes to Group C.

```text
synthetic SSH source
  → B3 inspection / real B1 recognition / approved pipeline
  → actual A2 HTTP input
  → authenticated HTTPS Elasticsearch / B1 linux-auth
  → C2's read-only development ES MCP server + analytics MCP server
  → C2 claims, verdict, audit trace and independent event-ID checks
```

This uses the **existing C1 development stand-in**, not Xuelei's final service.
It also uses C2's unchanged development index template in its test namespace,
not an agreed production mapping. Shared deployment/C1/C3/A3 sign-off remains.

## Verified results

B3 indexed **35 events**: 30 failed logins and one later successful login on
`DEMO-SSH`, plus three failures and a success on `BENIGN-SSH`. All went through
A2 and B1; none were directly bulk-loaded into ES. Replay submitted zero new
records and reused all 35. Ground truth contains exactly 31 attack events.

| Hunt | Verdict | Claims | Unique cited events | MCP calls |
|---|---|---:|---:|---:|
| attack | SUPPORTED | 2 | 31 | 15 |
| benign | NOT_SUPPORTED | 0 | 0 | 12 |
| missing-host | INCONCLUSIVE | 0 | 0 | 12 |
| empty-window | INSUFFICIENT_DATA | 0 | 0 | 8 |
| attack-repeat | SUPPORTED | 2 | 31 | 15 |

The attack hunt's two claims were:

- Source 203.0.113.99 produced 30 failed SSH logins
- Source 203.0.113.99 logged in successfully as demo on DEMO-SSH after its failed SSH logins began (30 failures from this source in the window)

- Citation precision and recall both **1.0** against the 31 planted attack
  events. The four benign events were excluded.
- All cited Elasticsearch IDs were fetched independently and checked for the
  ingested source ID, dataset and preserved original. This is narrower than
  C3's full independent claim/count verifier.
- All MCP calls succeeded and traversed the ES/analytics servers. Both attack
  claims passed C2's structural self-check.
- The repeated attack hunt had identical query request hashes, claim texts,
  evidence IDs and verdict. Runtime/run IDs are not expected to be identical.
- The planner was rules-based in every run. The environment passed to C2 was
  allowlisted and had no paid API keys or developer `.env` files.
- C2's existing offline suite passed **35 tests**, with 10 live tests deselected,
  in a temporary tracked-code snapshot and separate pinned environment.

## Reproduction and evidence

See [the demo runbook](../DEMO_RUNBOOK.md) for one-command execution after
prerequisites. [ONBOARDING_HUNT_RESULTS.json](ONBOARDING_HUNT_RESULTS.json)
records the exact C2 Git tree, dependency versions, hashes and checkpoint results.
Full synthetic per-run results, MCP traces and audits were retained locally at
`/tmp/smtd-onboarding-hunt-demo-3/`; a new run creates its own output folder.

No owner source files or the Group B Python environment were changed. All
owned Docker services/network/data/certificates/credentials were removed; the
existing Firefly services were left running.

## Setup findings and limits

The first attempt exposed an interpreter-path issue in the new harness; it
now preserves the virtual-environment executable instead of resolving its
symlink to base Python. The second attempt exposed an index-prefix mismatch:
A2 accepted HTTP while B3 verified another namespace, so B3 correctly failed.
The final run aligns A2/B3/C2 on `security-events-c2test*` and passed all cases.

This demo tests one SSH playbook chain, not all techniques. It does not certify
C1's final server, C3's report/verifier, shared-host connectivity, A3 streaming,
DLQ/restart recovery, or live LLM behavior. Firewall year policy remains open.
