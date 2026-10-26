# C3: evidence checking, verdict and report

Owner: C3 (Group C)

C2 now works from playbooks. The planner picks ATT&CK techniques and
requirement groups, every query sits in a vetted playbook step, and code turns
the step results into most of the claims. C3 reads what C2 writes, checks it
again on its own, and decides the verdict by rules.

```
C2 hunter -> HuntBundle (plan, evidence, claims, audit log, notes)
                |
C3        verify_bundle()   fetch the cited events again, compare quoted facts, check the claim text,
                |              replay aggregates and IOC lookups, replay every audited query
             decide()          Confirmed, Refuted or Inconclusive per requirement group
                |
             summary + report  JSON (for C4), Markdown, HTML, optional PDF
```

| Module | Task | What it does |
|---|---|---|
| `contracts.py` | T33 | Defines `HuntPlan`, `PlanStep`, `Evidence`, `Claim`, `AuditRecord`, `HuntNotes` and `HuntBundle`. `bundle_from_run_dir()` loads a C2 run folder. |
| `audit.py` | T33 | `result_hash()`, written to match the C1 server exactly. |
| `esclient.py`, `injection.py`, `util.py` | T35 | Read-only Elasticsearch client, prompt-injection scanner, UTC and Markdown helpers. |
| `gateways.py` | T35 | `MCPGateway` (separate connection to C1), `ESGateway` (read-only DSL replay) and `OfflineGateway`. |
| `verifier.py` | T35 | Sets the claim status (`verified`, `unsupported`, `contradicted` or `unverified`) and replays queries. |
| `verdict.py` | T36 | Rules per requirement group, minimum independent indicators, confidence, analyst review. |
| `summary.py` | T34 | Writes the summary from rules. An LLM rephrase is accepted only if it adds no IP, number or hash. |
| `report.py`, `templates/` | T34 | Report with 8 sections and 2 appendices, in JSON, Markdown, HTML or PDF. |
| `cli.py` | T34 | Commands `report`, `from-run` and `export-schemas`. |

## Verdict rules

| Verdict | When |
|---|---|
| Confirmed | Every requirement group has a technique with at least `min_support` independent verified indicators. Independent means distinct playbook steps, so one step seen in two time windows counts once. |
| Refuted | No group has a verified signal or below-threshold activity, every group could be tested over data without gaps, and no claim is left unverified. |
| Inconclusive | Everything else. The report gives the reasons and what would settle the question. |

The guardrails are:

- Only `verified` claims count.
- Support that comes only from LLM-proposed queries is a lead and never proof.
- Techniques chosen only by the LLM never decide the verdict.
- A host named in the hypothesis with no telemetry makes the verdict Inconclusive.
- Offline verification never decides anything.
- Confidence `high` needs at least two independent verified steps and full coverage (DESIGN §4.1).
- Every Confirmed verdict needs analyst review.
- Cited events with text aimed at an AI also force analyst review.

## Reviewing C2's own verdict

C2 drafts a verdict (`SUPPORTED`, `NOT_SUPPORTED`, `INCONCLUSIVE` or `INSUFFICIENT_DATA`) from its playbook
rules and writes it to `result.json`. C3 computes its own verdict from the claims it verified, then compares
the two. The final verdict stays the same or becomes more cautious. C3 never upgrades a C2 verdict.

| C2 said | C3's own result | Final | `review.outcome` |
|---|---|---|---|
| SUPPORTED, high | Confirmed, high | Confirmed, high | `agrees` |
| SUPPORTED, high | Confirmed, medium | Confirmed, medium | `downgraded` |
| SUPPORTED | Inconclusive (claims fail, or offline) | Inconclusive | `downgraded` |
| SUPPORTED | Refuted | Inconclusive | `contradicts` |
| INCONCLUSIVE or INSUFFICIENT_DATA | anything else | Inconclusive | `kept_c2_caution` |

The report prints both verdicts, for example "C2's draft verdict ... C3 review: downgraded".

## Reading C2's output

`bundle_from_run_dir()` and `cli from-run` read the run folder that the C2 prototype writes:

```
runs/<run_id>/plan.json     the plan
runs/<run_id>/result.json   schema 0.2, binding (INTERFACES §4.1): verdict (with review_reasons), techniques, claims, evidence,
                            findings (prompt_injection), step_results, dynamic_steps, queries (every MCP call), self_check,
                            coverage, limitations, notes, manifest
runs/<run_id>/trace.jsonl   the same calls as result.json queries[]. C2 still writes it. C3 uses queries[] and falls back
                            to this file for schema 0.1 runs.
audit/<run_id>.jsonl        C1 audit log: params, dsl, total, returned_ids, result_hash (Elasticsearch server only)
audit/<run_id>-analytics.jsonl   audit of C2's analytics server (check_ioc, gap_check, lookup_attack)
```

A few details of that format matter for C3:

- Claims arrive as `self_checked`, meaning C2's structural check passed. C3 verifies them again and reports its
  own four statuses. The original value stays in `claim.c2_status`.
- Calls to the analytics server are audited in `audit/<run_id>-analytics.jsonl`. C3 finds the file next to the ES
  audit file, or you can pass it with `--analytics-audit`. Evidence that points to such a call is accepted. C3
  replays these calls and compares only the totals, because the hash formula for them is C2's own. Replay needs MCP
  mode with `C3_MCP_ANALYTICS_ARGS`. Over plain Elasticsearch they are listed as "could not be replayed".
- `findings.prompt_injection` (C2 found log events with text aimed at an AI) becomes the flag
  `c2_prompt_injection`. The report shows it and an analyst must review the hunt. The text itself never reaches a verdict.
- The step behind a claim is not always in `plan.json`. C2 creates drill-down steps per attacker IP or host at run
  time (for example `T1078-b-203.0.113.99`) and lists their definitions in `dynamic_steps` in `result.json`. C3
  matches such a step to its plan step by prefix and takes the log source from the audited call.
- `coverage` is nested: `coverage.<source>.{total, n_buckets, empty_buckets, coverage_ratio}`. `notes` is a list of
  free-text baseline remarks, which the report prints in the baselines section.
- A log source is the dataset in the step's `event.dataset` filter (`linux.auth` becomes `auth`, Sysmon becomes
  `sysmon`), because every dataset lives in one index (`security-events-*`).

Confidence `high` needs at least two independent verified steps and full coverage (DESIGN §4.1). If you set
`C3_MIN_LOG_SOURCES=2`, it also needs events from two log sources, and the report then says that C3 lowered the
confidence and why.

Analyst review is required, and listed in `review_reasons`, for any of these (INTERFACES §4.3): a Confirmed
verdict, low confidence, a coverage gap (fewer than 95% of hourly buckets have events), prompt-injection-like text,
or a claim that failed verification.

## Claim checks

| Status | Cause |
|---|---|
| `unsupported` | The evidence id is unknown, or its call failed or was not audited. The claim cites no events, or a cited event cannot be retrieved. |
| `contradicted` | A quoted fact is not in the cited events. A replayed aggregate or IOC gives a different result. The claim text names an IP, host, account, number or hash that is not in its evidence (see below). |
| `verified` | All checks passed. |
| `unverified` | The claim cannot be checked in this mode (offline, or Elasticsearch cannot replay an IOC lookup), or it cites more than 500 events. C3 fetches every cited event again and never checks a sample. |

### Facts are not evidence

The `facts` field of a claim is what C2 says it quoted. C3 checks it and never uses it to back up the claim text.
For event claims, each fact must match the re-fetched events. For aggregate claims, `bucket_key` and `count` must
match the replayed bucket, and every other fact must match the events behind the bucket (or appear in the replayed
response or the step query). The claim text is then linted against the re-fetched events, the step query and the
replayed bucket only. A name or number that appears only in `facts` and in the text makes the claim `contradicted`.

### Text lint

Every IP, host name, account, number (2 or more digits) and hash in a claim's sentence must appear in that claim's
evidence. The match is by whole token, so `50` is not found inside `14:00:50` and `10.0.2.10` is not found inside
`10.0.2.100`.

Host names look like `WS-02` or `web-01`: letters, dashes and at least one digit. Accounts are read only from
high-precision patterns such as "logged in successfully as admin", `user=alice`, `account svc_backup2` and
`CORP\alice`. The extractor is a heuristic. It only has to catch invented names, so ordinary prose such as
"as suspected" is not flagged.

### Narrative check

C2 also writes free text about the whole hunt: `verdict.reasons`, a `rationale` field if present, and the run
`notes`. C3 checks this text the same way, against the plan, the claims that were not rejected, the evidence
excerpts and the audit log. A hit becomes the flag `narrative_unsupported_entity`. It does not change the verdict,
but it forces analyst review and appears in the report (verification summary, "Why this verdict" and limitations).

### PDF

`--formats json,md,html,pdf` also writes a PDF made from the HTML report. It needs WeasyPrint
(`pip install weasyprint`) or Playwright (`pip install playwright && playwright install chromium`). Both are
optional. Without one, the CLI prints a message and writes the other formats.

## Usage (from the repo root)

```bash
# offline preview (the verdict stays Inconclusive because nothing is re-checked)
python -m group_C.threat_hunting.evidence.cli report --bundle tests/group_C/c3/fixtures/hunt_bundle_confirmed.json

# live: load the sample into the dev Elasticsearch, then verify against it
docker compose -f group_C/threat_hunting/evidence/dev/docker-compose.dev.yml up -d elasticsearch
python group_C/threat_hunting/evidence/dev/load_sample_data.py --reset
python -m group_C.threat_hunting.evidence.cli report --bundle tests/group_C/c3/fixtures/hunt_bundle_confirmed.json --verify es

# through C1's MCP server (set C3_MCP_COMMAND and C3_MCP_ARGS in .env, see evidence/.env.example)
python -m group_C.threat_hunting.evidence.cli report --bundle <bundle.json> --verify mcp --formats json,md,html,pdf

# from a C2 run folder (the analytics audit file is read from next to the audit file)
python -m group_C.threat_hunting.evidence.cli from-run --plan runs/<id>/plan.json \
    --result runs/<id>/result.json --audit audit/<id>.jsonl --out hunt_bundle.json

# both MCP servers (C1 for Elasticsearch, C2's analytics server for check_ioc)
C3_MCP_ANALYTICS_COMMAND=python C3_MCP_ANALYTICS_ARGS="-m analytics_server.server" \
    python -m group_C.threat_hunting.evidence.cli report --bundle hunt_bundle.json --verify mcp
```

## Integration for C2

```python
from group_C.threat_hunting.evidence import HuntBundle, MCPGateway, run_with_gateway, write_report

bundle = HuntBundle(run_id=run_id, plan=plan, evidence=st.evidence, claims=st.claims,
                    audit=Audit.read(run_id), step_results=st.step_results, dynamic_steps=st.dynamic_steps,
                    weak_signals=st.weak_signals, notes=notes, baselines=baselines, limitations=limitations, meta=meta)
report = await run_with_gateway(bundle, MCPGateway(cmd, args, run_id=run_id + "-verify"))
write_report(report, "group_C/experiments/reports")
```

`notes.min_support` carries the playbook thresholds, for example `{"T1003.001": 2, "T1021.002": 2}`.

## Tests

Run `python -m pytest tests/group_C/c3 -q`. Without pytest, use `python -m unittest discover -s tests -t .`.
`python -m tests.group_C.c3.fixture_builder` regenerates the four example bundles.

`tests/group_C/c3/test_c2_runs.py` runs C3 on C2's two real sample runs (`c2_runs/`) and on tampered copies
with ten planted errors (`tamper.py`). See `tests/group_C/c3/c2_runs/README.md`.
