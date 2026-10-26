# C3 guide: evidence verification and report generation (SE6014)

This guide walks through the C3 tasks (T33 to T36) in SE6014_Q1_Team_Plan_Revised.xlsx, using the code in
`group_C/threat_hunting/evidence/`. It follows the project README (Common Log Schema, Integration Standards,
Repository Structure, GitHub Guidelines, Integration and Testing) and the C2 design.

## 1. What C3 does

C2 runs the hunt. A planner picks ATT&CK techniques, vetted playbooks hold every query, code turns query results
into claims, and C2 drafts a verdict. C3 trusts none of this. It reads C2's run folder and checks each claim and each
query again against the log store, through a read-only connection. It then decides the verdict by rules, compares it
with C2's draft, and writes the report.

| ID | Task | Delivered in |
|---|---|---|
| T33 | Evidence and query-trace record format | `contracts.py`, `audit.py`, `schemas/*.json`, `docs/contracts/c3_hunt_bundle.md` |
| T34 | Automated hunt report | `report.py`, `summary.py`, `templates/`, `cli.py` (JSON, Markdown, HTML, PDF) |
| T35 | Validate claims against stored evidence | `verifier.py`, `gateways.py` |
| T36 | Coverage and hallucination safeguards | `verdict.py`, the lint and narrative checks in `verifier.py` |

C3 also writes the "Agentic workflow design" section of the report (with C2), the guardrail demo, and the Q&A answer to
"What if the AI makes something up?" (the planted-error table in section 6). C4 compares runs using the verdict and the
verified claims in the JSON report.

## 2. What it checks

| Check | How |
|---|---|
| Every claim cites evidence and a query | evidence id must exist and its call must be in the audit log (or in `audit/<id>-analytics.jsonl` for analytics calls) |
| Quoted facts exist | cited events are fetched again (`get_event`) and the quoted fields compared |
| Numbers match aggregations | the aggregation is run again and the bucket compared |
| Names in the sentence exist | IPs, hosts, accounts, numbers and hashes in the claim text must be in the evidence (whole-token match) |
| Queries reproduce | Every audited query is run again; `result_hash` must match |
| C2's own text is grounded | verdict reasons, rationale and notes may not name an IP, host or account that is in no evidence |
| Verdict | Confirmed, Refuted or Inconclusive by rules. It is then compared with C2's draft and kept or lowered, never upgraded |
| Hostile log text | Text aimed at an AI inside cited events is flagged and forces analyst review |

Claim statuses are `verified`, `unsupported`, `contradicted` and `unverified` (could not be checked). C3 verifies C2's
`self_checked` claims again and keeps C2's value in `claim.c2_status`.

## 3. What to install

| Software | Version | Purpose |
|---|---|---|
| Python | 3.11.x (team standard) | run the code |
| Git | latest | shared repository |
| Docker Desktop (+ Compose) | latest | local Elasticsearch for live verification |

```bash
python3.11 -m venv .venv
source .venv/bin/activate                 # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r group_C/threat_hunting/evidence/requirements.txt
```

Required packages are `pydantic` 2.x and `jinja2` 3.x. Optional packages are `python-dotenv` (for `.env`), `mcp` (verification
through C1's MCP server, using C1's version), `weasyprint` or `playwright` (PDF), `pytest` and `jsonschema` (tests). You do not
need `elasticsearch-py`. C3 uses a REST client built on the standard library that can only read (GET `_doc`, POST `_search`
and `_count`).

## 4. File layout

```
group_C/threat_hunting/evidence/
  contracts.py    HuntBundle, Claim, Evidence, AuditRecord, C2Verdict; bundle_from_run_dir()
  audit.py        result_hash(), identical to the C1 server
  gateways.py     MCPGateway (C1 + analytics server), ESGateway (read-only DSL replay), OfflineGateway
  verifier.py     claim checks, text lint, narrative check, query replay
  verdict.py      verdict rules, requirement groups, review of C2's verdict
  summary.py      summary written from data
  report.py       HuntReport; JSON, Markdown, HTML, PDF
  cli.py          report, from-run, export-schemas
  templates/      report.md.j2, report.html.j2
  schemas/        JSON Schemas
  esclient.py     read-only Elasticsearch REST client (standard library)
  injection.py    finds text in logs that gives instructions to an AI
  util.py         UTC helpers, Markdown escaping
  requirements.txt
  dev/            docker-compose.dev.yml, load_sample_data.py (sample logs into a dev Elasticsearch)
tests/group_C/c3/        tests, fixtures, mock Elasticsearch / MCP, C2's real sample runs (c2_runs/), tamper cases
docs/contracts/c3_hunt_bundle.md      contract with C1 and C2
docs/group_C/c3_data_flow.html        data-flow diagrams
docs/group_C/sample_reports/          reports on the simulated hunts
docs/group_C/sample_reports_c2_runs/    reports on C2's real runs, untouched and tampered
```

## 5. Step by step

### Step 0: repository and branch

```bash
git clone <team-repo-URL>.git && cd <repo-name>
git checkout main && git pull
git checkout -b feature/c3-evidence-report
```

Copy the package into the repo root. Merge `group_C/`, `tests/` and `docs/`, and do not overwrite other members' files. The
root `.gitignore` must contain `.env`, `.venv/`, `__pycache__/` and `*.pyc`. Never commit `.env`, API keys, tokens or real logs.

### Step 1: run all tests

```powershell
python -m pytest tests -q
```
Without pytest, use `python -m unittest discover -s tests -t .`. All 77 tests should pass. The MCP tests are skipped if
`mcp` is not installed, and the PDF test is skipped if neither WeasyPrint nor Playwright is available.

### Step 2: T33, bring the contract to the M03 meeting

Show C1 and C2 the file `docs/contracts/c3_hunt_bundle.md` and the open points at its end (section 7 below).

### Step 3: T34, a report from C2's real run (offline first)

```powershell
python -m group_C.threat_hunting.evidence.cli from-run `
  --plan tests/group_C/c3/c2_runs/runs/share-lsass-lateral/plan.json `
  --result tests/group_C/c3/c2_runs/runs/share-lsass-lateral/result.json `
  --audit tests/group_C/c3/c2_runs/audit/share-lsass-lateral.jsonl --out hunt_bundle.json
python -m group_C.threat_hunting.evidence.cli report --bundle hunt_bundle.json --out-dir group_C/experiments/reports --formats json,md,html,pdf
```
Offline mode checks nothing again, so the verdict is always Inconclusive. Use it to preview the layout.

### Step 4: T35, live verification against Elasticsearch

```powershell
docker compose -f group_C/threat_hunting/evidence/dev/docker-compose.dev.yml up -d elasticsearch
python group_C/threat_hunting/evidence/dev/load_sample_data.py --reset
python -m group_C.threat_hunting.evidence.cli report --bundle tests/group_C/c3/fixtures/hunt_bundle_confirmed.json --verify es --out-dir group_C/experiments/reports
start group_C\experiments\reports\hunt_report_hunt-lsass-001.html
```
The result should be Confirmed (high), with 7 claims verified, 1 unsupported, 2 contradicted and replay 10/10 identical. Wait about
a minute after `up -d` and check `curl http://localhost:9200`. The live path has only been tested against a mock Elasticsearch
and a mock MCP server. If it fails on a real one, send the output.

### Step 5: T36, prove the safeguards

`python -m tests.group_C.c3.make_reports` rewrites the sample reports. Open
`docs/group_C/sample_reports_c2_runs/tampered/` and check that each planted error is caught (section 6).

### Step 6: integrate with C1 (MCP server)

1. Copy the lines you need from `group_C/threat_hunting/evidence/.env.example` into the root `.env` file (never commit it) and set `C3_MCP_COMMAND`, `C3_MCP_ARGS` and `C3_MCP_CWD`. `C3_MCP_CWD` is the folder the server starts from. Until C1 delivers its own server, the default starts C2's stand-in, `-m dev.es_mcp_standin.server`.
2. If C2's analytics server must also be reachable (`check_ioc`), set `C3_MCP_ANALYTICS_COMMAND` and `C3_MCP_ANALYTICS_ARGS`.
3. Run `cli report --bundle <file> --verify mcp`. C3 uses its own connection, so its calls go to their own audit file (`<run>-verify`).

### Step 7: integrate with C2 (agent)

C2 already writes `runs/<id>/` and `audit/<id>.jsonl`, and C3 reads them with `from-run`. C2 can also build a `HuntBundle`
directly (see the snippet in `evidence/README.md`). Agree the open points in section 7.

### Step 8: first end-to-end hunt (M07) and guardrail review (M08)

1. Run C2's hunt on the agreed datasets with Group A/B's index names.
2. Generate the report with `--verify es` or `--verify mcp`. Check that every finding shows a query, an index, a time window and an event you can open.
3. With the QA reviewer, go through the failure cases: missing host, data gap, malformed log, oversized event, log text containing instructions, and an unsupported claim. Keep those reports as evidence for the M08 sign-off.

### Step 9: commit and pull request

Use one commit per task so the history stays readable. For example: `C3: add hunt-bundle contract and schemas (T33)`,
`C3: add claim verifier and read-only gateways (T35)`, `C3: add verdict rules and C2 verdict review (T36)`,
`C3: add JSON/Markdown/HTML/PDF report and CLI (T34)`. Push the branch, open a PR into `main`, and ask C4, C1 or C2 to review it. The
description should list T33 to T36, how to run the tests, and the open points.

### Step 10: report, demo and pitch

The report section on agentic workflow design is not written yet. Write it with numbers from real runs once the team datasets are
available. Rehearse the guardrail demo with the tampered reports, and log your hours in the Team Assignments sheet.

## 6. Planted-error demo (answer to "what if the AI makes something up?")

C2's two real runs (`tests/group_C/c3/c2_runs/`) are clean. `tests/group_C/c3/tamper.py` copies them and plants one error in each copy:

| Case | Planted error | C3 result |
|---|---|---|
| `inflated_count` | "50 failed logins" (data: 30) | contradicted, verdict Inconclusive |
| `wrong_user` | login "as root" (event: admin) | contradicted, verdict Inconclusive |
| `invented_host` | login "on WS-09" (event: WS-02) | contradicted (host in no evidence) |
| `invented_user` | login "as svc_backup" (event: admin) | contradicted (account in no evidence) |
| `fake_event_id` | cites an event that does not exist | unsupported, verdict Inconclusive |
| `invented_claim` | "copied /etc/shadow", no evidence | unsupported |
| `forged_aggregate` | "40 error responses" (replay: 27) | contradicted by replay |
| `unknown_ioc` | an IP the threat-intel feed does not list | contradicted by replay |
| `invented_narrative` | C2's verdict reasons name an IP and a host in no evidence | claims stay verified; flag + analyst review |
| `two_indicators_wrong` | 2 of 3 LSASS indicators wrong | contradicted; below `min_support`, so Inconclusive |

On the untouched runs all claims are verified and all queries replay identically. C3 agrees with C2 on Confirmed (high), with
review outcome `agrees`. The log store in these tests is a recording of the run and not a live Elasticsearch (see
`tests/group_C/c3/c2_runs/README.md`).

## 7. Points to agree with C1 and C2

1. Settled by C2 (PR #22): `result.json` schema 0.2 is binding (INTERFACES §4.1).
2. Confidence `high` follows DESIGN §4.1 (supported, fully covered, at least two independent verified steps), as agreed with C2. Write the rule into INTERFACES. `C3_MIN_LOG_SOURCES=2` gives a stricter rule.
3. Settled: run-time steps are listed in `result.json` `dynamic_steps`.
4. Settled: analytics-server calls are audited in `audit/<run_id>-analytics.jsonl`.
5. Still open: `min_support` per technique (already in `result.json`), final index names, the MCP SDK version, and the tool names C3 calls (`get_event`, `search`, `aggregate`).
6. The hash formula `result_hash = sha256(json.dumps([sorted(ids), total]))[:16]` must not change. If it does, every replay looks like a mismatch.

## 8. Evidence checklist for the spreadsheet

| Task | Paste in the "Notes / Repo Link" column |
|---|---|
| T33 | PR link, `docs/contracts/c3_hunt_bundle.md`, `schemas/` |
| T34 | Reports (`.md`, `.html`, `.pdf`, `.json`) from a real run |
| T35 | Test output, a report with rejected claims, a `--verify es` report |
| T36 | Coverage table, the rejected-claims and flags sections, limitations, and the tampered reports |
| Demo | `sample_reports_c2_runs/tampered/` |

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: group_C` | Run commands from the repo root and check that `group_C/__init__.py` exists |
| `Elasticsearch unreachable` | Run `docker compose ... ps`, wait for the healthy status, and check `ES_URL` |
| ES container exits on Linux | `sudo sysctl -w vm.max_map_count=262144` |
| ES out of memory in Docker | Give Docker Desktop at least 4 GB |
| Fixture test reports "stale" | `python -m tests.group_C.c3.fixture_builder` |
| Schema test reports "stale" | `python -m group_C.threat_hunting.evidence.cli export-schemas` |
| Everything is "not re-verified" | You are in offline mode. Use `--verify es` or `--verify mcp` |
| Replay shows mismatches although the data is the same | C1 must return the full `_source` and keep the `result_hash` formula |
| `PDF not written` | `pip install weasyprint`, or `pip install playwright` then `playwright install chromium` |
| Analytics calls "could not be replayed" | Plain Elasticsearch cannot replay them. Use `--verify mcp` with the analytics server configured |
