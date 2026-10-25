# C2 — Threat-Hunting Agent

Takes a plain-language hypothesis, plans a hunt from vetted playbooks, queries Elasticsearch **only through MCP tools**, and returns a rule-based verdict (`SUPPORTED`, `NOT_SUPPORTED`, `INCONCLUSIVE` or `INSUFFICIENT_DATA`). Every claim is tied to event IDs and to the query that found them. Design: [DESIGN.md](DESIGN.md). Contracts with other members: [INTERFACES.md](INTERFACES.md).

## Layout

| Path | What |
|---|---|
| `threat_hunting/` | The agent (an MCP client): `planner`, `playbooks`, `hunter`, `verdict`, `selfcheck`, `query` (filter → DSL compiler), `llm`, `mcp_client`, `run` |
| `analytics_server/` | C2's MCP server: `gap_check`, `lookup_attack`, `check_ioc` (pure functions, no ES credentials) |
| `es_mcp_server/` | C1's maintained Elasticsearch MCP server; [install, configure and validate](es_mcp_server/README.md) |
| `dev/es_mcp_standin/` | The read-only ES MCP server C1's was promoted from; still the default command until C1 switches it |
| `dev/b1_pipelines/` | B1's pipelines vendored from PR #12 (`fee53b1`) + `windows_ext.json` (request R3a) |
| `dev/setup_test_es.py`, `dev/index_template.json` | Isolated test setup (`c2test-*` pipelines, `security-events-c2test` index, read-only key) |
| `scenarios/generate.py` | Deterministic synthetic data with planted attacks and ground truth |
| `tests/` | Offline unit tests + end-to-end hunts (`-m es`) |

## Run

Python 3.11+ with `requirements.txt`.

```bash
python -m pytest -q -m "not es"
```

```bash
ES_ADMIN_URL=http://127.0.0.1:9200 ES_ADMIN_PASSWORD=... python -m dev.setup_test_es
```

```bash
python -m pytest -q
```

```bash
python -m threat_hunting.run "An attacker on WS-01 dumped credentials from LSASS and then moved laterally to other hosts on 2026-10-01."
```

Each run writes `runs/<run_id>/{plan.json,result.json,trace.jsonl}` plus `audit/<run_id>.jsonl` (ES server) and `audit/<run_id>-analytics.jsonl` (analytics server). `result.json` is the contract with C3 (INTERFACES.md §4.1): verdict with review reasons, claims, evidence, findings, every query and the steps created at run time. Use `python -m dev.setup_test_es --teardown` to remove the test artifacts.

To use C1's server instead of the stand-in, set `HUNT_ES_MCP_CMD=python -m es_mcp_server.server` (see [C1 setup and tests](es_mcp_server/README.md)); the stand-in remains the default. Either server must offer the tools in INTERFACES.md §1.2: the agent refuses to start if a required tool or parameter is missing, and never routes tools outside its allowlist. To run the four reference hunts against team data, follow [RUN_HUNTS.md](RUN_HUNTS.md). Without an LLM configured, the planner uses its rules; `HUNT_FORCE_RULES=1` forces that.

## Test results (2026-10-25, Elastic 8.17 single node, 15,190 synthetic events through B1's pipelines; 53 tests)

| Hypothesis | Verdict | Notes |
|---|---|---|
| LSASS dump on WS-01, then lateral movement | `SUPPORTED`, high | 14/14 claims self-checked; cites exactly the 50 ground-truth events (12/12 items, recall and precision 1.0); decoys not reported |
| External IP brute-forced SSH, then logged in | `SUPPORTED`, high | 31/31 ground-truth events, recall and precision 1.0 |
| Brute force on DC-01 (none planted) | `NOT_SUPPORTED`, medium | Full coverage, no indicators; still flagged for review because the window contains injection text |
| Host HR-LAPTOP-99 (doesn't exist) | `INCONCLUSIVE` | Named entity has no telemetry |
| Exfiltration over 100 MB | `INSUFFICIENT_DATA` | The firewall log has no `network.bytes` |
| Empty window (2030) | `INSUFFICIENT_DATA` | No events in the window |
| Primary hunt with a 6-call budget | `INCONCLUSIVE` | Budget exhaustion is reported |
| Primary hunt run twice | identical | Same requests (hashes), evidence and claim texts |

A prompt-injection string planted in a web user agent changes no claim and no verdict (the LLM never sees log text). The injection sweep reports it as a finding with its event id, so every hunt over that day requires analyst review. Confidence and review follow INTERFACES.md §4.3.

## Findings for other members
- **B1 (R3a):** the `windows-json` pipeline sets no `@timestamp`, so Windows events are invisible to any time-bounded hunt. It also leaves the Sysmon fields the playbooks need (`CommandLine`, `ParentImage`, `SourceImage`, `TargetImage`, `GrantedAccess`, `TargetFilename`) unmapped. `dev/b1_pipelines/windows_ext.json` is a tested proposal.
- **B1 / A3:** the firewall dataset is called `firewall` (B1) vs `firewall.log` (A3). The agent accepts both for now.
- **B1 / A1:** without an index template, IPs are mapped as text/keyword. CIDR filters then fail loudly (by design), so internal-range exclusions won't work. `dev/index_template.json` is the proposed typing.
- **Firewall format:** with no ports or bytes, beaconing is counted per destination, host scanning uses distinct internal destinations, and exfiltration can't be tested.
