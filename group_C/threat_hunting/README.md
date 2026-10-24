# C2 — Threat-Hunting Agent

Takes a plain-language hypothesis, plans a hunt from vetted playbooks, queries Elasticsearch **only through MCP tools**, and returns a rule-based verdict (`SUPPORTED`, `NOT_SUPPORTED`, `INCONCLUSIVE` or `INSUFFICIENT_DATA`). Every claim is tied to event IDs and to the query that found them. Design: [DESIGN.md](DESIGN.md). Contracts with other members: [INTERFACES.md](INTERFACES.md).

**Origin.** This is a port of the C2 parts of the author's (Vu Tuan Dat) earlier prototype, `vtdat/se6014-agentic-threat-hunting@d1956af` (private). The port is adapted to the team's `security-events-*` index, `event.dataset` and B1's ingest pipelines. The prototype's ingestion, verifier, reporter and experiments are **not** included; they belong to Group B, C3 and C4.

## Layout

| Path | What |
|---|---|
| `threat_hunting/` | The agent (an MCP client): `planner`, `playbooks`, `hunter`, `verdict`, `selfcheck`, `query` (filter → DSL compiler), `llm`, `mcp_client`, `run` |
| `analytics_server/` | C2's MCP server: `gap_check`, `lookup_attack`, `check_ioc` (pure functions, no ES credentials) |
| `dev/es_mcp_standin/` | **Temporary** read-only ES MCP server standing in for C1's |
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

Each run writes `runs/<run_id>/{plan.json,result.json,trace.jsonl}`. Use `python -m dev.setup_test_es --teardown` to remove the test artifacts.

To use C1's server instead of the stand-in, set `HUNT_ES_MCP_CMD` (it must offer the tools in INTERFACES.md §1.2). Without an LLM configured, the planner uses its rules; `HUNT_FORCE_RULES=1` forces that.

## Test results (2026-10-24, Elastic 8.17 single node, 15,190 synthetic events through B1's pipelines)

| Hypothesis | Verdict | Notes |
|---|---|---|
| LSASS dump on WS-01, then lateral movement | `SUPPORTED`, high | 14/14 claims self-checked; cites exactly the 50 ground-truth events (12/12 items, recall and precision 1.0); decoys not reported |
| External IP brute-forced SSH, then logged in | `SUPPORTED`, high | 31/31 ground-truth events, recall and precision 1.0 |
| Brute force on DC-01 (none planted) | `NOT_SUPPORTED`, medium | Full coverage, no indicators |
| Host HR-LAPTOP-99 (doesn't exist) | `INCONCLUSIVE` | Named entity has no telemetry |
| Exfiltration over 100 MB | `INSUFFICIENT_DATA` | The firewall log has no `network.bytes` |
| Empty window (2030) | `INSUFFICIENT_DATA` | No events in the window |
| Primary hunt with a 6-call budget | `INCONCLUSIVE` | Budget exhaustion is reported |
| Primary hunt run twice | identical | Same requests (hashes), evidence and claim texts |

A prompt-injection string planted in a web user agent changes no claim and no verdict.

## Findings for other members
- **B1 (R3a):** the `windows-json` pipeline sets no `@timestamp`, so Windows events are invisible to any time-bounded hunt. It also leaves the Sysmon fields the playbooks need (`CommandLine`, `ParentImage`, `SourceImage`, `TargetImage`, `GrantedAccess`, `TargetFilename`) unmapped. `dev/b1_pipelines/windows_ext.json` is a tested proposal.
- **B1 / A3:** the firewall dataset is called `firewall` (B1) vs `firewall.log` (A3). The agent accepts both for now.
- **B1 / A1:** without an index template, IPs are mapped as text/keyword. CIDR filters then fail loudly (by design), so internal-range exclusions won't work. `dev/index_template.json` is the proposed typing.
- **Firewall format:** with no ports or bytes, beaconing is counted per destination, host scanning uses distinct internal destinations, and exfiltration can't be tested.
