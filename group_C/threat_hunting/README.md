# C2 — Threat-Hunting Agent

Takes a plain-language hypothesis and hunts for it in Elasticsearch **only through MCP tools**. Vetted playbooks run first. Then an LLM investigator follows leads with its own queries, a skeptic tests innocent explanations, and a responder drafts detection rules and response proposals. Data no playbook knows is matched to a known kind or hunted in draft mode, and what the agent finds there can be promoted into a new playbook. **The LLM proposes; code checks every proposal, computes every number and keeps the verdict rule-based** (`SUPPORTED`, `NOT_SUPPORTED`, `INCONCLUSIVE` or `INSUFFICIENT_DATA`). Every claim is tied to event IDs and to the query that found them; findings from LLM-proposed queries are *leads* that never decide the verdict. Design: [DESIGN.md](DESIGN.md) (agentic workflow §3.2–3.7, accepted risks §8.1). Contracts with other members: [INTERFACES.md](INTERFACES.md).

## Layout

| Path | What |
|---|---|
| `threat_hunting/` | The agent (an MCP client): `planner` (intake, window, new sources), `playbooks`, `hunter`, `agent` (investigator loop), `skeptic`, `act` (drafts), `promote`, `hunt_queue`, `feedback` (analyst memory), `verdict`, `selfcheck`, `guardrails`, `query` (filter → DSL compiler), `llm`, `mcp_client`, `run` |
| `analytics_server/` | C2's MCP server: `gap_check`, `lookup_attack`, `check_ioc` (pure functions, no ES credentials) |
| `hunt_server/` | C2 as an MCP server: `run_hunt`, `get_hunt`, `list_hunts`, `follow_up` (for Claude Code, Claude Desktop or other agents) |
| `es_mcp_server/` | C1's maintained Elasticsearch MCP server; [install, configure and validate](es_mcp_server/README.md) |
| `dev/es_mcp_standin/` | The read-only ES MCP server C1's was promoted from; still the default command until C1 switches it |
| `dev/b1_pipelines/` | B1's pipelines vendored from PR #12 (`fee53b1`) + `windows_ext.json` (request R3a) |
| `dev/setup_test_es.py`, `dev/index_template.json` | Isolated test setup (`c2test-*` pipelines, `security-events-c2test` and `security-events-c2test-new` indices, read-only key) |
| `scenarios/generate.py` | Deterministic synthetic data with planted attacks and ground truth, plus a VPN and a DNS source no playbook names |
| `tests/` | Offline unit tests with a scripted LLM, end-to-end hunts (`-m es`), live LLM hunts (`-m llm`, opt-in) |

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

Each run writes `runs/<run_id>/{plan.json,result.json,trace.jsonl,llm.jsonl}`, `runs/<run_id>/actions/` (detection drafts, response proposals) and `runs/<run_id>/candidates/` (candidate playbooks), plus `audit/<run_id>.jsonl` (ES server) and `audit/<run_id>-analytics.jsonl` (analytics server). `result.json` is the contract with C3 (INTERFACES.md §4.1): verdict with review reasons and leads, claims, evidence, findings, every query, the agent's steps, the skeptic's tests and the drafts. Use `python -m dev.setup_test_es --teardown` to remove the test artifacts.

### Agent mode

Put the LLM settings in `.env` (names in `.env.example`; any Anthropic or OpenAI-compatible model). Without them, or with `HUNT_FORCE_RULES=1`, every hunt is the rules-only hunt.

```bash
python -m threat_hunting.llm
```

```bash
python -m threat_hunting.run "An external IP brute-forced SSH and then logged in successfully on 2026-10-01." --run-id agent-ssh
```

Switch parts of the agent off for experiments with `--control agent_loop=off`, `skeptic=off`, `act=off` or `deterministic_sampling=off`.

Promote what the agent found on data no playbook covers (DESIGN §5.5):

```bash
python -m threat_hunting.promote runs/<run_id>/candidates/<technique>.yml --benign-from 2026-10-01T08:00:00Z --benign-to 2026-10-01T13:00:00Z --approved-by "<name>" --keywords "tunnel"
```

Let the agent propose hunts, then run the ones you approve (DESIGN §3.5):

```bash
python -m threat_hunting.hunt_queue propose --max 5
```

```bash
python -m threat_hunting.hunt_queue run queue/<queue_id>.json --approve 1,2
```

Record an analyst lesson for later hunts (DESIGN §3.6):

```bash
python -m threat_hunting.feedback add --run <run_id> --claim C-001 --label benign --note "IT's vulnerability scanner" --analyst "<name>"
```

Use C2 from Claude Code over MCP (DESIGN §3.7):

```bash
claude mcp add c2-hunt -- python -m hunt_server.server
```

Live LLM tests (API calls, a few minutes):

```bash
HUNT_LIVE_LLM=1 python -m pytest -q -m llm
```

To use C1's server instead of the stand-in, set `HUNT_ES_MCP_CMD=python -m es_mcp_server.server` (see [C1 setup and tests](es_mcp_server/README.md)); the stand-in remains the default. Either server must offer the tools in INTERFACES.md §1.2: the agent refuses to start if a required tool or parameter is missing, and never routes tools outside its allowlist. To run the four reference hunts against team data, follow [RUN_HUNTS.md](RUN_HUNTS.md). Without an LLM configured, every role uses its rules; `HUNT_FORCE_RULES=1` forces that.

## Test results (2026-10-25, team stack Elastic 8.19.23 over HTTPS, 15,190 synthetic events through B1's pipelines + 1,361 in the new-source index; 121 tests)

Rules mode (no LLM; the same verdicts are reached with the agent on, because leads never decide):

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

| VPN log no playbook names (new index) | `SUPPORTED`, high | Matched to auth by its ECS fields; generic auth steps find the 40 failures and the login as jdoe |
| DNS tunnelling, no playbook (new index, scripted LLM) | `INCONCLUSIVE` → promoted → `SUPPORTED` | Draft-mode lead on `exfil-tunnel.net`; the candidate passes the attack and benign replays; the rerun is vetted |

A prompt-injection string planted in a web user agent changes no claim and no verdict. The injection sweep reports it as a finding with its event id, so every hunt over that day requires analyst review, and the event is withheld from every LLM prompt. Confidence and review follow INTERFACES.md §4.3.

Agent mode, live (DeepSeek `deepseek-flash`, temperature 0; `pytest -m llm` passes). The agent's path differs between runs; verdicts and every number come from rules:

| Hunt | Verdict | What the agent added |
|---|---|---|
| LSASS dump + lateral movement (c2test) | `SUPPORTED`, high | 10 investigator queries, 4 leads, 6 benign explanations tested and ruled out, 7 Sigma drafts (all replayed), 5 response proposals; 21 LLM calls, about 150 k tokens, 5 min. C3: 18/18 claims verified, 71/71 replays identical, agrees |
| SSH brute force + login (c2test) | `SUPPORTED`, high | 10 queries, 3 leads, 4 skeptic tests all ruled out, 4 drafts, 5 proposals; 16 calls, about 75 k tokens, 2.7 min |
| VPN brute force, new source (c2test-new) | `SUPPORTED`, high | VPN log matched to auth by the classifier and checked by code; 10 queries, 2 leads, 4 benign explanations ruled out (e.g. "all failures target one account": 17 were against `admin`); 22 calls, about 90 k tokens, 3.6 min |
| DNS tunnelling, no playbook (c2test-new) | `INCONCLUSIVE`, low | Draft mode: the investigator found `exfil-tunnel.net` from WS-03 (4 leads) and wrote a candidate playbook; 16 calls, 1.5 min. C3: 4/4 verified, 24/24 replays identical, agrees |
| Team stack, attack case (C1's server) | `SUPPORTED`, medium | A skeptic test held, which capped confidence; it only re-counted the finding, which led to the `not_discriminating` rule (DESIGN §3.3) |
| Team stack, benign case (C1's server) | `INCONCLUSIVE`, low | The investigator recorded 3 failed logins and a success from 198.51.100.20 as leads; leads block a refutation (by design: a missed attack costs more than a review) |

C3 (PR #23 at `5d8ced3`) re-verifies agent runs over MCP like any other: leads are verified like every claim and, as in C2, never decide the verdict. Across the live runs, investigator rejections fell from up to half of the turns to none after the validator learned the parameter names models use (`dataset`, `filter`, `limit`, `group_by`, `time_range`) and started running valid queries whose claim spec was wrong.

## Findings for other members
- **C1:** when `get_mapping` fails, for example with a key that has `read` but not `view_index_metadata` (INTERFACES.md §3.2), `es_mcp_server` silently uses an empty mapping. `ip` fields are then queried with `case_insensitive` term queries, which match nothing, so hunts silently find nothing and a benign-looking result can be wrong. C2 now refuses to refute in that case (every technique gets a coverage gap), but the server should fail loudly. Seen on the team stack with the B3 read key.
- **B1 (R3a):** the `windows-json` pipeline sets no `@timestamp`, so Windows events are invisible to any time-bounded hunt. It also leaves the Sysmon fields the playbooks need (`CommandLine`, `ParentImage`, `SourceImage`, `TargetImage`, `GrantedAccess`, `TargetFilename`) unmapped. `dev/b1_pipelines/windows_ext.json` is a tested proposal.
- **B1 / A3:** the firewall dataset is called `firewall` (B1) vs `firewall.log` (A3). The agent accepts both for now.
- **B1 / A1:** without an index template, IPs are mapped as text/keyword. CIDR filters then fail loudly (by design), so internal-range exclusions won't work. `dev/index_template.json` is the proposed typing.
- **Firewall format:** with no ports or bytes, beaconing is counted per destination, host scanning uses distinct internal destinations, and exfiltration can't be tested.
