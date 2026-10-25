# C2 — Interface Contracts and Requests to Other Members (Draft v0.5)

| | |
|---|---|
| **Owner** | Vu Tuan Dat (C2) |
| **Status** | **Proposal.** Please comment on the PR or propose changes; nothing here is final until agreed |
| **Companion** | [DESIGN.md](DESIGN.md) |
| **Changes in v0.5** | C1 delivered `es_mcp_server/` (promoted from the stand-in): §1.2 and §1.4 now describe both servers; §4.2 states the fact rule C2 and C3 share; R1 delivered; [RUN_HUNTS.md](RUN_HUNTS.md) gives the Group C commands for the four reference hunts |
| **Changes in v0.4** | Settles the conflicts from C3's review: §4.1 now documents the real `result.json` (binding for C3), with `queries[]`, `dynamic_steps`, `findings` and `review_reasons`; new §4.3 is the single source of truth for confidence and analyst review; §1.1 tool allowlist, §1.4 limits, §1.5 structured filters, §5 CLI and controls all match the code; `logs-*` examples replaced by `security-events-*` |
| **Changes in v0.3** | Synced with the working port (`threat_hunting/`): §1.2 lists the tools the agent actually calls (implemented by the C1 stand-in `dev/es_mcp_standin/`); §1.6 marks what the analytics server implements; §2.1 follows Group B's `security-events-*` + `event.dataset` convention; new request **R3a** to B1 |
| **Changes in v0.2** | C2-owned contracts only: hunt-analytics MCP server (§1.6); coverage matrix and decision-risk fields in `HuntResult` (§4.1); profiles, switchable controls and new CLI flags for C4 (§5). No new requests to other members |

This document lists **what the threat-hunting agent (C2) needs from each member**, in a concrete form, and the **cross-cutting considerations** that affect all of our implementations. Until each item is delivered, C2 uses the stand-in shown, so nobody is blocked.

---

## 0. Summary of Requests

| # | From | Request | Priority | Needed by | C2 stand-in until then |
|---|---|---|---|---|---|
| R1 | **C1** | MCP tool set + response/error envelope (§1) | High | M4 | **Delivered** as `es_mcp_server/` (tools §1.2); the target envelope §1.3 is still open. Stand-in `dev/es_mcp_standin/` remains the default command |
| R2 | **C1** | Server-side query safety limits (§1.4) | High | M4 | Same limits enforced in C2's compiler |
| R3 | **Group B (B1)** | Dataset names, index naming, per-dataset field list with ES types (§2) | High | M2/M5 | Assumed ECS mapping below |
| R3a | **Group B (B1)** | `windows-json` pipeline: set `@timestamp` from `EventTime`/`UtcTime` (today **no** Windows event gets one, so time-bounded hunts never see them) and map `CommandLine`, `ParentImage`, `SourceImage`, `TargetImage`, `GrantedAccess`, `TargetFilename` | High | M5 | `dev/b1_pipelines/windows_ext.json` appended in the test setup |
| R4 | **Group B (B1/B2)** | Parse-failure marking + custom-field namespace (§2.3) | Medium | M5 | Synthetic data has no failures |
| R5 | **Group A (A1)** | ES/Kibana version, endpoint, CA cert, read-only API key for C1 (§3) | High | M4 | Own single-node ES in Docker |
| R6 | **Group A (A2/A3)** | Deterministic `_id`s, timestamp policy for replays, frozen snapshot for experiments (§3) | High | M6 | Own generator with fixed `_id`s |
| R7 | **Group A (A3)** | Ability to replay C2's attack scenarios through the real pipeline (§3) | Medium | M5 | Bulk-load directly into local ES |
| R8 | **C3** | Agree on the `HuntResult` schema and the split of verification work (§4) | High | M3 | C2 self-check only |
| R9 | **C4** | Agree on the CLI and run manifest; which fields must match across runs (§5) | Medium | M6 | — |
| R10 | **Groups B + C** | LLM provider/model decision that meets the requirements in §6 | High | M3 | Provider-agnostic `LLMClient` |
| R11 | **A1 (Repo/CI)** | Branch protection on `main`, `.gitignore` additions, CI for offline tests (§7.6) | Medium | M1 | — |

---

## 1. C1 — MCP Server Tool Contract (R1, R2)

### 1.1 Transport and trust
- **Transport:** stdio for local development; Streamable HTTP for the shared deployment.
- **Credentials:** the MCP server holds the ES credentials. **The agent never sees them.** The agent passes ES settings only to the ES server; the analytics server gets none.
- **Tool allowlist (threat T7):** at start-up the agent routes only the tools it uses (`describe_data`, `search`, `count`, `aggregate` on the ES server; `gap_check`, `lookup_attack`, `check_ioc` on the analytics server) and checks that each one declares the parameters it relies on. A missing tool or parameter, or one tool name offered by two servers, stops the run. Any other tool a server offers is never routed and is listed in `manifest.ignored_tools`. Allowlist: `ALLOWED` in `threat_hunting/mcp_client.py`.

### 1.2 Tools the agent calls (implemented by C1's `es_mcp_server/` and by the stand-in `dev/es_mcp_standin/`)

Filters use a structured language, never raw DSL: `{field, op, value}` with `op` in `eq|neq|in|wildcard|prefix|contains|gte|lte|gt|lt|exists`; `filters` are ANDed, `must_not` excluded, `any_of` needs one match. The server compiles them with `threat_hunting/query.py` (index allowlist `security-events-*`, mandatory time range, size cap 200, no scripts, CIDR only on `ip` fields).

| Tool | Parameters | Returns |
|---|---|---|
| `describe_data` | `index_pattern = "security-events-*"` | `{sources: [{dataset, docs, first_event, last_event}], fields: ["name:type", ...]}` |
| `search` | `index, time_from, time_to, filters?, must_not?, any_of?, fields?, size ≤ 200, sort` | `{total, returned, truncated, hits: [{index, event_id, fields}], dsl}` |
| `count` | `index, time_from, time_to, filters?, must_not?, any_of?` | `{total, dsl}` |
| `aggregate` | `index, time_from, time_to, agg (terms, rare_terms, cardinality, stats, sum, max, date_histogram), field?, filters?, …, size, interval, sum_field?, distinct_field?` | `{total, result: [{key, count, sum?, distinct?}] or {value…}, dsl}` |
| `get_event` | `index` (exact), `event_id` | `{event}` including `event.original`. **Used by C3 to verify evidence** |
| `save_finding`, `get_audit_log` | | Audit helpers |

`time_from`/`time_to` are **mandatory** and become a `range` filter on `@timestamp`, so a query without a time bound is impossible. C1's server offers exactly these names and shapes; select it with `HUNT_ES_MCP_CMD=python -m es_mcp_server.server` (the stand-in stays the default until C1 says otherwise). (The v0.2 proposal of `list_indices` / `get_field_mapping` / raw-DSL `search` is superseded by this list.)

### 1.3 Response envelope (all tools)

*Today the stand-in returns `{call_id, tool, dsl, total, …}` or `{call_id, tool, error}`. The agent records every call in `runs/<id>/trace.jsonl` with the arguments, the returned `dsl` and its own `request_hash` (sha256 of tool + canonical arguments), and copies that list into `result.json` `queries[]` (§4.1). The envelope below remains the target for C1.*

```json
{
  "ok": true,
  "tool": "aggregate",
  "request": { "index": "security-events-2026.10.01", "body": { "...canonical ES request actually sent..." } },
  "request_hash": "sha256:9f2c...",
  "es": { "took_ms": 14, "timed_out": false, "total": 4182, "total_relation": "eq" },
  "truncated": false,
  "result": { "...tool-specific..." },
  "warnings": []
}
```

```json
{
  "ok": false,
  "tool": "search",
  "error": {
    "code": "FIELD_NOT_FOUND",
    "message": "Field 'src_ip' not in mapping for security-events-2026.10.01",
    "retryable": false
  }
}
```

**Error codes** (lets the agent recover automatically instead of guessing):
`INDEX_NOT_ALLOWED` · `INDEX_NOT_FOUND` · `FIELD_NOT_FOUND` · `INVALID_QUERY` · `CLAUSE_NOT_ALLOWED` · `LIMIT_EXCEEDED` · `TIMEOUT` · `ES_UNAVAILABLE` · `AUTH_FAILED`

**Why `request` and `request_hash` matter:** C3 must record the exact query behind every finding, and C4 compares queries across runs. If the server echoes the canonical request, all three of us share a single source of truth.

### 1.4 Safety limits (enforced by the query compiler `threat_hunting/query.py` and by both ES servers)
- Index allowlist: patterns starting with `security-events-`. No system indices (`.security*`, `.kibana*`), no `_all`, `*` or `..`.
- Structured filters only (§1.2) compile to `bool`, `term`, `range`, `exists`, `wildcard`, `prefix`, `match_phrase`. **Rejected:** `script`, `script_fields`, `scripted_metric`, `runtime_mappings`, raw DSL.
- **Leading wildcards are allowed** because filters come only from vetted playbooks, never from the LLM: `*\lsass.exe`, `*.dmp`, `*/uploads/*.php`, the SQL-injection patterns, and `contains` on keyword fields (`*value*`). This is fine at course-project volumes; at scale, map `url.original` and `process.command_line` as the `wildcard` field type.
- Caps: search `size ≤ 200`, terms `size ≤ 100`, date-histogram buckets ≤ 1000, request timeout 20 s, mandatory time range ≤ 31 days, no `scroll` or deep pagination.
- CIDR values only on `ip`-typed fields; on any other type the call fails instead of silently matching nothing.
- **Read-only ES API key** for the server (see §3.2).
- Results include only the requested `fields`; `event.original` is dropped from `search` hits and returned only by `get_event`.

### 1.5 Filters vs raw DSL (settled)
Tools take the structured filter language of §1.2, not raw DSL. That keeps queries canonical (hashable for C4), keeps scripts and unbounded queries impossible, and keeps the LLM out of query writing.
> Elastic's official Elasticsearch MCP server takes raw DSL and has no limits or audit; if C1 builds on it, the limits above and the §1.2 tool names still need to be added.

### 1.6 C2's hunt-analytics MCP server (provided by C2, not a request)
The project requires *every* capability the hunt needs to be exposed as MCP tools, so C2 exposes its analytics through a second, small MCP server. Its tools are **pure functions**: they take data the agent already obtained from C1's tools, hold no ES credentials and make no network calls. Each call returns `{call_id, tool, …}` and is written to its own audit file `audit/<run_id>-analytics.jsonl` (params, total, result hash); it also appears in `trace.jsonl` and `queries[]`.

| Tool | Status | Input | Output |
|---|---|---|---|
| `gap_check` | **implemented** | Date-histogram buckets `[{key, count}]` | `n_buckets`, `empty_buckets`, `coverage_ratio` |
| `lookup_attack` | **implemented** | Technique id or keyword | Offline ATT&CK subset entries |
| `check_ioc` | **implemented** | IP or domain | Matches in the local threat-intel list |
| `burst_detect` | planned | Timestamps or histogram per key, threshold, window | Keys exceeding the threshold within any sliding window, with peak counts and times |
| `beacon_score` | planned | Event timestamps per (source, destination) pair | Inter-arrival mean, coefficient of variation, regularity score, event count |
| `rare_values` | planned | Term counts for the hunt window and a baseline window | Values first seen in the hunt window or below a rarity threshold |

C1 is welcome to absorb these tools into the ES MCP server later. The agent routes each tool name to the server that offers it (a name offered twice is refused at start-up), so this would only change config.

---

## 2. Group B — Normalised Data Contract (R3, R4)

### 2.1 Naming
Agreed with Group B (CONTRACTS.md §6): one integrated index pattern **`security-events-*`**, datasets told apart by `event.dataset`. The agent accepts both spellings currently used in the team:

| Log type | `event.dataset` values the agent accepts | Produced by |
|---|---|---|
| Linux auth (sshd, sudo) | `linux.auth` | B1 `linux-auth`, A3 parser |
| Apache / Nginx access | `apache.access`, `nginx.access` | B1 `apache-access`, A3 parser |
| Firewall syslog | `firewall`, `firewall.log` | B1 `firewall-syslog` (`firewall`), A3 parser (`firewall.log`) |
| Windows / Sysmon | `Microsoft-Windows-Sysmon/Operational`, `windows.sysmon` | B1 `windows-json` (copies `Channel`) |
| Experiment snapshot | as above | a frozen `security-events-<name>` index (see §3.3) |

Please converge on one spelling per dataset; until then the alias list lives in `threat_hunting/playbooks.py` (`DATASETS`).

### 2.2 Minimum fields C2 relies on (with required ES types)

| Field | ES type | linux.auth | web access | firewall | Notes |
|---|---|:-:|:-:|:-:|---|
| `@timestamp` | `date` | ✔ | ✔ | ✔ | UTC, ISO 8601 |
| `event.dataset` | `keyword` | ✔ | ✔ | ✔ | |
| `event.category` | `keyword` (array) | `authentication` | `web` | `network` | ECS allowed values only |
| `event.type` | `keyword` (array) | `start` | `access` | `connection` / `allowed` / `denied` | |
| `event.action` | `keyword` | e.g. `ssh_login` | — | e.g. `allow` / `deny` | Agree on the value list |
| `event.outcome` | `keyword` | `success` / `failure` | `success` / `failure` | ✔ | ECS values only: `success`, `failure`, `unknown` |
| `event.original` | `keyword` (`index: false` OK) | ✔ | ✔ | ✔ | Must be preserved for verification |
| `host.name` | `keyword` | ✔ | ✔ | ✔ | |
| `source.ip` | **`ip`** | ✔ | ✔ | ✔ | Must be `ip`, not `keyword` or `text` (needed for CIDR queries) |
| `source.port` | `long` | opt | opt | ✔ | |
| `destination.ip` | **`ip`** | opt | opt | ✔ | |
| `destination.port` | `long` | ✔ (22) | opt | ✔ | |
| `network.transport` | `keyword` | — | — | ✔ | |
| `network.bytes` | `long` | — | — | opt | Beaconing analytics |
| `user.name` | `keyword` | ✔ | opt | — | |
| `process.name` | `keyword` | ✔ (`sshd`) | — | — | |
| `url.original` | `keyword` (+ `wildcard` or text sub-field) | — | ✔ | — | |
| `http.request.method` | `keyword` | — | ✔ | — | |
| `http.response.status_code` | `long` | — | ✔ | — | |
| `user_agent.original` | `keyword` | — | ✔ | — | |
| `log.level` | `keyword` | opt | opt | opt | |

**Mapping requirement:** use explicit ECS mappings in an index template (for example Elastic's `ecs@mappings` component template on recent 8.x versions). Do not rely on dynamic mapping, which tends to map IPs as `text` + `keyword`. A wrong type makes hunt queries **silently return zero hits**, which the agent would then wrongly read as "no attack".

### 2.3 Parse failures and agent-generated schemas (B2)
- Records that fail parsing should **still be indexed** with `tags: ["_parse_failure"]` and `error.message`, and `event.original` kept. C2 will use the failure rate to decide `INSUFFICIENT_DATA` rather than wrongly concluding `NOT_SUPPORTED` (*planned: the agent does not read this tag yet*).
- Fields invented by schema generation must use ECS names where one exists, otherwise a single custom namespace (proposal: `se6014.*`) to avoid mapping explosion and collisions.
- **Notify Group C before any mapping change.** C2's field allowlist comes from live mappings, but playbooks assume the field names listed above.
- **Prompt injection applies to Group B too:** if an LLM parses or classifies raw logs, attacker-controlled log text can manipulate that output. Validate generated schemas and parsed fields deterministically against samples before registering them.

---

## 3. Group A — Infrastructure and Data (R5, R6, R7)

### 3.1 Platform facts needed
- Exact versions of ES, Kibana and Logstash (one version for all three; the Python `elasticsearch` client's major version must match the server's).
- ES endpoint and Kibana base URL (for evidence deep links).
- TLS: Elastic 8.x has security on by default. Share the **CA certificate** through a safe channel (not git).

### 3.2 Read-only API key for C1's MCP server

```http
POST /_security/api_key
{
  "name": "se6014-mcp-readonly",
  "role_descriptors": {
    "hunt_readonly": {
      "indices": [ { "names": ["security-events-*"], "privileges": ["read", "view_index_metadata"] } ]
    }
  }
}
```

### 3.3 Data properties needed for correct and repeatable hunts
- **Deterministic `_id`s** (e.g. a hash of `event.original` + source + offset), so that re-ingesting or replaying the same file does not create duplicates that inflate counts.
- **Timestamp policy for the replayer:** keep original timestamps (preferred for fixed-window hunts) or shift them to "now". If shifted, record the offset.
- **Frozen snapshot for experiments:** a static index (e.g. `security-events-eval`) or an ES snapshot that C4 runs against, so data does not change between the two runs.
- **Scenario replay:** the A3 replayer accepts C2's scenario files (NDJSON + timing) so we can test the full pipeline, from ingestion through parsing to hunting.
- Rough volume estimates per dataset (affects budgets and timeouts).

---

## 4. C3 — `HuntResult` Handoff (R8)

### 4.1 `result.json` (binding for C3)
Every run writes `runs/<run_id>/result.json`. This is the contract; field names are taken from a real run. `schema_version` is `"0.2"`.

| Field | Content |
|---|---|
| `run_id`, `hypothesis` (string), `time_range` `{from, to}` | The hypothesis as given; the window is derived from the data and a date in the hypothesis |
| `verdict` | `{label, confidence, requires_analyst_review, review_reasons[], reasons[]}`. Labels: `SUPPORTED`, `NOT_SUPPORTED`, `INCONCLUSIVE`, `INSUFFICIENT_DATA`. Rules in §4.3 |
| `techniques[]` | Per technique: `technique, name, required, sources, usable_sources, accepted_claims, supporting_steps, min_support, supported, any_signal, covered, gaps` |
| `claims[]` | `claim_id, text, technique, evidence_ids[], facts{}, step_id, kind (events/aggregate/ioc), first_seen, event_ids[] ("<index>/<_id>"), replay{} (for aggregates), context_only, status, verifier_notes`. `status` is `self_checked` or `unsupported` after C2; C3 may set `verified` / `unsupported` / `contradicted` |
| `evidence[]` | `evidence_id, call_id, step_id, index, event_ids[], total_hits, excerpt[]` |
| `findings.prompt_injection` | `{step_id: "guard-injection", checked_fields, markers, call_id, total, findings: [{event_id, @timestamp, dataset, source.ip, host.name, fields, excerpt}]}` |
| `step_results{}` | Per step id (static and dynamic): `{call_id, status (ok/error/skipped_budget), total, tool, complete?, error?}` |
| `dynamic_steps[]` | Full definitions (`step_id, technique, tool, params, purpose, role, claim_template, analysis, must_have`) of steps created at run time: drill-downs `<step>-dd-<key>`, pivots `T1021.002-base/b-<host>`, `T1078-first/b-<ip>`. Static steps are in `plan.json` |
| `queries[]` | **Every MCP call of the run, in order:** `query_id (= call_id), seq, phase (planning/hunt/guardrail), step_id, purpose, server, tool, request, request_hash, dsl, ok, total, error?` |
| `self_check` | `{claims, self_checked, failed: [{claim_id, problems}]}` |
| `coverage` | `{data_sources, coverage: {<log type>: {total, n_buckets, empty_buckets, coverage_ratio}}, gaps, missing_fields, entity_missing}` |
| `limitations[]`, `notes[]` | Plain-text caveats and execution notes (truncation, budget, baseline exclusions) |
| `manifest` | `run_id, backend, planner, code_hash, tool_calls, seconds, python, temperature, controls, perturb_seed, index, mcp_servers, ignored_tools, audit_files` |

Example claim and query (abridged from a real run):
```json
{ "claim_id": "C-002", "technique": "T1078", "status": "self_checked", "kind": "events",
  "text": "Source 203.0.113.99 logged in successfully as admin on WS-02 after its failed SSH logins began (30 failures from this source in the window)",
  "evidence_ids": ["E-T1078-b-203.0.113.99"], "step_id": "T1078-b-203.0.113.99",
  "facts": { "source.ip": "203.0.113.99", "user.name": "admin", "host.name": "WS-02", "failed_logins": "30" },
  "event_ids": ["security-events-c2test/76ea6af0d7a7b6512f7f"], "first_seen": "2026-10-01T14:03:10.000Z" }
{ "query_id": "pytest-ssh-0007", "seq": 10, "phase": "hunt", "step_id": "T1110-a", "purpose": "Sources with many failed SSH logins",
  "server": "es", "tool": "aggregate", "request": { "index": "security-events-c2test*", "agg": "terms", "field": "source.ip", "filters": ["…"] },
  "request_hash": "f5b7df…", "dsl": { "query": { "bool": { "filter": ["…"] } }, "aggs": { "…": "…" } }, "ok": true, "total": 149 }
```

Audit files next to it: `audit/<run_id>.jsonl` (ES server: params, exact DSL, returned ids, result hash) and `audit/<run_id>-analytics.jsonl` (analytics server).
*Not yet in `result.json` (DESIGN target):* `coverage_matrix`, `recommended_next_steps`, `parse_failure_rate`.

### 4.2 Split of anti-hallucination work

| Check | C2 (self-check, before handoff) | C3 (independent verification) |
|---|---|---|
| Every claim cites existing evidence; its event ids come from the cited results | ✔ | ✔ |
| Every fact is a field value of **every** cited event (the only derived fact is `n_connections` = number of cited events); aggregate counts / sums / distinct counts match the cited bucket | ✔ | ✔ |
| IPs and numbers quoted in a claim's text appear in its cited events, bucket or query. **A claim's own facts never count as evidence for its text** | ✔ (claim text only) | ✔ |
| Hosts and users quoted in claims, reasons and notes are in the evidence | — | ✔ |
| Document evidence exists in ES with these field values | — | ✔ via `get_event` |
| Re-executing the query reproduces the result (`queries[].request`) | — | ✔ (optional / sampled) |
| Report rendering (Markdown / HTML / PDF) | — | ✔ |

A claim quotes only what it cites. A value from other evidence (for example the failure count behind a successful-login claim) belongs in the claim that cites that evidence (here the T1110 aggregate claim), not in `facts`.

A technique counts as testable when it has at least one step with role `indicator`, even if that step finds nothing; for T1078 that is `T1078-a` (brute-force candidates), so a hunt with no brute force can be refuted.

### 4.3 Confidence and analyst review (single source of truth for C2 and C3)
Implemented in `threat_hunting/verdict.py`; C3 applies the same rule.

| Confidence | Rule |
|---|---|
| `high` | `SUPPORTED`, **every required technique fully covered** (no gaps), and backed by **at least two independent self-checked steps** in total across the required techniques (DESIGN §4.1). The steps may come from one log source |
| `medium` | Any other `SUPPORTED`, and every `NOT_SUPPORTED` |
| `low` | `INCONCLUSIVE` and `INSUFFICIENT_DATA` |

*C3 option, off by default:* a stricter `high` that also needs events from two log sources. When it is on, C3 states in its report that it lowered the agent's confidence and why.

`requires_analyst_review` is true when any of these holds, each listed in `review_reasons` (DESIGN §4.2): the verdict is `SUPPORTED`; confidence is `low`; there is a coverage gap; the window contains prompt-injection-like text (`findings.prompt_injection`); a claim failed the self-check.

Coverage: a log type has a gap when fewer than **95 %** of its hourly buckets in the window have events (DESIGN §5.4). One empty hour in a 10-hour window is therefore a gap, which blocks `NOT_SUPPORTED`.

---

## 5. C4 — Repeatability Interface (R9)

**CLI entry point (today):**

```bash
python -m threat_hunting.run "An external IP brute-forced SSH and then logged in successfully on 2026-10-01." --run-id run1 --max-calls 120 --control canonical_order=off
```

The window is not a parameter: it runs from the first to the last event in the data, narrowed to a date written in the hypothesis. It is recorded as `time_range` in `result.json`.

| Control (`--control NAME=off`) | What it keeps stable |
|---|---|
| `canonical_order` | Steps run in playbook order |
| `coverage_enforcement` | Every planned step runs (re-added if dropped) |
| `complete_results` | A truncated search is re-asked for every hit (≤ 200) |
| `canonical_params` | Playbook queries cannot be altered by the planner |

`threat_hunting/perturb.py` injects seeded plan variance for experiments (`run_hunt(..., perturb_seed=N)`); it is not an LLM and must not be reported as one. Safety guardrails (read-only access, query limits, tool allowlist, injection sweep, self-check) cannot be switched off.

*Planned (DESIGN §9): `--profile`, `--no-playbook`, `--warmup`, `--replay` and the other four controls (`pin_model`, `deterministic_sampling`, `absolute_window`, `rule_based_verdict`).*

**Suggested experiment (C4 decides):** run with all controls off twice, then enable them one at a time, twice each.

**Run manifest:** `result.json` `manifest` (§4.1).

**Fields that should match across two runs:** `verdict.label`, `verdict.confidence`, `verdict.requires_analyst_review`, the ordered `queries[].request_hash`, the sorted `claims[].event_ids`, claim texts, `coverage`.
**Fields expected to differ:** `run_id`, `call_id`/`query_id`, `seconds`.

---

## 6. Groups B + C — LLM Choice Requirements (R10)

Whichever model is chosen should:
1. Support reliable **tool/function calling** and **structured (JSON-schema) output**.
2. Allow pinning an **exact model version**, temperature 0, and ideally a seed.
3. Have a large enough context window and rate limits for multi-step hunts.
4. Come with acceptable **data-handling terms** for log data sent to it (synthetic or public data only).
5. Have a predictable cost for the experiment budget (C4 runs everything at least twice).

Proposal: B and C share one thin `LLMClient` interface so the provider can be changed in one place.

---

## 7. Cross-Cutting Considerations for All Implementations

1. **Version alignment:** one Elastic Stack version for ES, Kibana and Logstash. The Python client major version matches the server. Python 3.11. Pinned `requirements.txt` per component.
2. **Time:** everything in UTC. Parsers must handle logs without a year or timezone (classic syslog) explicitly and document the assumption.
3. **Silent failure modes to test for:**
   - Wrong field type, so a query returns zero hits
   - A dataset name mismatch, so the wrong index is searched
   - Approximate aggregations (`cardinality` is approximate; `terms` counts can be approximate across shards). Use exact counts where a claim depends on them
4. **Idempotent ingestion:** deterministic `_id`s; replays must not double-count.
5. **Ground truth stays out of the index:** labels for planted attacks live in separate files so no agent can "cheat".
6. **Repo and secrets hygiene (A1):**
   - Enable branch protection on `main` (require PR + 1 approval), since the rule is currently only written in the README
   - Add to `.gitignore`: `*.pem`, `*.key`, `*.crt`, `*.p12`, `certs/`, `*.jks`
   - Note that `*.log` is already ignored, so synthetic datasets should use `.ndjson`
   - Commit a `.env.example` with variable names only
7. **Shared environment variable names (proposal):**

   | Variable | Used by |
   |---|---|
   | `ES_URL`, `ES_API_KEY`, `ES_CA_CERT` | C1 (and C2 local dev only) |
   | `MCP_SERVER_URL` / `MCP_SERVER_CMD` | C2, C3, C4 |
   | `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY` | B, C2 |
   | `KIBANA_URL` | C3 (evidence links) |
8. **Testing without dependencies:** each component should have offline tests using fixtures (no live ES, no LLM) that run in CI, plus a separate integration suite.
9. **Agentic components are attack surface:** B2 (schema generation), B3 (source onboarding) and C2 all feed attacker-influenced text to an LLM. Each needs input sanitisation, constrained outputs, deterministic validation of the LLM's output before it is used, and an audit log.
10. **Evidence for the course:** record each agreed contract change, along with its PR link, in the Technical Work & Evidence Log.
