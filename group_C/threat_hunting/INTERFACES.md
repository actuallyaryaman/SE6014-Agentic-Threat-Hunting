# C2 — Interface Contracts and Requests to Other Members (Draft v0.2)

| | |
|---|---|
| **Owner** | Vu Tuan Dat (C2) |
| **Status** | **Proposal.** Please comment on the PR or propose changes; nothing here is final until agreed |
| **Companion** | [DESIGN.md](DESIGN.md) |
| **Changes in v0.2** | C2-owned contracts only: hunt-analytics MCP server (§1.6); coverage matrix and decision-risk fields in `HuntResult` (§4.1); profiles, switchable controls and new CLI flags for C4 (§5). No new requests to other members |

This document lists **what the threat-hunting agent (C2) needs from each member**, in a concrete form, and the **cross-cutting considerations** that affect all of our implementations. Until each item is delivered, C2 uses the stand-in shown, so nobody is blocked.

---

## 0. Summary of Requests

| # | From | Request | Priority | Needed by | C2 stand-in until then |
|---|---|---|---|---|---|
| R1 | **C1** | MCP tool set + response/error envelope (§1) | High | M4 | `LocalESTools` with the same signatures |
| R2 | **C1** | Server-side query safety limits (§1.4) | High | M4 | Same limits enforced in C2's compiler |
| R3 | **Group B (B1)** | Dataset names, index naming, per-dataset field list with ES types (§2) | High | M2/M5 | Assumed ECS mapping below |
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
- **Credentials:** the MCP server holds the ES credentials. **The agent never sees them.**
- **Server identity:** the agent connects only to the configured URL. It checks the tool list at start-up and refuses unknown tools.

### 1.2 Proposed tools

| Tool | Parameters | Returns |
|---|---|---|
| `list_indices` | `pattern: str = "logs-*"` | `[{index, docs_count, data_stream?}]` |
| `get_field_mapping` | `index: str` | Flattened `{ "source.ip": "ip", "user.name": "keyword", ... }` |
| `get_time_coverage` | `index: str`, `field: str = "@timestamp"` | `{min, max, count}` |
| `count` | `index`, `query` (ES DSL `bool`), `time_range: {gte, lte}` | `{count}` |
| `search` | `index`, `query`, `time_range`, `fields: [str]`, `size ≤ 100`, `sort` | `{total, hits: [{_index, _id, fields}]}` |
| `aggregate` | `index`, `query`, `time_range`, `aggs` (terms / date_histogram / cardinality / stats; ≤ 1 nesting level) | Bucket tree |
| `get_documents` | `index`, `ids: [str] (≤ 100)` | Documents by `_id`. **Used by C3 to verify evidence** |

`time_range` is a **separate, mandatory** parameter. The server adds it to the query as a `range` filter on `@timestamp`, so a query without a time bound is impossible.

### 1.3 Response envelope (all tools)

```json
{
  "ok": true,
  "tool": "aggregate",
  "request": { "index": "logs-linux.auth-default", "body": { "...canonical ES request actually sent..." } },
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
    "message": "Field 'src_ip' not in mapping for logs-linux.auth-default",
    "retryable": false
  }
}
```

**Error codes** (lets the agent recover automatically instead of guessing):
`INDEX_NOT_ALLOWED` · `INDEX_NOT_FOUND` · `FIELD_NOT_FOUND` · `INVALID_QUERY` · `CLAUSE_NOT_ALLOWED` · `LIMIT_EXCEEDED` · `TIMEOUT` · `ES_UNAVAILABLE` · `AUTH_FAILED`

**Why `request` and `request_hash` matter:** C3 must record the exact query behind every finding, and C4 compares queries across runs. If the server echoes the canonical request, all three of us share a single source of truth.

### 1.4 Server-side safety limits (defence in depth; C2 enforces the same limits)
- Index allowlist: `logs-*` (or the agreed pattern). No system indices (`.security*`, `.kibana*`).
- Allowed clauses: `bool`, `term`, `terms`, `range`, `exists`, `match`, `match_phrase`, `prefix`. **Rejected:** `script`, `script_score`, `regexp`, leading-wildcard `wildcard`, `runtime_mappings`.
- Caps: `size ≤ 100`, terms `size ≤ 50`, total buckets ≤ 1000, `timeout: 30s`, no `scroll` or deep pagination in v1.
- **Read-only ES API key** for the server (see §3.2).
- Results include only the requested `fields`; `event.original` is returned only when it is explicitly requested.

### 1.5 Open point for C1
Should tools accept validated ES DSL (this proposal, which keeps tools generic) or only structured filters (simpler to validate)? C2 can work with either: its `QuerySpec` compiles to both.
> Note: Elastic publishes an official Elasticsearch MCP server. C1 could evaluate it as a base, but the envelope, limits and `request_hash` above would still need to be added.

### 1.6 C2's hunt-analytics MCP server (provided by C2, not a request)
The project requires *every* capability the hunt needs to be exposed as MCP tools, so C2 exposes its analytics through a second, small MCP server. Its tools are **pure functions**: they take data the agent already obtained from C1's tools, hold no ES credentials, make no network calls, and use the same response envelope as §1.3 (with `request_hash` over the inputs).

| Tool | Input | Output |
|---|---|---|
| `gap_check` | Date-histogram buckets, interval, hunt window | `time_coverage_ratio`, gap ranges, expected vs observed buckets |
| `burst_detect` | Timestamps or histogram per key, threshold, window | Keys exceeding the threshold within any sliding window, with peak counts and times |
| `beacon_score` | Event timestamps per (source, destination) pair | Inter-arrival mean, coefficient of variation, regularity score, event count |
| `rare_values` | Term counts for the hunt window and a baseline window | Values first seen in the hunt window or below a rarity threshold |

C1 is welcome to absorb these tools into the ES MCP server later. The agent addresses tools as `<server>.<tool>`, so this would only change config.

---

## 2. Group B — Normalised Data Contract (R3, R4)

### 2.1 Naming
Proposal: Elastic data-stream convention `logs-<event.dataset>-<namespace>`:

| Log type | `event.dataset` | Index / data stream |
|---|---|---|
| Linux auth (sshd, sudo) | `linux.auth` | `logs-linux.auth-default` |
| Nginx / Apache access | `nginx.access` / `apache.access` | `logs-nginx.access-default` |
| Firewall / network syslog | `firewall.log` | `logs-firewall.log-default` |
| Experiment snapshot | — | `logs-<dataset>-eval` (frozen; see §3.3) |

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
- Records that fail parsing should **still be indexed** with `tags: ["_parse_failure"]` and `error.message`, and `event.original` kept. C2 uses the failure rate to decide `INSUFFICIENT_DATA` rather than wrongly concluding `NOT_SUPPORTED`.
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
      "indices": [ { "names": ["logs-*"], "privileges": ["read", "view_index_metadata"] } ]
    }
  }
}
```

### 3.3 Data properties needed for correct and repeatable hunts
- **Deterministic `_id`s** (e.g. a hash of `event.original` + source + offset), so that re-ingesting or replaying the same file does not create duplicates that inflate counts.
- **Timestamp policy for the replayer:** keep original timestamps (preferred for fixed-window hunts) or shift them to "now". If shifted, record the offset.
- **Frozen snapshot for experiments:** a static index (e.g. `logs-*-eval`) or an ES snapshot that C4 runs against, so data does not change between the two runs.
- **Scenario replay:** the A3 replayer accepts C2's scenario files (NDJSON + timing) so we can test the full pipeline, from ingestion through parsing to hunting.
- Rough volume estimates per dataset (affects budgets and timeouts).

---

## 4. C3 — `HuntResult` Handoff (R8)

### 4.1 Schema (abridged)

```json
{
  "schema_version": "0.1",
  "run_id": "8d6c1d0e-...",
  "hypothesis": { "text": "External IP brute-forced SSH then logged in", "spec": { "...HuntSpec..." } },
  "verdict": { "label": "SUPPORTED", "confidence": "high", "rationale": "...",
               "requires_analyst_review": true,
               "review_reasons": ["SUPPORTED verdicts always require analyst review"],
               "recommended_next_steps": [
                 { "action": "Reset credentials for 'admin' on web-01", "advisory": true, "evidence": ["E3"] },
                 { "action": "Hunt for post-login activity on web-01 (PB-05)", "advisory": true, "evidence": ["E3"] } ] },
  "claims": [
    { "claim_id": "C1",
      "statement": "203.0.113.7 produced 412 failed SSH logins between 02:10 and 02:31 UTC",
      "evidence": ["A1"], "query_ids": ["Q1"] },
    { "claim_id": "C2",
      "statement": "203.0.113.7 then logged in successfully as 'admin' on web-01",
      "evidence": ["E3"], "query_ids": ["Q3"] }
  ],
  "evidence": [
    { "evidence_id": "E3", "type": "document", "query_id": "Q3",
      "index": "logs-linux.auth-default", "doc_id": "a1b2c3",
      "@timestamp": "2026-10-14T02:33:05Z",
      "fields": { "source.ip": "203.0.113.7", "user.name": "admin", "event.outcome": "success", "host.name": "web-01" } },
    { "evidence_id": "A1", "type": "aggregation", "query_id": "Q1",
      "bucket": { "key": "203.0.113.7", "doc_count": 412 } }
  ],
  "queries": [
    { "query_id": "Q1", "step": "s1", "purpose": "Sources with many failed SSH auths",
      "server": "es", "tool": "aggregate", "request": { "..." }, "request_hash": "sha256:...",
      "result_summary": { "buckets": 1 }, "took_ms": 14, "ok": true }
  ],
  "coverage": { "indices": ["logs-linux.auth-default"], "time_range": { "gte": "...", "lte": "..." },
                "missing_fields": [], "parse_failure_rate": 0.002, "full_coverage": true },
  "coverage_matrix": {
    "techniques": [
      { "id": "T1110.001", "status": "tested",       "steps": ["s1"] },
      { "id": "T1110.003", "status": "tested",       "steps": ["s1", "s2"] },
      { "id": "T1110.004", "status": "not_testable", "reason": "No breach-list data to distinguish credential stuffing" },
      { "id": "T1078",     "status": "tested",       "steps": ["s3"] } ],
    "criteria": [
      { "id": "CC1", "status": "tested", "steps": ["s1"] },
      { "id": "CC2", "status": "tested", "steps": ["s3"] },
      { "id": "RC1", "status": "tested", "steps": ["s3"] } ],
    "datasets": [
      { "dataset": "linux.auth",   "role": "primary",       "status": "queried",
        "time_coverage_ratio": 0.99, "gaps": [] },
      { "dataset": "firewall.log", "role": "corroborating", "status": "not_available" } ],
    "completeness_gate": "passed"
  },
  "limitations": ["No web logs available for host web-01"],
  "manifest": { "...see §5..." }
}
```

### 4.2 Proposed split of anti-hallucination work

| Check | C2 (self-check, before handoff) | C3 (independent verification) |
|---|---|---|
| Every claim cites at least one evidence ID and query ID | ✔ | ✔ |
| Cited IDs exist in `evidence[]` / `queries[]` | ✔ | ✔ |
| Numbers in a statement match the cited aggregation buckets | ✔ (structural) | ✔ |
| Document evidence actually exists in ES with these field values | — | ✔ via `get_documents` |
| Re-executing the query reproduces the result | — | ✔ (optional / sampled) |
| Narrative contains no entities (IPs, users, hosts) absent from the evidence | ✔ (entity extraction) | ✔ |
| Report rendering (Markdown / HTML / PDF) | — | ✔ |

---

## 5. C4 — Repeatability Interface (R9)

**CLI entry point:**

```bash
python -m threat_hunting.cli hunt --hypothesis-file hyp.txt --from 2026-10-14T00:00:00Z --to 2026-10-21T00:00:00Z --profile eval --out results/run1.json
```

| Option | Purpose |
|---|---|
| `--profile dev\|eval\|baseline\|demo` | `eval` and `demo` use MCP only; `baseline` switches all repeatability controls off |
| `--set controls.<name>=on\|off` | Toggle one control: `pin_model`, `deterministic_sampling`, `absolute_window`, `playbook_first`, `canonical_queries`, `deterministic_sort`, `rule_based_verdict`, `completeness_gate` |
| `--no-playbook` | Force LLM planning, so agentic planning itself is tested for repeatability |
| `--warmup` / `--replay <file>` | Demo support: pre-connect and cache; replay a recorded run |

Safety guardrails (read-only access, query limits, injection handling, self-check) cannot be switched off in any profile.

**Suggested experiment (C4 decides):** run `baseline` twice, then enable controls one at a time (or in groups), running each configuration twice. That shows *what was changed to make the runs converge*, as the project requirements ask.

**Run manifest (inside every `HuntResult`):**
```json
{ "agent_git_sha": "...", "profile": "eval",
  "controls": { "pin_model": true, "deterministic_sampling": true, "absolute_window": true, "playbook_first": true,
                "canonical_queries": true, "deterministic_sort": true, "rule_based_verdict": true, "completeness_gate": true },
  "tool_backends": { "es": "mcp:<C1 server version>", "analytics": "mcp:<C2 server version>" },
  "model": "<provider>/<exact-model-version>", "temperature": 0, "seed": 42,
  "prompt_hashes": { "intake": "sha256:...", "planner": "sha256:..." },
  "playbooks": { "PB-01": "0.1.0" }, "budgets": { "max_tool_calls": 20 },
  "mcp_server_version": "...", "index_doc_counts": { "logs-linux.auth-default": 104233 },
  "time_range": { "gte": "...", "lte": "..." }, "started_at": "...", "finished_at": "..." }
```

**Fields that should match across two runs:** `verdict.label`, `verdict.confidence`, `verdict.requires_analyst_review`, the set of `request_hash`, the set of `evidence[].doc_id`, `coverage` and `coverage_matrix`.
**Fields expected to differ:** `run_id`, timings, `started_at`/`finished_at`, narrative wording.

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
