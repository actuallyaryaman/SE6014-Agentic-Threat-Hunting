# C1 Elasticsearch MCP server

This package promotes `dev/es_mcp_standin` into the maintained C1 server.
The temporary implementation and C2's default command remain available.
Phase 1 preserves the existing tool arguments, top-level JSON responses,
structured filters, 200-hit search cap, 31-day query window and audit format.
The query compiler is reused from `threat_hunting.query`.

## Install

Use Python 3.11 or later. From `group_C/threat_hunting`, in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use the same environment to run C2 so its MCP subprocess uses this interpreter.
No dependencies beyond the existing Group C requirements are added.

## Configure and run

Set the following in the process environment, or in the existing local `.env`
file loaded by `threat_hunting.config`. Never commit credentials.

- `ES_URL`: Elasticsearch endpoint, normally `https://localhost:9200`.
- `ES_API_KEY`: an encoded read-only Elasticsearch API key. Provision it outside
  this server with `read` and `view_index_metadata` on `security-events-*`.
- `ES_CA_CERT`: path to the cluster CA certificate. Leave empty only when the
  server certificate is already trusted by the client's default trust store.
- `HUNT_INDEX`: optional discovery/hunt pattern, default `security-events-*`.
- `HUNT_INDEX_PREFIX`: optional allowed prefix, default `security-events-`.

HTTPS certificate verification is explicitly enabled and cannot be disabled
through these settings. Self-signed clusters require their CA certificate.
Plain HTTP remains compatible with isolated local test clusters; it does not
encrypt credentials. The server does not grant or verify API-key privileges:
the cluster administrator must restrict the key. No ES write tools are exposed.

Launch directly over stdio (it waits for MCP messages, not interactive input):

```powershell
.\.venv\Scripts\python.exe -m es_mcp_server.server
```

Select C1 for Dat's existing C2 client, using the same working directory:

```powershell
$env:HUNT_ES_MCP_CMD = 'python -m es_mcp_server.server'
.\.venv\Scripts\python.exe -m threat_hunting.run "An external IP brute-forced SSH and then logged in on 2026-10-01."
```

Supply the real `ES_URL`, `ES_API_KEY`, and `ES_CA_CERT` securely in that process
before running a hunt. C2 passes these variables to the ES MCP subprocess.
Relative CA paths resolve from `group_C/threat_hunting`; absolute paths avoid
ambiguity. `HUNT_RUN_ID` identifies audit records; C2 sets it automatically.
Audit files remain in `audit/`, and C2 traces/results remain in `runs/`.

To return to the temporary server, set
`HUNT_ES_MCP_CMD=python -m dev.es_mcp_standin.server`.
The inherited `--http --port 8765` entry point is retained for manual use;
C2 currently connects over stdio only. Shared HTTP deployment is outside Phase 1.

## Compatible tools

| Tool | Arguments | Top-level result fields |
|---|---|---|
| `describe_data` | `index_pattern` | `sources`, `fields`, `total` |
| `search` | `index`, `time_from`, `time_to`, optional `filters`, `must_not`, `any_of`, `fields`, `size`, `sort` | `hits`, `total`, `returned`, `truncated`, `dsl` |
| `count` | index/time bounds and optional filter lists | `total`, `dsl` |
| `aggregate` | index/time bounds, `agg`, optional `field`, filter lists, `size`, `interval`, `sum_field`, `distinct_field` | `total`, `result`, `dsl` |
| `get_event` | exact `index`, `event_id` | `total`, `event` including `event.original` |
| `save_finding` | `claim`, `evidence_ids` | `total`, `saved` |
| `get_audit_log` | optional `run_id` | `run_id`, `n`, `records` |

Responses retain `tool` and `call_id` (`null` for `get_audit_log`). Failures retain
top-level `error`. FastMCP includes JSON in the first text content block, as
required by C2. Search hits retain `{index, event_id, fields}`; `event_id` is
the Elasticsearch document `_id`, not the source's ECS `event.id`.
`save_finding` records an audit entry; it does not independently verify a claim.
Detailed filter/aggregation behavior remains that of the temporary server.

## Validate Phase 1

From `group_C/threat_hunting`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -m "not es"
.\.venv\Scripts\python.exe -m pytest -q tests/test_es_mcp_server.py
```

Tests compare all seven input schemas against the stand-in, call every tool
against a fake ES backend, verify query limits/evidence shapes/error envelopes
and TLS configuration, initialize the real server entry point over MCP stdio,
and exercise C2's real `McpHunt` and `hunter.run_step` over stdio.
Subprocess tests use temporary audit directories and need no Elasticsearch,
LLM, API key or live network connection. They require the actual MCP and ES
Python packages from `requirements.txt`.

The test-only backend lives in `tests/c1_mcp_fixture.py`; production has no fake
backend setting. Live cluster access, stricter validation/error handling,
mapping conflict handling and shared ingestion integration remain later phases.
