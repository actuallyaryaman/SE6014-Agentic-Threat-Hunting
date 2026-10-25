# B3 — Source onboarding

Batches 5–6 provide bounded source inspection, read-only planning, explicit
execution, Elasticsearch verification and JSONL audit records. Execution is
opt-in; a transport acknowledgement alone never counts as success.

## Python API

```python
from group_B.agentic_ingestion import (
    ExecutionConfig, InspectionPolicy, SourceSpec, onboard, plan_source,
)
from group_B.common import load_b1_recognizer

source = SourceSpec(kind="file", location="/approved/logs/apache.log")
policy = InspectionPolicy(allowed_roots=("/approved/logs",))
options = dict(
    recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
    known_pipelines={"apache_access": "apache-access"},
)
plan = plan_source(source, policy, **options)
print(plan.model_dump_json(indent=2))

# Still a dry run: no audit, registry, pipeline or ingestion writes.
report = onboard(source, policy, ExecutionConfig.from_env(), **options)

# Explicit execution. Configure credentials and Group A endpoints first.
report = onboard(source.model_copy(update={"dry_run": False}), policy,
                 ExecutionConfig.from_env(), **options)
print(report.model_dump_json(indent=2))
```

B1 is now included from merged `main` at `group_B/B1/`; configure the loader
as `group_B.B1.recognizer:recognise`. Missing B1 configuration blocks planning;
only an explicit
`reason_code="no_match"` invokes B2. Known formats require an operator-approved
format-to-pipeline mapping consistent with B1's pipeline ID when supplied.
Their pipelines must already exist in Elasticsearch. New/reused B2 pipelines
receive fresh live `_simulate` validation before pending records are sent.
Missing generated pipelines are installed; conflicting installed definitions
are rejected rather than overwritten. New schemas receive live validation at
the registry boundary too. Installation/registration can remain after a later
failure; B3 does not delete shared pipelines or roll back indexed documents.

`SourceSpec` follows `CONTRACTS.md`: source kind, location, format/dataset hints,
host metadata, timezone, ingestion mode and `dry_run=True` by default.
`format_hint` is structural: `auto`, `json`, `csv`, `kv`, or `line`.
Naive timestamps require an explicit IANA timezone. Yearless syslog remains
blocked until the team agrees on a year policy.

Auto routes: file → pull, HTTP → push, stream → stream. File/HTTP sources can
explicitly choose pull or push. `direct_es` requires an explicit request and
is a local fallback. Stream inspection takes `stream_samples=` through the
Python API without binding/sending UDP. Stream execution remains blocked:
A3 consumes normalized events and its B3 raw-envelope boundary is unresolved.

`plan_source` always remains read-only, including with `dry_run=False`.
Raw samples and exact B2 resolutions stay in memory and are excluded from JSON
plans. Plans are summaries, not executable bundles: `onboard` captures the
source once and constructs its own fresh plan from that snapshot.

## Access and bounds

- Empty path/host allowlists deny access. Files must resolve within an allowed
  root. Descriptor-relative no-follow opens prevent path swaps after resolution;
  symlink escapes and non-regular files are rejected.
- HTTP/HTTPS hosts must exactly match the allowlist. Every resolved address
  and redirect is checked. Link-local, reserved, multicast, unspecified and
  known cloud-metadata addresses are rejected even when allowlisted.
  Private/loopback sources require explicit host permission.
- HTTP pins a validated IP while retaining Host and TLS SNI. Environment
  proxies are unused; TLS certificates are verified. HTTPS redirects cannot
  downgrade to HTTP.
- Inspection defaults: 50 nonblank records, 64 KiB per line, 1 MiB total bytes,
  a 5-second socket/sampling deadline, and 3 redirects. UTF-8 line-oriented
  inputs only; compressed HTTP bodies, binary and oversized records fail.
- Execution captures the complete bounded snapshot: at most 10,000 nonblank
  lines (including any CSV header) and 16 MiB. Over-limit sources fail before
  transport; B3 never silently ingests only the inspection sample. The first
  50 records drive planning. A declared CSV header is omitted from events.
  Python `ExecutionConfig` can lower these execution limits.

## Execution and verification

Envelopes preserve raw `message`, optional `host.name`, deterministic top-level
`event_id` and nested `event.id`, plus `labels.source_id`, `run_id`,
`ingest_mode` and `ingest_pipeline`. IDs hash the canonical source identity,
nonblank-record ordinal and exact raw line. Identical lines at different
ordinals remain distinct events.

Pull atomically publishes a private NDJSON file into an existing configured
A2 incoming directory. Files use mode `0600`; provision a matching runtime
UID so A2 can read them. B3 does not create the directory or widen permissions. Push sends one JSON object per
HTTP request, with certificate verification, no redirects or environment
proxies, and a bounded request timeout/60-second send loop. Direct ES uses
100-record bulk batches with the selected pipeline and waits for refresh.
Partial bulk/HTTP errors are reported; adapters do not automatically retry.

Before sending, B3 searches the configured index pattern for logical IDs and
checks their evidence. Valid existing records are reused; conflicting or
duplicate matches fail. Missing read credentials or an unavailable search
blocks submission and returns `unverified`. After sending, bounded polling
checks every expected record for:

- Preserved `event_id`, exact raw `event.original` hash and `labels.source_id`.
- The selected `event.dataset`, nonempty `message`, and UTC ISO timestamp.
- `_parse_failure` records additionally carry `error.message`; the report
  counts them. `verified` proves indexing and required evidence, not that
  every record parsed successfully.

A2's current fingerprint combines source ID and event ID. B3 therefore queries
preserved `event_id` rather than assuming Elasticsearch `_id` equals it.
Direct ES uses the logical ID as `_id`. Sequential replays skip verified
records, including across daily indices. Concurrent runs and an A2 handoff
still in flight across a day boundary are not an exactly-once guarantee;
serialize onboarding per source and use `verify` before replaying uncertain
handoffs. Duplicate search matches fail verification.

The audit path receives durable `started` and `completed` JSONL entries,
including run/source IDs, status, pipeline/dataset, counts and stable error
codes. No source contents, credentials or source URLs/paths are recorded.
Failure to persist the starting entry prevents execution; failure to persist
completion returns `failed` even if documents indexed. A started entry without
completion signals an interrupted run. Audit files are operator-managed local
evidence, not tamper-proof storage.

## Configuration and CLI

Run from the repository root. `B3_ALLOWED_ROOTS` is colon-separated on Linux;
`B3_ALLOWED_HOSTS` is comma-separated. See `group_B/.env.example`.

```bash
B3_ALLOWED_ROOTS="$PWD/group_B/tests/fixtures/otrf" \
  group_B/.venv/bin/python -m group_B.agentic_ingestion.cli inspect \
  group_B/tests/fixtures/otrf/AWS_S3_HoneyBucketLogs.csv --kind file

# B1 must be available. Default onboard is a dry run; plan is always read-only.
B3_ALLOWED_ROOTS=/approved/logs \
  group_B/.venv/bin/python -m group_B.agentic_ingestion.cli onboard \
  /approved/logs/apache.log --kind file \
  --b1 group_B.B1.recognizer:recognise \
  --known-pipelines '{"apache_access":"apache-access"}' --dry-run --json

# After configuring Group A/ES, use the same arguments with --execute.
# For the local fallback, also set --mode direct_es explicitly.
# Use verify in place of onboard to query existing documents without sending.
```

`--execute` is accepted only by `onboard`. `verify` captures/plans and writes
audit evidence, but never installs pipelines, registers schemas or submits
records. All results are JSON (`--json` is optional). Exit codes: 0 for
inspection, a produced plan, dry run or verified result; 2 for blocked; 1 for
failed/input errors; 3 for unavailable ES verification. Source/configuration
errors go to stderr. Argparse retains its standard text/exit code 2.

| Setting | Purpose |
|---|---|
| `ES_URL`, `ES_CA_CERT`, `ES_VERIFY_CERTS=true` | ES endpoint and trusted CA; disabling verification is rejected |
| `ES_READ_API_KEY` | Verification search over the intended indices (`read` privilege) |
| `ES_WRITE_API_KEY` | `manage_pipeline`; direct mode also needs write/create-index rights on the configured prefix |
| `ES_WRITE_INDEX_PREFIX` | Direct index `<prefix>-YYYY.MM.dd`, default `security-events` |
| `ES_SEARCH_INDEX_PATTERN` | Verification scope, default `security-events-*`; must cover the write prefix |
| `A2_INCOMING_DIR`, `A2_PUSH_URL` | Operator-selected Group A file directory/HTTP endpoint |
| `B3_AUDIT_PATH` | Local JSONL audit path, default ignored `agentic_ingestion/runtime/audit.jsonl` |

A2 has its own output credentials/index-prefix configuration. Align its index
prefix and B3's search pattern before execution; A2 development defaults are
not the integrated `security-events-*` convention. Pull/push also need the B3
pipeline-management key when records are pending. A2 owns the indexing key.

`--llm-route` requests optional OpenRouter transport advice using
`OPENROUTER_API_KEY` and `OPENROUTER_MODEL`; only kind, format and sample count
are sent. Advice cannot change endpoints, permissions, pipeline or dry-run
controls. `--llm-schema` explicitly enables B2's sample-bearing OpenRouter
candidate provider. Tests use deterministic heuristics/injected inference;
no paid/live OpenRouter result is claimed.

## Modules and validation

| Module | Responsibility |
|---|---|
| `models.py` | Source, policy, plan, execution configuration and results |
| `inspect.py` | Safe bounded inspection and complete execution snapshots |
| `planner.py` | B1/B2 orchestration, approved pipeline selection and routes |
| `llm.py` | Optional constrained OpenRouter transport advice |
| `execution.py` | Fresh planning, pipeline preparation and orchestration |
| `adapters.py` | Atomic file drop, HTTP push, explicit direct ES bulk |
| `verify.py` | Independent logical-ID/required-field verification |
| `audit.py` | Private append-only JSONL evidence |
| `cli.py` | JSON `inspect`, `plan`, `onboard` and `verify` commands |

The isolated ES 8.19.23 suite covers real simulation, installation, indexing,
verification and replay. See `group_B/tests/LIVE_ES_RESULTS.md` for evidence.
The unchanged A1/A2 configurations also passed with actual Logstash pull/push
over authenticated HTTPS in an isolated environment; see
`group_B/tests/A1_A2_INTEGRATION_RESULTS.md`. The actual shared deployment,
the A3 boundary, live LLM behavior and the complete team demo remain.

Live C2/C3 snapshot integration: [results and unresolved correlation claim](../tests/C2_C3_INTEGRATION_RESULTS.md).
