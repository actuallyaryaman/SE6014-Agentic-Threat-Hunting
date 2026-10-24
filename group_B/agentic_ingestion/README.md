# B3 — Source inspection and planning

Batch 5 inspects bounded source samples, calls B1 recognition and B2 schema
resolution, and produces an ingestion plan. Transport, pipeline installation,
schema registration, Elasticsearch verification and audit belong to Batch 6.

## Python API

```python
from group_B.agentic_ingestion import InspectionPolicy, SourceSpec, plan_source
from group_B.common import load_b1_recognizer

source = SourceSpec(kind="file", location="/approved/logs/apache.log")
plan = plan_source(
    source, InspectionPolicy(allowed_roots=("/approved/logs",)),
    recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
    known_pipelines={"apache_access": "apache-access"},
)
print(plan.model_dump_json(indent=2))
```

B1 must be installed/importable separately. Its implementation is not copied
into this branch. Missing B1 configuration blocks planning; only an explicit
`reason_code="no_match"` invokes B2. Known formats require an operator-approved
format-to-pipeline mapping consistent with B1's pipeline ID when supplied.

`SourceSpec` follows `CONTRACTS.md`: source kind, location, format/dataset hints,
host metadata, timezone, ingestion mode and `dry_run=True` by default.
`format_hint` is structural: `auto`, `json`, `csv`, `kv`, or `line`.
Naive timestamps require an explicit IANA timezone. Yearless syslog remains
blocked until the team agrees on a year policy; inspection does not invent one.

Auto routes: file → pull, HTTP → push, stream → stream. File/HTTP sources can
explicitly choose pull or push. `direct_es` requires an explicit request and
is a local-fallback plan. Stream inspection takes `stream_samples=` through
the Python API without binding/sending UDP. Stream plans remain blocked:
A3 consumes normalized events and its B3 raw-envelope boundary is unresolved.

`status="planned"` means a plan was produced, not that ingestion succeeded.
Every plan states `verification_required=true`. New schemas still need
registration and Elasticsearch pipeline installation. B2 validation is offline;
reused schemas are checked against the current samples before accepting a plan.
Even `dry_run=False` executes nothing in this batch.

Raw samples and the exact B2 `schema_resolution` remain in memory for a future
executor but are excluded from JSON. JSON plans are summaries, not executable
bundles. Execution must inspect/plan again or consume the in-memory result.

## Access and sampling

- Empty path/host allowlists deny access. Files must resolve within an allowed
  root. Descriptor-relative no-follow opens prevent path swaps after resolution;
  symlink escapes and non-regular files are rejected.
- HTTP/HTTPS hosts must exactly match the allowlist. Every resolved address
  and redirect is checked. Link-local, reserved, multicast, unspecified and
  known cloud-metadata addresses are rejected even when allowlisted.
  Private/loopback sources require explicit host permission.
- HTTP pins a validated IP while retaining the Host and TLS SNI hostname.
  Environment proxies are unused; TLS certificates are verified. HTTPS
  redirects cannot downgrade to HTTP.
- Defaults: 50 nonblank records, 64 KiB per line, 1 MiB total bytes, a 5-second
  socket timeout/sampling deadline, and 3 redirects. Inputs are line-oriented
  UTF-8; compressed HTTP bodies, binary or oversized records fail clearly.
- `sample_limit_reached` means sampling stopped at the cap; it does not claim
  that the whole source was inspected.

## CLI

Run from the repository root. `B3_ALLOWED_ROOTS` uses `os.pathsep` (`:` on
Linux); `B3_ALLOWED_HOSTS` is comma-separated.

```bash
B3_ALLOWED_ROOTS="$PWD/group_B/tests/fixtures/otrf" \
  group_B/.venv/bin/python -m group_B.agentic_ingestion.cli inspect \
  group_B/tests/fixtures/otrf/AWS_S3_HoneyBucketLogs.csv --kind file

# Once B1 is available, plan a known source using approved pipeline IDs.
B3_ALLOWED_ROOTS=/approved/logs \
  group_B/.venv/bin/python -m group_B.agentic_ingestion.cli plan \
  /approved/logs/apache.log --kind file \
  --b1 group_B.B1.recognizer:recognise \
  --known-pipelines '{"apache_access":"apache-access"}'
```

Results are JSON. Exit codes: 0 for inspection/a produced plan, 2 for a blocked
plan, 1 for source/configuration errors. Source/configuration errors go to
stderr. Argparse usage errors retain its standard text and exit code 2.
There is no execution flag in Batch 5.

`--llm-route` optionally requests OpenRouter transport advice using
`OPENROUTER_API_KEY` and `OPENROUTER_MODEL`. It sends only source kind, format
and sample count to the public OpenRouter endpoint. Advice can choose only
permitted modes and cannot override an explicit mode, source permission,
pipeline, dry-run setting or blocking reason. Invalid advice falls back to
the deterministic route. Python callers can separately inject B2's
`schema_provider`. Tests inject offline inference; no live LLM run is claimed.

## Modules and remaining work

| Module | Responsibility |
|---|---|
| `models.py` | Source specification, policy, inspection and plan results |
| `inspect.py` | Safe file/HTTP inspection, stream samples, timestamps |
| `planner.py` | B1/B2 orchestration, approved pipeline selection and routes |
| `llm.py` | Optional constrained OpenRouter transport advice |
| `cli.py` | JSON `inspect` and `plan` commands |
| `adapters.py` | Protocol for Batch 6 adapters; no implementations yet |

Batch 6 adds transport adapters, verification, audit and execution controls.
The B2 live Elasticsearch check has now passed on an isolated 8.19.23 server
(10 live cases; 227 tests in the combined suite). See
`group_B/tests/LIVE_ES_RESULTS.md`. Batch 7 still verifies shared A1/A2/A3
integration, live LLM behavior and the complete demo.
