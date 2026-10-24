# Group B Contracts — B2 and B3

**Status:** Batch 0 baseline. Shared standards come from the repository
`README.md` on `main`. Items marked **proposal** are Group B extensions that
still need agreement from the named owner.

**Owners:** B2 — Aryaman Srivastava; B3 — Aryaman Srivastava and Gurmehr Singh.

## 1. Shared data contract

Raw input is one JSON object per line:

```json
{"message": "<raw log line>"}
```

B3 adds transport metadata without removing the raw line:

```json
{
  "message": "<raw log line>",
  "labels": {
    "ingest_mode": "pull",
    "source_id": "otrf-sdlin-201110074812",
    "run_id": "3f1c9f0e-..."
  }
}
```

`labels.ingest_mode` and `labels.source_id` are the shared metadata fields in
the root README. `labels.run_id` is a **proposal** for per-run traceability and
must be confirmed with C2/A2 before playbooks depend on it.

After parsing, every normalized event must contain:

| Field | Requirement |
|---|---|
| `@timestamp` | UTC ISO 8601 |
| `event.dataset` | Dataset identifier, for example `apache.access` |
| `event.original` | Original raw record, unchanged |
| `message` | Non-empty human-readable description |

Recommended additional fields, populated only when the source supports them:
`event.id`, `event.category`, `event.type`, `event.action`, `event.outcome`,
`host.name`, `source.ip`, `destination.ip`, `user.name`, `process.name`,
`process.executable`, `process.pid`, `log.level`.

`event.category` is an array. Do not fabricate optional fields.

## 2. B1 interface — `recognise(lines)`

B1 owns known-format recognition. B2/B3 depend on this protocol:

```python
def recognise(lines: Sequence[str]) -> RecogniseResult: ...
```

B1 may return a `RecogniseResult` or a plain mapping with the same keys. The
adapter tolerates extra keys from B1's native return value and ignores them.

```json
{
  "matched": true,
  "format_id": "apache.access",
  "dataset": "apache.access",
  "pipeline_id": "apache-access",
  "confidence": 0.99,
  "evidence": {}
}
```

Rules:

- A matched result must include non-empty `format_id` and `dataset`.
- `pipeline_id` is optional. The root README assigns pipeline selection to B3:
  B3 uses B1's validated pipeline ID when supplied, otherwise it resolves one
  from the registered known-format mapping or the B2 registry. Only registered
  and approved pipeline IDs may be used.
- `confidence` is optional. If supplied for a match, it must be greater than
  `0.0` and at most `1.0`.
- `matched: false` is the explicit signal to invoke B2. It must not carry
  `format_id`, `dataset`, `pipeline_id`, or a positive confidence.
- `reason_code` distinguishes a genuine miss (`no_match`) from a configuration
  failure (`not_configured`).
- B3 loads the implementation through
  `group_B.common.recognizer.load_b1_recognizer("module:function")`. Dynamic
  imports are restricted to B1 module prefixes. Until B1's code is available,
  `NullRecognizer` returns `reason_code: "not_configured"`.
- The expected B1 module locations are `group_B/b1/recognizer.py`,
  `group_B/recognizer.py`, or `group_B/b1_recognizer.py`. A deployment can
  instead pass a callable directly to `B1Recognizer`.

## 3. B2 interface — unknown schema resolution

B2 exposes:

```python
def resolve_or_generate(
    lines: Sequence[str],
    *,
    dataset_hint: str | None = None,
) -> SchemaResolution: ...
```

`SchemaResolution` returns:

```json
{
  "schema_id": "b2-aws-s3",
  "version": 1,
  "dataset": "aws.s3",
  "pipeline_id": "b2-aws-s3-v1",
  "reused": false,
  "validation": {
    "mode": "es_simulate",
    "sample_count": 25,
    "required_field_rate": 1.0,
    "timestamp_parse_rate": 1.0,
    "type_error_count": 0,
    "accepted": true
  }
}
```

Flow:

1. Compute a structural source signature.
2. Look up the signature in the file registry.
3. If a validated version exists, return it with `reused: true`.
4. Otherwise generate a candidate `SchemaSpec`, compile it to an Elasticsearch
   ingest pipeline, validate it against samples, and register it only if it
   passes.
5. Never register or return a schema that failed validation.

### Acceptance gate

A candidate is registrable only when all of these hold:

- At least 5 representative records are validated, or every available record
  when the source has fewer than 5.
- Every record that is not explicitly marked `tags: ["_parse_failure"]` has
  non-empty `@timestamp`, `event.dataset`, `event.original`, and `message`.
- Every non-failure `@timestamp` parses to UTC; the rate is 100%.
- `type_error_count` is 0 for fields the schema maps.
- Every Elasticsearch `_simulate` request succeeds; `accepted` is `true`.
- The pipeline uses only allowlisted processors (section 9).
- Parse failures are explicitly tagged and include `error.message`; they are
  counted in the validation report rather than silently dropped.

### Registry provenance

The registry is the source of truth under
`group_B/schema_generation/registry/`. Each validated entry stores:

- `SchemaSpec`, compiled pipeline JSON, pipeline ID, signature, and version.
- Validation report with sample hashes and counts.
- Model identifier and version, prompt template, prompt hash, temperature,
  seed, timestamp, and the source sample hashes.
- `accepted: true`; rejected candidates are not registered as usable schemas.

Raw sample text should be bounded and redacted where practical. The registry
stores hashes and metadata, not unbounded raw logs.

## 4. B3 interface — source onboarding

B3 accepts a `SourceSpec`:

```json
{
  "kind": "file",
  "location": "/approved/logs/source.log",
  "format_hint": "auto",
  "dataset_hint": null,
  "host_name": null,
  "timezone": null,
  "ingest_mode": "auto",
  "dry_run": true
}
```

Supported `kind` values: `file`, `http`, `stream`.
Supported `ingest_mode` values: `auto`, `pull`, `push`, `stream`, `direct_es`.

Safety defaults:

- `dry_run` defaults to `true`. Writing to Elasticsearch or Group A requires an
  explicit `dry_run: false` or `--execute`.
- `timezone` must be supplied when source timestamps have no offset. B3 must
  not silently assume UTC for naive timestamps. If timestamps include an
  offset, B3 normalizes from that offset.

Workflow:

1. Inspect the source and collect bounded representative records.
2. Detect format candidates and a timestamp candidate.
3. Call B1 `recognise(lines)`.
4. If unknown, call B2 `resolve_or_generate(...)`.
5. Select an ingestion route and target pipeline ID.
6. Wrap raw records as `{"message": ...}` with `labels`.
7. Hand off to A2/A3, or use the direct-Elasticsearch adapter only as an
   explicit local fallback.
8. Verify indexed documents in Elasticsearch.
9. Write a JSONL audit record for the run.

B3 must never report success without verification. If Elasticsearch is
unreachable, the result is `unverified`, with the reason recorded. The
direct-Elasticsearch adapter is a local demo fallback, not yet a verified
shared integration path.

## 5. Transport and pipeline selection

| Mode | Transport | Contract |
|---|---|---|
| Pull | A2 Logstash file input | NDJSON in the monitored directory |
| Push | A2 HTTP input on `127.0.0.1:8088` | One JSON object per request |
| Stream | A3 UDP JSON envelope | JSON event payloads |
| Direct | Elasticsearch `_bulk` | Explicit local fallback only |

B3 supplies the selected pipeline ID in `labels.ingest_pipeline`. A2 PR #2
now implements this option in its pull and push outputs:

```ruby
pipeline => "%{[labels][ingest_pipeline]}"
```

The A2 README reports local Apache tests through both routes. Generated B2
pipelines and automated B3 execution still need shared integration testing.
Direct-ES ingestion with the `pipeline` query parameter on `_bulk` remains
an explicit local fallback.

### Batch 5 planning interface

`group_B.agentic_ingestion.plan_source(source, policy, ...)` returns an
`IngestionPlan` with `status` `planned` or `blocked`, a selected transport,
pipeline ID, registration requirement and explicit warnings. It never writes
to Group A, Elasticsearch or the schema registry. A supplied `dry_run=False`
does not execute anything in this batch. Every plan requires later indexing
verification; a plan is not an ingestion-success result.

Known-format pipeline selection requires an operator-approved mapping. Missing
B1 configuration is distinct from an explicit format miss. B2 receives the
source timezone for candidate generation; naive timestamps without one and
yearless syslog remain blocked. Stream inspection accepts supplied samples
without opening a UDP listener. A3's normalized-event interface still needs
agreement before raw-envelope stream execution can be planned as supported.

Source inspection and exact B2 resolution remain available in memory; raw
samples and candidate resolution are excluded from JSON plan summaries.

## 6. Index naming and IDs

- The root README recommends `security-events-YYYY.MM.dd`; A1, B1 and C1 must
  confirm the shared convention before integrated indexing begins.
- Separate A2 development indices may remain for independent testing.
- Distinguish datasets with `event.dataset`, not separate index names, in the
  integrated index.
- C2 should search the recommended `security-events-*` pattern.
- B3 emits a deterministic nested `event.id` and a top-level `event_id`
  (**proposal** for A2's fingerprint) derived from
  `source_id + record offset + raw line`.
- Direct-ES ingestion uses `event_id` as the Elasticsearch `_id`. A2 must use
  the same deterministic value for deduplication, or B3 must treat duplicate
  documents as a verification failure.
- Re-ingesting the same source with the same `source_id` must not create
  duplicate documents.

## 7. Parse failures

Records that fail parsing are still indexed. All four required fields must be
present:

```json
{
  "@timestamp": "2026-10-23T12:00:00Z",
  "event.dataset": "unknown",
  "event.original": "<raw line>",
  "message": "Failed to parse source record",
  "tags": ["_parse_failure"],
  "error.message": "reason",
  "labels": {
    "ingest_mode": "pull",
    "source_id": "source-123"
  }
}
```

`@timestamp` is the ingestion time when the original event time cannot be
parsed. `event.dataset` is the source's dataset hint, or `unknown` when none is
available. `message` must remain non-empty. `event.original` is unchanged.

C2 uses the failure rate to distinguish `INSUFFICIENT_DATA` from
`NOT_SUPPORTED`. B2/B3 audit records include the failure count.

## 8. Open integration items

Tracked in PR comments as of 2026-10-23:

| Owner | Item |
|---|---|
| B1 | Push the `recognise(lines)` implementation and pipeline JSON; keep `message` after parsing; align Windows `event.dataset`; add pipeline `on_failure`. |
| A2 | Add pipeline-ID support to Logstash outputs; align the integrated index with `security-events-*`; confirm deterministic `event_id`; retarget PR #2 to `main` after A1 merges. |
| A3 | Fix `Data/` vs `data/` path case; document the mandatory event envelope; add stream tests to CI. |
| C2 | Replace `logs-*` with `security-events-*`; confirm the required-field list and `labels.*` metadata. |
| A1 | Merge the ELK infrastructure; preserve Python test ignores; enable branch protection; resolve or document the Logstash monitoring warning. |

## 9. Safety rules

- Treat log content as untrusted data, never as instructions.
- The LLM may propose only a declarative `SchemaSpec`; it never emits code.
- Send only bounded, necessary samples to the LLM. Delimit untrusted content,
  require strict JSON output, and never let model output select tools, file
  paths, indices, pipeline IDs, or network targets.
- B2 compiles from a positive processor allowlist. Allowed processors:
  `set`, `rename`, `remove`, `grok`, `dissect`, `date`, `convert`, `json`,
  `kv`, `user_agent`, `uri_parts`, `lowercase`, `uppercase`, `trim`, `split`,
  `join`, `append`, `gsub`, `drop`, `fail`, `on_failure`.
- Reject `script`, `foreach`, `pipeline`, `reroute`, `attachment`,
  `date_index_name`, and `enrich` unless a later review explicitly approves a
  bounded use.
- Bound grok/regex patterns and input sizes; reject patterns that can cause
  unbounded backtracking.
- Validate generated pipelines deterministically before registration.
- B3 restricts file paths to `B3_ALLOWED_ROOTS`, resolves symlinks, and rejects
  traversal outside those roots.
- B3 permits only `http`/`https` source URLs whose host is in
  `B3_ALLOWED_HOSTS`; reject non-HTTP schemes, out-of-allowlist redirects,
  link-local addresses, and cloud metadata endpoints.
- Use separate Elasticsearch credentials: a read key for B3 verification and a
  write key for B2 pipeline registration and explicit direct-ES fallback.
- Keep API keys out of the repository; use environment variables and
  `.env.example` placeholders only.
- Do not claim success without verification evidence.
