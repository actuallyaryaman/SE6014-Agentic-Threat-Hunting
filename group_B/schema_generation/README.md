# B2 — Unknown Schema Generation

This package implements the B2 lifecycle:

```text
detect no match
  -> build a candidate SchemaSpec
  -> compile an Elasticsearch ingest pipeline
  -> validate against sample records
  -> register the validated schema
  -> reuse it for the next source with the same signature
```

## Modules

| Module | Responsibility | Status |
|---|---|---|
| `models.py` | Declarative `SchemaSpec`, parser, field, timestamp, validation and provenance models | Batch 1 |
| `signature.py` | Deterministic structural signatures for CSV, JSON, KV and line sources | Batch 1 |
| `registry.py` | Versioned file registry, signature index and atomic writes | Batch 1 |
| `detect.py` | Signature construction and registry lookup | Batch 1 |
| `generate.py` | Heuristic and LLM candidate generation | Batch 3 |
| `validate.py` | Required fields, timestamps, types, parse rate, safety rules | Batch 2 |
| `compile_es.py` | `SchemaSpec` to Elasticsearch ingest pipeline JSON | Batch 2 |
| `cli.py` | `detect`, `generate`, `validate`, `register`, `list`, `resolve` | Batch 4 |

## Compile and validate

```python
from group_B.schema_generation import (
    compile_pipeline,
    validate_pipeline,
)

pipeline = compile_pipeline(schema, samples=samples)
report = validate_pipeline(schema, pipeline, samples)
if report.accepted:
    registry.register(
        schema=schema,
        signature=signature,
        pipeline=pipeline,
        validation=report,
        provenance=provenance,
    )
```

`compile_pipeline` uses only the positive processor allowlist from
`group_B/CONTRACTS.md`. CSV is compiled to a bounded `grok` pattern because the
native Elasticsearch `csv` processor is not allowlisted; CSV compilation
therefore needs representative samples to infer the header or column count.
Sample values are not written into the pipeline.

`validate_pipeline` defaults to a deterministic offline simulation of the
generated processors. Pass `mode="es_simulate"` and an Elasticsearch client to
use the real `_simulate` API instead. The report records the sample count,
available count, required-field and timestamp rates, type errors, parse-failure
count, and any validation errors.

Parse failures are still indexed with the four required fields, a
`tags: ["_parse_failure"]` marker, and `error.message`. A schema must parse at
least one sample successfully before it can be accepted.

## Generation

```python
from group_B.schema_generation import (
    generate_schema,
    resolve_or_generate,
    OpenRouterCandidateProvider,
)

# heuristics only; deterministic offline
report = generate_schema(samples, "unknown.dataset")

# with an OpenRouter candidate provider (offline tests inject the callable)
provider = OpenRouterCandidateProvider(model="google/gemini-2.0-flash-001")
report = generate_schema(samples, "unknown.dataset", provider=provider)

# batch-3 entry point used by B3 and the Batch 4 CLI
resolution = resolve_or_generate(samples, "unknown.dataset", registry=registry)
if resolution.reused:
    entry = resolution.entry
else:
    result = resolution.generation
```

The heuristic generators propose candidates for plain JSON objects, CSV with a
header, and `key=value` records. Anything else needs an injected provider.
`generate_schema` keeps the first candidate whose validation report is
accepted; rejected candidates are kept for provenance. The generator never
touches the network by itself: `OpenRouterCandidateProvider` only calls
OpenRouter when :meth:`propose` is invoked and an inference callable or API
key is supplied.

## Registry layout

```text
registry/
  index.json
  schemas/<schema_id>/v<version>.json
```

`index.json` maps a source signature hash to the validated schema version and
pipeline. Entry files contain the `SchemaSpec`, compiled pipeline, pipeline ID,
validation report and provenance. Only entries whose validation report is
accepted can be registered. Writes use a temporary file and `os.replace`.

## B1 integration boundary

B1 is owned separately and remains on its own branch and PR. B2 and B3 do not
copy or import B1's implementation directly; they depend only on the
`Recognizer` protocol and load B1 through
`group_B.common.recognizer.load_b1_recognizer("module:function")`.

The boundary is covered by contract tests that pass B1-shaped mappings through
`B1Recognizer`, without importing B1. A matched mapping must set
`"matched": true` and include non-empty `format_id` and `dataset`;
`pipeline_id` is optional. An unmatched mapping must set `"matched": false`
and use `reason_code` `"no_match"` or `"not_configured"`.

The current B1 branch (`b1-recogniser-pipelines`) returns this exact shape and
exposes the recogniser at `group_B.B1.recognizer:recognise` via a shim, which
is accepted by the default allowlist after `matched` was added. Loading it
works end-to-end when merged: `load_b1_recognizer` dynamically imports the
shim and the adapter coerces B1's dict to `RecogniseResult`.

Runtime loading also requires B1 to be importable from one of the allowlisted
module prefixes and to expose a callable. This is an
integration requirement only; B2 does not vendor B1's code.

## CLI

```bash
# signature lookup against the registry
group_B.schema_generation.cli --registry ./my-registry detect samples.jsonl

# generate (offline heuristics) and register on acceptance
group_B.schema_generation.cli --registry ./my-registry generate samples.jsonl \
    --dataset unknown.dataset --register

# generate with an OpenRouter provider (OPENROUTER_* env vars)
group_B.schema_generation.cli generate samples.jsonl --llm --register

# re-validate a SchemaSpec JSON file against samples
group_B.schema_generation.cli validate schema.json samples.jsonl

# register a bundle produced by `generate --emit bundle.json`
group_B.schema_generation.cli register bundle.json

# end-to-end: reuse when the signature is known, else generate
group_B.schema_generation.cli resolve samples.jsonl --dataset unknown.dataset
```

Every command prints one JSON document. Rejected candidates exit non-zero with
an error document on stderr; raw sample text is never written to the registry
or the output.

## Batch status

- Batch 0: package scaffold.
- Batch 1: schema model, signature, registry and detection.
- Batch 2: pipeline compiler and validator.
- Batch 3: agentic generation with an optional OpenRouter candidate provider;
  the heuristic generators stay offline and deterministic.
- Batch 4: CLI (detect, generate, validate, register, list, resolve) with
  end-to-end signature reuse; complete.

See `group_B/CONTRACTS.md` for the interfaces with B1, B3, A2/A3 and C2.
