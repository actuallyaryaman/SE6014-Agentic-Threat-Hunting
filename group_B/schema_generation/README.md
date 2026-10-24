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
| `cli.py` | `detect`, `generate`, `validate`, `register`, `list` | Batch 4 |

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

## Batch status

- Batch 0: package scaffold only.
- Batch 1: schema model, signature, registry and detection.
- Batch 2: pipeline compiler and validator.
- Batch 3: agentic generation.
- Batch 4: CLI and end-to-end reuse.

See `group_B/CONTRACTS.md` for the interfaces with B1, B3, A2/A3 and C2.
