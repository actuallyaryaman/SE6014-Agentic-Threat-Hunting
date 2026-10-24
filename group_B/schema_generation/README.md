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

## Planned modules

| Module | Responsibility |
|---|---|
| `detect.py` | Structural signature and registry lookup |
| `generate.py` | Heuristic and LLM candidate generation |
| `validate.py` | Required fields, timestamps, types, parse rate, safety rules |
| `compile_es.py` | `SchemaSpec` to Elasticsearch ingest pipeline JSON |
| `registry.py` | Versioned file registry and pipeline registration |
| `cli.py` | `detect`, `generate`, `validate`, `register`, `list` |

## Batch status

- Batch 0: package scaffold only.
- Batch 1: schema model, signature and registry.
- Batch 2: pipeline compiler and validator.
- Batch 3: agentic generation.
- Batch 4: CLI and end-to-end reuse.

See `group_B/CONTRACTS.md` for the interfaces with B1, B3, A2/A3 and C2.
