# B3 — Agentic Source Onboarding

This package implements the B3 lifecycle:

```text
accept a source
  -> inspect and sample it
  -> recognise the format (B1)
  -> resolve or generate a schema (B2)
  -> select pull / push / stream / direct-ES
  -> hand off to A2/A3
  -> verify the documents in Elasticsearch
  -> write an audit trail
```

## Planned modules

| Module | Responsibility |
|---|---|
| `cli.py` | `onboard`, `verify`, `--dry-run`, `--json` |
| `inspect.py` | File/HTTP/UDP inspection and format candidates |
| `planner.py` | Ingestion route and pipeline selection |
| `adapters/` | `file_drop`, `http_push`, `stream`, `direct_es` |
| `verify.py` | Counts, parse failures, timestamps and sample retrieval |
| `audit.py` | JSONL run records |

## Batch status

- Batch 0: package scaffold only.
- Batch 5: source inspection and planner.
- Batch 6: adapters, verification and audit.
- Batch 7: end-to-end integration and demo.

See `group_B/CONTRACTS.md` for the A2/A3 transport and pipeline-ID contracts.
