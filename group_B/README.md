# Group B - Agentic Log Processing

## Team Members

| Role | Name | Responsibility |
|---|---|---|
| B1 | Noor Al Ibrahim | Log Recognition + Known Schemas |
| B2 | Aryaman Srivastava | Unknown Schema Creation |
| B3 | Aryaman Srivastava, Gurmehr Singh | Agentic Source Onboarding |

## Responsibilities

### B1 - Log Recognition + Known Schemas
- Define the shared normalized log fields using ECS.
- Create parsing templates for the three selected log types.
- Implement automatic recognition of known log formats.
- Select and apply the appropriate parsing schema.
- Test field extraction and malformed log handling.

### B2 - Unknown Schema Creation
- Detect log formats without an existing schema.
- Develop agent-driven generation of new parsing schemas.
- Validate generated schemas against sample records.
- Save and register validated schemas for future reuse.
- Handle schema generation and validation failures.

### B3 - Agentic Source Onboarding
- Implement the workflow for accepting a user-specified log source.
- Identify the source type and appropriate ingestion method.
- Coordinate ingestion with Group A.
- Invoke schema recognition or generation as required.
- Record ingestion decisions, errors and outcomes.
- Test the complete agentic onboarding workflow.

## Integration Requirements

### Group A - ELK & Ingestion
- Coordinate log source formats and ingestion interfaces.
- Ensure parsed records can be indexed in Elasticsearch.
- Agree on source metadata and error handling.

### Group C - MCP & Threat Hunting
- Provide ECS-normalized logs in Elasticsearch.
- Document field mappings and index names.
- Ensure parsed records support threat-hunting queries.

## Testing Requirements
- Successfully recognize all selected known log formats.
- Validate extracted fields against expected values.
- Generate and validate a schema for an unknown format.
- Demonstrate reuse of registered schemas.
- Test the full source onboarding workflow.
- Record test results and errors.

## Collaboration
- Follow the Python version and ECS conventions in the main README.
- Use separate feature branches for each member.
- Document code, dependencies and test results.
- Coordinate interface changes with Groups A and C.
- Submit pull requests before merging into main.

## Implementation Layout

| Path | Purpose |
|---|---|
| `common/` | Shared models, errors and the B1 `recognise(lines)` adapter |
| `schema_generation/` | B2 unknown-schema detection, generation, validation and registry |
| `agentic_ingestion/` | B3 source inspection, ingestion planning, adapters and verification |
| `tests/` | Offline unit tests and OTRF fixtures |
| `CONTRACTS.md` | Shared interfaces with B1, B3, A2/A3 and C2 |
| `requirements.txt` | Pinned Python dependencies |

Run the offline tests from this directory:

```bash
python -m pytest
```

The tests do not require Elasticsearch or an LLM API key. Tests that need
live services must use `@pytest.mark.integration` and are selected explicitly
with `python -m pytest -m integration`.

From the repository root, verify the committed OTRF fixture hashes:

```bash
python group_B/scripts/fetch_otrf_fixtures.py --check
```

The fixture provenance, upstream commit, ATT&CK mappings and licence note are
in `tests/fixtures/otrf/`.

## B3 Batches 5–6

`agentic_ingestion` provides bounded inspection, read-only planning, opt-in
pull/push/direct execution, independent Elasticsearch verification and JSONL
audit evidence. The CLI adds `onboard` (dry-run by default, `--execute` for
writes) and `verify`. Stream execution remains blocked pending A3 agreement.
See [the B3 README](agentic_ingestion/README.md) for configuration and failure
semantics, and [live ES results](tests/LIVE_ES_RESULTS.md) for isolated indexing
and replay evidence. The unchanged A1/A2 configurations now also pass an
isolated authenticated HTTPS integration run; see
[the integration results](tests/A1_A2_INTEGRATION_RESULTS.md). Access to the
shared deployment, A3 agreement and the complete hunting demo remain.


## Independent local hunt demo

The [demo runbook](DEMO_RUNBOOK.md) exercises B3 → actual A2 → HTTPS ES →
C2's existing development MCP servers → a rules-based SSH hunt. It needs no
shared credentials or live LLM. The [recorded results](tests/ONBOARDING_HUNT_RESULTS.md)
include positive/negative cases, exact planted-event evidence and repeatability.
The final C1/C3 services and A3 agreement remain separate integration work.
