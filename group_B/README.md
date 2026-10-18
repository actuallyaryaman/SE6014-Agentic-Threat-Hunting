# Group B - Agentic Log Processing

## Team Members

| Role | Name | Responsibility |
|---|---|---|
| B1 | Noor Al Ibrahim | Log Recognition + Known Schemas |
| B2 | Aryaman Srivastava | Unknown Schema Creation |
| B3 | Aryaman Srivastava, Ashvin Kalaivanan | Agentic Source Onboarding |

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
