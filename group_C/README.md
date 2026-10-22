# Group C - MCP & Agentic Threat Hunting

## Team Members

| Role | Name | Responsibility |
|---|---|---|
| C1 | xuelei wu | MCP Server + ELK Tools |
| C2 | VU TUAN DAT | Threat-Hunting Agent |
| C3 | Rafi Dasa Nanda Putra | Evidence + Report Generation |
| C4 | Ashvin Kalaivanan | Experiments + Repeatability |

## Responsibilities

### C1 - MCP Server + ELK Tools
- Build an MCP server that connects to Elasticsearch.
- Expose search and aggregation functions as MCP tools.
- Implement additional tools required for threat hunting.
- Validate tool inputs and handle errors.
- Test tool execution and returned results.

### C2 - Threat-Hunting Agent
- Accept natural-language threat-hunting hypotheses.
- Develop agentic planning and investigation workflows.
- Use MCP tools to execute Elasticsearch queries.
- Test hypotheses against the available log evidence.
- Coordinate with C3 to produce supported verdicts.

### C3 - Evidence + Report Generation
- Link investigation findings to retrievable log evidence.
- Record all queries executed during each investigation.
- Generate hunt reports containing verdicts and evidence.
- Check for missing or unsupported claims.
- Implement safeguards against hallucinated findings.

### C4 - Experiments + Repeatability
- Automate two runs of the same threat-hunting hypothesis.
- Collect and compare the generated reports.
- Measure consistency of verdicts, queries and evidence.
- Investigate differences between runs.
- Document improvements made to increase repeatability.

## Integration Requirements

### Group A - ELK & Ingestion
- Obtain Elasticsearch connection details.
- Agree on index names and available log sources.
- Verify access to successfully ingested logs.

### Group B - Agentic Log Processing
- Use normalized ECS-compatible fields.
- Agree on Elasticsearch field mappings.
- Confirm which log formats and fields are supported.

## Testing Requirements
- Verify that MCP search and aggregation tools work.
- Demonstrate a complete hypothesis-based threat hunt.
- Produce reports containing verdicts, evidence and queries.
- Verify claims against actual Elasticsearch results.
- Run the same hypothesis twice.
- Compare results and document differences.
- Test error handling and hallucination safeguards.

## Collaboration
- Follow the Python version and ECS conventions in the main README.
- Use separate feature branches for each member.
- Document code, dependencies and test results.
- Coordinate interface changes with Groups A and B.
- Submit pull requests before merging into main.
