NTU | SE6014 Security Monitoring & Threat Detection

Project: Question 1 – Agentic Threat Hunting on the ELK Stack

1. Project Overview

This project aims to develop an AI-assisted threat-hunting system using the ELK Stack (Elasticsearch, Logstash and Kibana), Model Context Protocol (MCP), and agentic AI.

The system should:

- Ingest logs through pull, push and stream methods.
- Support at least three distinct log types.
- Automatically identify log formats and apply appropriate parsing schemas.
- Generate and validate new schemas when existing templates are unavailable.
- Accept threat-hunting hypotheses in natural language.
- Use an AI agent and MCP tools to investigate logs.
- Generate evidence-backed threat-hunting reports with queries and verdicts.
- Evaluate accuracy, completeness and repeatability through experiments.

2. Technology Stack

The following are proposed common standards for all members.

Component| Technology / Standard
Programming language| Python 3.11.x
SIEM / Log management| Elasticsearch, Logstash, Kibana
Containerization| Docker and Docker Compose
Agent communication| Model Context Protocol (MCP)
Log schema| Elastic Common Schema (ECS)
Data interchange| JSON / NDJSON
Version control| Git and GitHub
AI framework / Model| To be finalized by Groups B and C
Operating systems| Windows, macOS or Linux with compatible tools

Important:

- Everyone should use Python 3.11 for consistency.
- Use a Python virtual environment for dependencies.
- The ELK components must use mutually compatible versions, preferably the same release version.
- The exact ELK, MCP SDK and library versions will be finalized and documented by the respective groups.
- Keep dependencies documented in "requirements.txt" or the relevant component requirements file.
- Docker is recommended for consistent development across operating systems.

3. Team Structure

Group A — ELK Infrastructure & Log Ingestion (3 Members)

Responsibilities:

- Configure Elasticsearch, Logstash and Kibana.
- Implement pull ingestion.
- Implement push ingestion.
- Implement stream ingestion.
- Test log collection, reliability and indexing.

Group B — Agentic Log Processing (3 Members)

Responsibilities:

- Identify incoming log formats.
- Create and select known parsing schemas.
- Automatically generate schemas for unknown log formats.
- Validate generated schemas and register them for future use.
- Implement the agentic ingestion and parsing workflow.

Group C — MCP & Agentic Threat Hunting (4 Members)

Responsibilities:

- Develop the MCP server and search/aggregation tools.
- Implement natural-language hypothesis interpretation.
- Build the AI threat-hunting workflow.
- Verify evidence and prevent unsupported conclusions.
- Generate threat-hunting reports.
- Conduct repeatability experiments and compare results.

4. Common Log Schema

All groups must use a consistent normalized log structure to avoid integration problems.

We will follow Elastic Common Schema (ECS) field conventions wherever applicable.

Core Fields

Field| Purpose| Example
"@timestamp"| Event timestamp in UTC| "2026-10-18T10:30:00Z"
"event.dataset"| Identifies the log dataset| "apache.access"
"event.category"| Event classification| "web"
"event.action"| Activity performed| "user_login"
"event.outcome"| Event outcome| "success"
"event.original"| Original raw log record| Original log text
"message"| Human-readable event message| "Login successful"
"host.name"| Source hostname| "server01"
"source.ip"| Source IP address| "192.0.2.10"
"destination.ip"| Destination IP address| "198.51.100.20"
"user.name"| Username, if available| "admin"
"process.name"| Process name, if available| "sshd"
"log.level"| Log severity, if available| "warning"

Schema Rules

1. Normalize timestamps to UTC using ISO 8601.
2. Preserve original log records for verification.
3. Use ECS-compatible field names whenever possible.
4. Not all fields are required for every log type. Populate only applicable fields.
5. Use consistent data types (IP address, date, keyword, etc.) across Elasticsearch mappings.
6. Include source metadata to identify the originating dataset and ingestion method.
7. Document any custom fields that do not belong to ECS.
8. Group B is responsible for maintaining and validating parsing schemas, in coordination with Group A.

Log Types

The project requires at least three distinct log types.

Suggested examples:

- Linux authentication logs
- Apache/Nginx web server logs
- Firewall or network syslog records

The final three log types and their sample datasets must be agreed upon by all groups before integration.

5. Integration Standards

To ensure independent development, the following interfaces must remain consistent.

Group A → Group B

- Provide raw log records and their source metadata.
- Agree on input formats and ingestion interfaces.
- Coordinate automatic parsing before Elasticsearch indexing.

Group B → Group C

- Provide ECS-normalized log records indexed in Elasticsearch.
- Maintain agreed field mappings and index names.
- Document supported log formats and parsing limitations.

Group A → Group C

- Provide Elasticsearch access configuration.
- Agree on index naming conventions.
- Provide sample indexed records for independent testing.

Group C can begin development using sample indexed logs before the full ingestion pipeline is completed.

6. Proposed Repository Structure

The following structure will be created and adjusted as required:

- "group_A/"
  - "infrastructure/" — ELK and Docker configuration
  - "ingestion/" — Pull, push and stream ingestion
- "group_B/"
  - "log_recognition/" — Log identification and known schemas
  - "schema_generation/" — Automatic schema generation and validation
  - "agentic_ingestion/" — Ingestion orchestration
- "group_C/"
  - "mcp_server/" — MCP tools and interfaces
  - "threat_hunting/" — Agent and investigation workflow
  - "experiments/" — Reports and repeatability testing
- "tests/" — Shared test cases and sample log records
- "docs/" — Documentation and integration details
- "README.md" — Common project guidelines
- ".gitignore" — Files excluded from Git

7. GitHub Collaboration Guidelines

All 10 members will contribute to one shared GitHub repository.

Branching Rules

- The "main" branch contains stable integrated code.
- Each member should create a separate feature branch.
- Example branch names:
  - "feature/a2-pull-ingestion"
  - "feature/b1-log-recognition"
  - "feature/c2-threat-hunting"
- Submit a pull request when a component is ready.
- At least one other member should review changes before merging.
- Do not directly modify another member's component without coordinating.

General Rules

- Commit changes regularly with meaningful messages.
- Include setup instructions for your component.
- Test code before submitting pull requests.
- Report integration issues as soon as they occur.
- Do not upload passwords, API keys, tokens, private ".env" files or real sensitive logs.
- Store only approved or synthetic test data in the repository.
- Record individual contributions for the final project timesheet.

8. Integration and Testing

The final integrated system must demonstrate:

- Working pull, push and stream ingestion.
- Successful ingestion of at least three distinct log types.
- Automatic schema selection, generation and validation.
- An MCP server exposing required Elasticsearch capabilities.
- An AI agent planning and executing a complete hypothesis-based hunt.
- Evidence-backed reports containing verdicts and executed queries.
- Guardrails against hallucinations and unsupported findings.
- Two runs of the same hypothesis, with results compared and differences explained.

9. Project Deliverables

Deliverable 1 — Final Project Report (60%)

Includes:

- Executive summary
- System architecture and data flow
- Setup and implementation documentation
- Agentic workflow and safety controls
- Experiments and comparative results
- Limitations and future improvements
- Repository URL
- Individual contribution timesheet and work breakdown

Deliverable 2 — Live Demo & Shark Tank Pitch (40%)

- 5-minute technical demonstration
- 5-minute product pitch
- Q&A session

Each group is responsible for documenting and testing its assigned technical components. Final integration, report consolidation and presentation responsibilities will be coordinated across the team.

---

Note: Technology versions, log types, schemas and integration interfaces should be finalized jointly before implementation. Changes affecting other groups must be communicated before adoption.
