
# SE6014 — Agentic Threat Hunting

**Nanyang Technological University (NTU)**  
**Course:** SE6014 Security Monitoring & Threat Detection  
**Project:** Question 1 — Agentic Threat Hunting on the ELK Stack  
**Group:** 7

---

## ⚠️ IMPORTANT: GitHub Collaboration Rules

- Do not push code directly to `main`.
- Work freely on your own feature branches.
- Submit a Pull Request (PR) when your code is ready.
- Get at least one other member to review and approve your PR before merging into `main`.
- Test your code before submitting a PR.
- Coordinate with other groups before modifying shared configurations, schemas or interfaces.
- Do not overwrite another member's work without prior discussion.

**Workflow:** Create Branch → Develop → Test → Push → Pull Request → Review → Merge into `main`

These rules apply to all team members, including group coordinators.

---

## 1. Project Overview

This project aims to develop an AI-assisted threat-hunting system using the ELK Stack (Elasticsearch, Logstash and Kibana), Model Context Protocol (MCP), and agentic AI.

The system aims to:

- Ingest logs through pull, push and stream methods.
- Support at least three distinct log formats.
- Automatically identify log formats and select or generate parsing schemas.
- Accept natural-language threat-hunting hypotheses.
- Investigate logs using AI agents and MCP tools.
- Generate evidence-backed verdicts and reports.
- Evaluate completeness, accuracy and repeatability.

Detailed tasks, responsibilities and milestones are available in the shared Team Plan Excel workbook.

**Project status:** Individual components are being implemented and tested. Full cross-group integration and end-to-end verification remain in progress.

---

## 2. Technology Stack

The following technologies and conventions are used or recommended for integration.

| Component | Technology / Standard |
|---|---|
| Programming Language | Python 3.11.x (common development recommendation) |
| SIEM / Log Management | Elasticsearch, Logstash, Kibana 8.19.23 |
| Containerization | Docker and Docker Compose |
| Agent Communication | Model Context Protocol (MCP) |
| Log Schema | Elastic Common Schema (ECS) |
| Common Input Format | JSON / NDJSON |
| Stream Transport | UDP with JSON event payloads (A3) |
| Schema Processing | Elasticsearch ingest pipelines |
| Format Recognition | Python-based recognizer |
| Version Control | Git and GitHub |
| AI Framework / Model | Configurable; final implementation choice to be documented |
| Operating Systems | Windows, macOS or Linux |

### Development Guidelines

- Use Python 3.11 where possible for consistency.
- Use Python virtual environments.
- Record dependencies in `requirements.txt`.
- Use mutually compatible ELK component versions.
- Prefer Docker for reproducible environments.
- Document software versions, setup instructions and configuration.
- Follow the agreed common schema and integration standards.
- Coordinate changes to shared interfaces.
- Test code before submitting pull requests.
- Never commit passwords, API keys, access tokens or private `.env` files.

---

## 3. Team Structure

The project has 10 members divided into three groups.

| Group | Members | Primary Responsibility |
|---|---|---|
| Group A | 3 | ELK Infrastructure & Log Ingestion |
| Group B | 3 | Agentic Log Processing |
| Group C | 4 | MCP & Agentic Threat Hunting |

### Group A — ELK & Ingestion

- **A1 — Ishaan:** ELK infrastructure, Docker setup, Elasticsearch access and repository configuration.
- **A2 — Akanksha:** Automatic pull ingestion, HTTP push ingestion, sender and verification.
- **A3 — Ria:** Stream ingestion, raw-log processing and event replay.

### Group B — Agentic Log Processing

- **B1 — Noor:** Format recognition, known parsing schemas and ECS fields.
- **B2 — Aryaman:** Unknown-schema generation, validation, registration and reuse.
- **B3 — Aryaman and Gurmehr:** Agentic source onboarding and ingestion orchestration.

### Group C — MCP & Threat Hunting

- **C1 — Xuelei:** Elasticsearch-facing MCP server and query tools.
- **C2 — Dat:** Threat-hunting agent, planning and analytics.
- **C3 — Rafi:** Evidence verification and report generation.
- **C4 — Ashvin:** Repeatability experiments and comparison.

Individual roles and tasks are maintained in the shared Excel workbook.

---

## 4. Common Log Schema

All groups should follow **Elastic Common Schema (ECS)** conventions wherever applicable.

The common schema includes the original README fields and additional fields proposed by B1 based on Apache and Windows datasets.

### 4.1 Common ECS Fields

| Field | Purpose |
|---|---|
| `@timestamp` | Event timestamp in UTC |
| `event.id` | Unique event identifier, where available |
| `event.dataset` | Log dataset identifier |
| `event.category` | Event classification |
| `event.type` | Event type |
| `event.action` | Activity performed |
| `event.outcome` | Event outcome |
| `event.code` | Event code, such as Windows Event ID |
| `event.original` | Original raw log record |
| `message` | Human-readable event description |
| `host.name` | Source hostname |
| `source.ip` | Source IP address |
| `source.port` | Source port |
| `destination.ip` | Destination IP address |
| `destination.port` | Destination port |
| `user.name` | Username |
| `process.name` | Process name |
| `process.executable` | Executable path |
| `process.pid` | Process identifier |
| `log.level` | Log severity |
| `http.request.method` | HTTP request method |
| `url.original` | Original observed URL or request target |
| `url.path` | URL path |
| `url.query` | URL query string, where available |
| `http.response.status_code` | HTTP response status |
| `http.response.body.bytes` | HTTP response body size |
| `http.request.referrer` | HTTP referrer |
| `user_agent.original` | Original user-agent string |

### 4.2 Required and Optional Fields

The following fields are required in a successfully normalized log event:

| Required Field | Purpose |
|---|---|
| `@timestamp` | Normalized event timestamp |
| `event.dataset` | Dataset/log format identifier |
| `event.original` | Original unmodified log record |
| `message` | Human-readable event description |

All other ECS fields are populated **when the source data allows**.

Examples:

- `host.name` — included when available from the log or reliable source metadata.
- `event.action` — derived when reliably identifiable; otherwise left unset.
- `event.code` — populated for Windows Event IDs where available.
- `process.name` and `process.executable` — populated for applicable process events.
- `source.ip` and `destination.ip` — populated for applicable network events.
- HTTP fields — populated for applicable web access events.

Missing optional fields should be documented when relevant, not fabricated.

**Important:** Raw input records do not need to contain all four required normalized fields. These fields must be populated or validated during parsing and normalization.

### 4.3 Schema Rules

- Normalize timestamps to UTC using ISO 8601.
- Preserve the original raw log record in `event.original`.
- Retain `message` as a human-readable description after parsing.
- Populate only fields applicable to each log format.
- Use ECS-compatible names and consistent data types.
- Represent `event.category` as an array.
- Preserve source metadata and event identifiers.
- Document any custom fields.
- Coordinate schema changes between groups.
- Do not reject an otherwise valid event solely because an optional field is missing.

### 4.4 Selected Log Formats

The following formats have been selected for Group B development and cross-group integration.

| Log Format | Source | Processing |
|---|---|---|
| Apache Access Logs | Web server | Elasticsearch ingest pipeline |
| Windows Event Logs | Sysmon and Windows Security | JSON-based ingest pipeline |
| Linux Authentication / Syslog | Linux authentication events | Elasticsearch parsing pipeline |
| Firewall Logs (additional) | Firewall/network events | Additional recognizer and pipeline |

**Notes:**

- Sysmon and Windows Security share one JSON layout and pipeline in B1's current implementation.
- Linux authentication/syslog is the selected third baseline format.
- Firewall logs are included as an additional supported format for integration and threat-hunting use cases.
- A3 will provide firewall sample records for B1's recognizer and pipeline development.
- More formats may be supported if required.

### 4.5 Source and Ingestion Metadata

For evidence traceability, preserve:

- `@timestamp` — event timestamp.
- `event.dataset` — dataset identifier.
- `event.id` — event identifier, where available.
- `event.original` — original log record.
- Elasticsearch `_index` and `_id` — retrievable document references.
- Ingestion method — pull, push or stream.
- Source identifier — originating file, endpoint or stream.

**Recommended transport metadata:**

- `labels.ingest_mode`
- `labels.source_id`

Existing development-specific fields may be mapped to these names during integration.

### 4.6 Schema Recognition and Processing

Group B is responsible for identifying log formats and selecting or generating appropriate schemas.

**Common workflow:**

1. Inspect representative input records.
2. Recognize the log format using B1's Python recognizer.
3. Select the appropriate Elasticsearch ingest pipeline.
4. If no schema matches, invoke B2's schema-generation workflow.
5. Validate generated schemas against representative records.
6. Register validated schemas for reuse.
7. Normalize records to ECS-compatible fields.
8. Verify successful indexing in Elasticsearch.

B1's format recognizer exposes:

```python
recognise(lines)
```

B3 coordinates source onboarding and connects the recognition workflow with Group A's ingestion routes.

### 4.7 Common Parsing Approach

**Recommended integrated approach: Elasticsearch ingest pipelines perform the primary parsing and normalization.**

This builds on B1's existing implementation and Group A's Logstash ingestion routes.

A3's Python parsers can be retained for independent validation by processing representative sample lines and comparing the extracted fields with Elasticsearch pipeline output.

The integrated workflow should avoid applying two independent parsers sequentially to the same record unless explicitly required.

---

## 5. Integration Standards

### 5.1 Group A ↔ Group B

Group A handles log transport, while Group B handles format recognition, schema selection/generation and normalization.

**Group A ingestion methods:**

- **Pull:** Automatic NDJSON file ingestion through Logstash.
- **Push:** HTTP ingestion using a Python sender.
- **Stream:** Continuous UDP transmission using JSON event payloads.

### Common Raw Input Format

Use the following JSON structure for a raw log line:

```json
{"message": "<raw log line>"}
```

For file-based ingestion, use one JSON object per line (NDJSON).

For HTTP push and UDP stream ingestion, use a corresponding JSON event payload.

Plain-text logs, including Apache, Linux and firewall records, may be wrapped in this format before entering the shared ingestion route.

### Recommended End-to-End Integration Flow

1. The user provides a log source.
2. B3 identifies the source and selects the ingestion route.
3. B1's `recognise(lines)` identifies the log format from representative records.
4. The corresponding Elasticsearch ingest pipeline is selected.
5. B2 handles unknown formats through schema generation and validation.
6. Group A ingests the events through pull, push or stream.
7. Logstash forwards events using the selected Elasticsearch ingest pipeline.
8. The Elasticsearch pipeline parses the raw record and populates ECS fields.
9. Elasticsearch stores the normalized events.
10. The workflow verifies successful indexing and record retrieval.

**Recommended pipeline selection:** B3 supplies a validated ingest-pipeline identifier to the ingestion workflow, and Logstash uses it when forwarding the corresponding records to Elasticsearch.

Only registered and approved pipeline identifiers should be selected.

The complete workflow will be verified during cross-group integration.

### 5.2 Group B ↔ Group C

Group B provides ECS-normalized records in Elasticsearch.

Group C consumes normalized records for threat hunting through MCP.

The shared interface should support:

- Index and source discovery.
- Field mapping discovery.
- Search and aggregation.
- Filtering by source, host, user, IP address and event type.
- Timestamp and coverage analysis.
- Retrieval of supporting event documents.
- Evidence and query traceability.

### 5.3 Group A ↔ Group C

Group A provides Group C with:

- Elasticsearch connection settings.
- Authentication and certificate requirements.
- Index naming conventions.
- Representative indexed security events.
- Example queries for MCP testing.

Elasticsearch-facing MCP tools should use read-only permissions and bounded queries.

### 5.4 Elasticsearch Index Naming

Current implementation patterns:

| Component | Index Pattern |
|---|---|
| A1 | `security-events-YYYY.MM.dd` |
| A2 Pull | `a2-pull-YYYY.MM.dd` |
| A2 Push | `a2-push-YYYY.MM.dd` |

**Recommended integrated index pattern:**

`security-events-YYYY.MM.dd`

Use `event.dataset` and ingestion metadata to distinguish log formats and ingestion modes.

Separate A2 indices may be retained for independent development and testing.

**Recommended Group C search pattern:** `security-events-*`.

The shared naming convention should be confirmed by A1, B1 and C1 before integrated indexing begins.

### 5.5 Group A Implementation Status

#### A1 — ELK Infrastructure

- Elasticsearch, Logstash and Kibana 8.19.23 tested locally.
- Docker environment and external `elastic` network configured.
- Elasticsearch HTTPS, authentication and CA certificate verification established.
- Sample events successfully indexed in Elasticsearch.
- Kibana search and visualization verified.
- Setup documentation and required prerequisites provided.

#### A2 — Pull and Push Ingestion

**Pull:**

- Logstash automatically monitors `group_A/a2/incoming/`.
- Newly added NDJSON files are picked up without restarting Logstash.
- Persistent processing state is maintained.

**Push:**

- Reusable Python sender.
- Logstash HTTP input on local port `8088`.
- JSON event transmission.
- Authenticated HTTPS output to Elasticsearch.

**Verification:**

- Two distinct pull events successfully indexed.
- Two distinct push events successfully indexed.
- Duplicate push submission did not increase the document count.
- Missing input files and malformed JSON were rejected by the sender.

Implementation and test evidence are documented in A2's README and PR #2.

#### A3 — Stream Ingestion and Replay

- Python-based UDP sender and receiver.
- JSON event payloads.
- Raw-log processing for Linux authentication, Apache and firewall logs.
- ECS-style event validation.
- Fixed sample events for reproducible replay.
- Local UDP stream and reliability tests.

**Verification status:** UDP streaming has been tested locally. End-to-end streaming through Logstash into Elasticsearch remains to be verified.

Implementation and tests are documented in PR #8.

### 5.6 Group B Implementation Status

#### B1 — Known Log Recognition and Parsing

B1 has reported local testing of:

- Elasticsearch ingest pipelines for Apache and Windows event formats.
- Python-based log-format recognition.
- 7,887 Windows event records parsed.
- 1,000,000 Apache access-log records parsed.
- Four known attack events identified in the test data.

Common ECS field definitions and Apache pipeline documentation are included in B1's open pull requests.

**Next integration activities:**

- Extend parsing support for Linux authentication/syslog.
- Add firewall recognition and parsing using A3's samples.
- Preserve raw records in `event.original`.
- Retain readable descriptions in `message`.
- Connect known-format recognition with Group A ingestion.

#### B2 — Unknown-Schema Generation

Responsible for:

- Identifying formats without matching schemas.
- Generating candidate schemas.
- Validating proposed schemas against sample records.
- Registering and versioning validated schemas.
- Reusing previously registered templates.

#### B3 — Agentic Source Onboarding

Responsible for:

- Accepting source information.
- Selecting the appropriate ingestion route.
- Invoking format recognition and schema handling.
- Coordinating pipeline selection.
- Verifying successful indexing.
- Recording workflow decisions and errors.

### 5.7 Recommended Integration Sequence

1. Finalize ECS fields and common log formats.
2. Confirm index naming and source metadata.
3. Connect Group A ingestion with Group B parsing.
4. Verify normalized records in Elasticsearch.
5. Connect Group C's MCP tools.
6. Execute one complete hypothesis-based threat hunt.
7. Perform repeatability experiments.
8. Record evidence for the final report and demonstration.

---

## 6. MCP and Agentic Threat-Hunting Standards

The following recommended interfaces are based on C2's threat-hunting agent design.

### 6.1 MCP Tools

**C1 — Elasticsearch MCP Server**

Recommended tools:

- `list_indices`
- `get_field_mapping`
- `get_time_coverage`
- `count`
- `search`
- `aggregate`
- `get_documents`

These tools provide controlled, read-only access to Elasticsearch.

**C2 — Hunt Analytics MCP Server**

Proposed tools:

- `gap_check`
- `burst_detect`
- `beacon_score`
- `rare_values`

These tools support deterministic analysis of retrieved evidence.

### 6.2 Agentic Workflow

The proposed agentic workflow is:

1. Accept a natural-language hypothesis.
2. Convert it into a structured hunt specification.
3. Identify relevant ATT&CK techniques, sources and time windows.
4. Discover available Elasticsearch data and mappings.
5. Select a matching playbook or generate a bounded plan.
6. Check planned investigation coverage.
7. Execute MCP queries and analytics.
8. Retrieve supporting and contradictory evidence.
9. Produce an evidence-backed verdict.
10. Verify evidence references and generate the hunt report.

### 6.3 Evidence Requirements

Every finding should be traceable through:

- Query ID.
- MCP tool name.
- Elasticsearch index.
- Document ID.
- Event timestamp.
- Query parameters and time window.
- Relevant ECS fields.
- Coverage and error information.

The system should distinguish supported findings from unsupported claims and insufficient evidence.

### 6.4 Threat-Hunting Playbooks

C2's proposed playbooks include:

| Playbook | Hypothesis | Relevant Logs |
|---|---|---|
| PB-01 | SSH brute force / password spraying | Linux authentication and firewall |
| PB-02 | Web scanning / exploitation attempts | Apache access and firewall |
| PB-03 | Internal port scanning | Firewall |

**Recommended initial hypothesis:** Select a playbook supported by B1's labelled attack data and available event fields.

A web-related hypothesis is a practical starting point if the Apache dataset contains sufficient known attack evidence.

The final hypothesis should include a fixed dataset, time window and ground-truth evidence.

### 6.5 Guardrails and Safety Controls

The system should:

- Use bounded and validated Elasticsearch queries.
- Restrict access to approved indices and fields.
- Treat log content as untrusted data.
- Prevent untrusted log text from becoming agent instructions.
- Check coverage of relevant data sources and time windows.
- Link claims to retrievable evidence.
- Avoid fabricated event counts or evidence references.
- Return `INCONCLUSIVE` or `INSUFFICIENT_DATA` when appropriate.
- Record MCP tool calls and query traces.
- Provide advisory recommendations without automatically executing defensive actions.

### 6.6 Repeatability Experiment

The project requires executing the same hypothesis-based hunt twice.

Record and control:

- Hypothesis text.
- Dataset and fixture version.
- Fixed time window.
- Model and version.
- Prompts and configuration.
- MCP tool interfaces.
- Elasticsearch index snapshot.
- Relevant run settings.

Compare:

- Verdicts.
- Supporting evidence IDs.
- Data-source and time-window coverage.
- Queries and tool calls.
- Differences between runs.
- Changes made to improve convergence.

Save both reports and the comparison for the final project report.

---

## 7. Repository Structure

The project is organized into three workstreams:

```text
SE6014-Agentic-Threat-Hunting/
├── group_A/
├── group_B/
├── group_C/
├── .gitignore
└── README.md
```

Each group maintains implementation files, tests and documentation in its respective directory.

Additional shared files and directories may be added through reviewed pull requests.

---

## 8. Common Technical Standards and Integration Decisions

The following table summarizes the agreed development direction and recommended integration choices.

| Shared Decision | Common Standard / Recommendation | Responsible Members |
|---|---|---|
| ELK version | Elasticsearch, Logstash, Kibana 8.19.23 | A1 |
| Programming language | Python 3.11.x | All groups |
| Log formats | Apache, Windows JSON, Linux auth/syslog; firewall additional | B1, B3, A3 |
| Required normalized fields | `@timestamp`, `event.dataset`, `event.original`, `message` | B1, A3, C1 |
| Optional ECS fields | Populate where source data allows | B1, A3, C1 |
| Raw input | JSON/NDJSON with `message` containing raw line | A2, A3, B1, B3 |
| Primary parser | Elasticsearch ingest pipelines | B1, A2, A3, B3 |
| Independent parser validation | A3 Python parsers | A3, B1 |
| Known schemas | B1's Elasticsearch ingest pipelines | B1 |
| Unknown schemas | Generate → validate → register → reuse | B2, B3 |
| Source onboarding | Python workflow with format recognition | B3 |
| Pipeline selection | `recognise(lines)` → validated pipeline ID → Logstash/Elasticsearch | B1, B3, A2 |
| Stream transport | UDP with JSON payloads | A3 |
| Integrated indices | `security-events-YYYY.MM.dd` (recommended) | A1, B1, C1 |
| Source metadata | ECS event fields and agreed ingestion identifiers | A1, A2, A3, B1 |
| MCP interfaces | Read-only Elasticsearch tools and deterministic analytics | C1, C2 |
| Evidence references | Index, document ID, timestamp and query ID | C1, C2, C3 |
| Hunting hypothesis | C2 playbook supported by labelled test data | B1, C2, C4 |
| Repeatability | Same hypothesis, fixed fixture, two runs and comparison | A3, C2, C3, C4 |
| Integration | Reviewed PRs and staged end-to-end testing | All groups |

Changes affecting shared technical standards should be coordinated with the relevant component owners and documented in the shared Major Decisions spreadsheet.

---

## 9. Documentation & Security

Maintain records in the shared **SE6014 Technical Work & Evidence Log**.

- Record implementation details, test results and observations.
- Document troubleshooting steps and limitations.
- Include screenshots, queries and representative log excerpts.
- Link relevant GitHub commits or pull requests.
- Keep individual contributions traceable.
- Document dataset sources, licences and ground truth.
- Never commit passwords, API keys, tokens, private `.env` files or sensitive logs.
- Use approved public or synthetic datasets.

The technical work log is a working document. Members should update their assigned sections as development progresses.

---

## 10. Important Notes

- Refer to the Team Plan Excel workbook for assignments and milestones.
- Use the Technical Work & Evidence Log to document implementation and experiments.
- Maintain consistent ECS fields and integration interfaces across groups.
- Coordinate technical changes affecting other members.
- Test and review all contributions before merging into `main`.
- Confirm integration through reproducible end-to-end testing.
- Record the system's actual capabilities and limitations accurately.

---

**SE6014 | Security Monitoring & Threat Detection**  
**Nanyang Technological University — Group 7, Question 1**
