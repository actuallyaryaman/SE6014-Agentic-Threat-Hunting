
# SE6014 — Agentic Threat Hunting

**Nanyang Technological University (NTU)**  
**Course:** SE6014 Security Monitoring & Threat Detection  
**Project:** Question 1 — Agentic Threat Hunting on the ELK Stack

---

## ⚠️ IMPORTANT: GitHub Collaboration Rules

- **Do not push code directly to `main`.**
- Work freely on your own feature branches.
- Submit a **Pull Request (PR)** when your code is ready.
- Get at least **one other member to review and approve** your PR before merging into `main`.
- Test your code before submitting a PR.
- Coordinate with other groups before modifying shared configurations, schemas or interfaces.
- Do not overwrite another member's work without prior discussion.

**Workflow:** Create Branch → Develop → Test → Push → Pull Request → Review → Merge into `main`

*These rules apply to all team members, including group coordinators.*

---

## 1. Project Overview

This project aims to develop an **AI-assisted threat-hunting system** using the ELK Stack (Elasticsearch, Logstash and Kibana), Model Context Protocol (MCP), and agentic AI.

The system will:
- Ingest logs through pull, push and stream methods.
- Support at least three distinct log types.
- Automatically identify log formats and select or generate parsing schemas.
- Accept natural-language threat-hunting hypotheses.
- Investigate logs using AI agents and MCP tools.
- Generate evidence-backed verdicts and reports.
- Evaluate completeness, accuracy and repeatability.

**Detailed tasks, responsibilities and milestones are available in the shared Team Plan Excel workbook.**

---

## 2. Technology Stack

The following are proposed common technical standards.

| Component | Technology / Standard |
|---|---|
| Programming Language | Python 3.11.x |
| SIEM / Log Management | Elasticsearch, Logstash, Kibana |
| Containerization | Docker and Docker Compose |
| Agent Communication | Model Context Protocol (MCP) |
| Log Schema | Elastic Common Schema (ECS) |
| Data Format | JSON / NDJSON |
| Version Control | Git and GitHub |
| AI Framework / Model | To be finalized by Groups B and C |
| Operating Systems | Windows, macOS or Linux |

### Development Guidelines

- Use **Python 3.11** for consistency.
- Use Python virtual environments.
- Record dependencies in `requirements.txt`.
- Use mutually compatible ELK component versions.
- Prefer Docker for consistent development environments.
- Document software versions and setup instructions.
- Agree on shared configurations before integration.

---

## 3. Team Structure

The project has **10 members divided into three groups**.

| Group | Members | Primary Responsibility |
|---|---|---|
| **Group A** | 3 | ELK Infrastructure & Log Ingestion |
| **Group B** | 3 | Agentic Log Processing |
| **Group C** | 4 | MCP & Agentic Threat Hunting |

Each group has its own directory and README containing its responsibilities.

Individual roles and tasks are maintained in the shared Excel workbook.

---

## 4. Common Log Schema

All groups should follow **Elastic Common Schema (ECS)** conventions wherever applicable.

### Core Fields

| Field | Purpose |
|---|---|
| `@timestamp` | Event timestamp in UTC |
| `event.dataset` | Log dataset identifier |
| `event.category` | Event classification |
| `event.action` | Activity performed |
| `event.outcome` | Event outcome |
| `event.original` | Original raw log record |
| `message` | Human-readable description |
| `host.name` | Source hostname |
| `source.ip` | Source IP address |
| `destination.ip` | Destination IP address |
| `user.name` | Username |
| `process.name` | Process name |
| `log.level` | Log severity |

### Schema Rules

1. Normalize timestamps to UTC using ISO 8601.
2. Preserve original log records for verification.
3. Use ECS-compatible field names and consistent data types.
4. Populate only applicable fields for each log type.
5. Document custom fields and source metadata.
6. Coordinate schema changes between groups.

### Proposed Log Types

- Linux authentication logs
- Apache / Nginx web server logs
- Firewall or network syslog records

**Note:** Final log types, datasets and schema mappings must be agreed upon by all groups before integration.

---

## 5. Integration Standards

### Group A ↔ Group B
- Agree on log formats, source metadata and ingestion interfaces.
- Ensure records are correctly parsed before indexing into Elasticsearch.

### Group B ↔ Group C
- Provide ECS-normalized records in Elasticsearch.
- Agree on field mappings and index naming conventions.

### Group A ↔ Group C
- Coordinate Elasticsearch access and connection settings.
- Provide sample indexed logs for independent MCP testing.

**Parallel Development:** Groups may work independently using agreed interfaces and sample data. Integration should begin early.

---

## 6. Repository Structure

```text
SE6014-Agentic-Threat-Hunting/
├── group_A/
│   ├── infrastructure/
│   └── ingestion/
├── group_B/
│   ├── log_recognition/
│   ├── schema_generation/
│   └── agentic_ingestion/
├── group_C/
│   ├── mcp_server/
│   ├── threat_hunting/
│   └── experiments/
├── tests/
├── docs/
├── .gitignore
└── README.md
```

*Directory structure may be adjusted during development.*

---

## 7. Documentation & Security

- Maintain records in the shared **SE6014 Technical Work & Evidence Log**.
- Record implementation details, test results, observations, issues and relevant screenshots.
- Include GitHub commit or pull-request references where applicable.
- Keep individual contributions traceable.
- **Never commit passwords, API keys, access tokens, private `.env` files or sensitive logs.**
- Use approved public or synthetic datasets.

The technical work log is a working document. Members should update their assigned table cells as development progresses.

---

## 8. Important Notes

- Refer to the **Team Plan Excel workbook** for individual assignments, technical tasks and milestones.
- Use the **Technical Work & Evidence Log** to document implementation and experimental findings.
- Agree on software versions, log types, schema mappings and integration interfaces before combining components.
- Communicate changes affecting other groups.
- Test and review all contributions before merging into `main`.

---

**SE6014 | Security Monitoring & Threat Detection**  
*Nanyang Technological University — Question 1*
