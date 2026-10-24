# A1 Handover — ELK Infrastructure and Repository/CI

## 1. Role and Responsibilities

**Owner:** Ishaan Deep Singh  
**Component:** A1 — ELK Infrastructure + Repository/CI

A1 is responsible for providing the Elasticsearch, Logstash, and Kibana infrastructure used by the Agentic Threat Hunting project. The setup supports ingestion, storage, and visual inspection of security events.

## 2. Architecture

The local development pipeline is:

1. Sample security events are read from `group_A/sample-data/security-events.ndjson`.
2. Logstash reads and processes the events using `group_A/logstash/pipeline/logstash.conf`.
3. Logstash sends the processed events to Elasticsearch over HTTPS with authentication.
4. Elasticsearch stores the events in daily indices named `security-events-YYYY.MM.dd`.
5. Kibana provides the Discover interface for searching and inspecting indexed events.

## 3. Current Verification Status

The following checks have been completed locally:

- Elasticsearch container is running.
- Logstash container is running.
- Kibana is accessible at `http://localhost:5601`.
- Elasticsearch contains three sample security-event documents.
- The Kibana data view `Security Events` uses the pattern `security-events-*`.
- Discover displays all three sample documents after configuring the appropriate timestamp range.
- Logstash pipeline configuration validation succeeded.
- Repeated ingestion checks returned three documents for the sample index, demonstrating duplicate prevention for the current sample events.

These are local verification results. GitHub Actions CI has been added but still needs to run successfully.

## 4. Important Repository Paths

- `group_A/docker-compose.local.yaml` — local Logstash and Kibana Compose configuration.
- `group_A/docker-compose.yaml` — shared Compose configuration; review before using it.
- `group_A/logstash/pipeline/logstash.conf` — Logstash input, processing, and output.
- `group_A/sample-data/security-events.ndjson` — synthetic test events.
- `.env.example` — placeholder configuration for required environment variables.
- `.github/workflows/ci.yml` — automated repository validation.
- `.gitignore` — excludes local secrets and certificates.

## 5. Viewing Events in Kibana

1. Open `http://localhost:5601`.
2. Open Discover.
3. Select the `Security Events` data view.
4. Set a time range that includes the sample event timestamps from 18 October 2026.
5. Clear any unwanted filters or search queries.
6. Confirm that the sample documents appear.

The current sample events represent a failed logon, a process-creation event, and an HTTP 401 response.

## 6. Configuration and Security

- Keep the root `.env` file local and do not commit it.
- Do not commit Elasticsearch passwords, Kibana service-account tokens, or private credentials.
- Keep the local CA certificate under `certs/`; this directory is ignored by Git.
- Share only placeholder values through `.env.example`.
- Keep Elasticsearch security enabled and use authenticated HTTPS connections.
- Do not copy another developer's passwords or service tokens into the repository.

The current local configuration has used a Docker-network IP address for Elasticsearch. This address may change when the network or containers are recreated. Before sharing the setup, the team should agree on a stable hostname and certificate configuration.

## 7. CI Workflow

The workflow at `.github/workflows/ci.yml` is intended to run on pushes and pull requests. It checks:

- YAML parsing of both Compose files.
- JSON validity of each non-empty line in the sample NDJSON file.
- Presence of required project files.

These checks do not prove that containers start correctly, that TLS authentication succeeds, or that the complete ingestion pipeline works. Those checks must still be performed in the development environment.

## 8. Known Limitations and Follow-up Work

- Review `group_A/docker-compose.yaml` before using it; ensure it agrees with the secure local configuration and current Elasticsearch version.
- Replace environment-specific IP addresses with a team-agreed, certificate-valid hostname or configuration.
- Confirm that `.env.example` documents every required variable without containing real credentials.
- Run the GitHub Actions workflow and resolve any failures.
- Document the agreed setup and ingestion interface for Groups B and C.
- Confirm that the event fields conform to the team's agreed event schema.
- The current Elasticsearch container has no mounted data volume. Indexed data may be lost if the container is removed.
- The current Elasticsearch container has restart policy no; automatic restart after a Docker daemon restart is not configured.

## 9. Integration Notes for Groups B and C

Coordinate with A1 before changing Elasticsearch connectivity, index naming, authentication, TLS certificates, or shared Compose networking.

Group B and Group C should agree on their ingestion interface with A1 before integrating their components. Use synthetic or approved test events during validation.

**Handover status:** Core local ELK functionality verified; repository CI, shared Compose review, and final team integration remain to be completed.