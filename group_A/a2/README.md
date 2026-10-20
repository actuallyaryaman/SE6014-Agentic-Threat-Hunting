# A2 — Pull and Push Log Ingestion

**Module:** SE6014 — Security Monitoring and Threat Detection
**Project:** Agentic Threat Hunting on the ELK Stack
**Component:** A2 — Pull and Push Ingestion (T05–T08)

## 1. Overview

This component implements two log-ingestion methods using Logstash 8.19.23 and Elasticsearch.

- **Pull ingestion:** Automatically discovers and processes NDJSON log files placed in a monitored directory.
- **Push ingestion:** Accepts JSON security events through a local HTTP endpoint using a Python sender.

Both methods use HTTPS with CA verification and credentials when forwarding events to Elasticsearch.

## 2. Project Structure

| Path | Purpose |
|---|---|
| `pipeline/pull.conf` | Logstash pull-ingestion configuration |
| `push-pipeline/push.conf` | Logstash HTTP push-ingestion configuration |
| `incoming/` | Monitored directory for new NDJSON files |
| `samples/` | Sample security events for pull testing |
| `tools/push_sender.py` | Python HTTP event sender |
| `tools/push-test.json` | First push-test event |
| `tools/push-test-2.json` | Second push-test event |
| `tools/invalid-test.json` | Malformed JSON test fixture |
| `../docker-compose.pull.yaml` | Docker Compose configuration for A2 |

## 3. Prerequisites

- Docker Desktop and Docker Compose
- Python 3.11 or compatible Python 3
- Running Elasticsearch 8.19.23 connected to Docker network `elastic`
- Root `.env` file containing local Elasticsearch connection settings
- Root `certs/http_ca.crt` from the local Elasticsearch environment

The Elasticsearch URL must match a valid hostname or IP address in its TLS certificate. Credentials and certificates must not be committed.

## 4. Start A2 Services

Run from the repository root:

```bash
docker compose --env-file .env -f group_A/docker-compose.pull.yaml config --quiet
docker compose --env-file .env -f group_A/docker-compose.pull.yaml up -d
```

The services are:

- `logstash-a2-pull`
- `logstash-a2-push`

The push endpoint is available locally at `http://127.0.0.1:8088`.

## 5. Pull Ingestion

Copy an NDJSON sample into the monitored directory:

```bash
cp group_A/a2/samples/a2-pull-test.ndjson group_A/a2/incoming/
```

The running Logstash file input discovers the new file and ingests its contents automatically.

Files are read as complete inputs. Processing state is stored in a Docker volume, and completed files are preserved.

**Elasticsearch index:** `a2-pull-YYYY.MM.dd`

## 6. Push Ingestion

Send a security event using Python:

```bash
python group_A/a2/tools/push_sender.py group_A/a2/tools/push-test.json
```

The sender validates the JSON document and submits it to the local Logstash HTTP input.

**Elasticsearch index:** `a2-push-YYYY.MM.dd`

## 7. Local Verification Results

| Test | Observed result |
|---|---|
| First pull sample file | Successfully indexed |
| Second pull sample file | Automatically detected and indexed |
| Pull index document count | 2 |
| First HTTP push request | HTTP 200; event indexed |
| Python push sender | HTTP 200; successful |
| Duplicate push submission | Index count remained 1 |
| Second distinct push event | Push index count increased to 2 |
| Missing sender input file | Rejected with file-not-found message |
| Malformed JSON input | Rejected before HTTP submission |

These results were obtained during local testing on 21 October 2026.

Both pipelines use deterministic SHA-256 fingerprint-based document IDs to reduce duplicate indexing.

## 8. Limitations

- The current implementation is intended for local development with synthetic logs.
- The HTTP push input does not have its own authentication or TLS and is published only on the host's localhost interface.
- The Python sender does not yet implement automatic retries or batching.
- The pull implementation monitors a local directory rather than fetching files from a remote API.
- Elasticsearch provisioning and shared infrastructure remain A1 dependencies.
- Log-field normalization and agentic source onboarding require coordination with Group B.
- Additional validation is needed before production use or full end-to-end team integration.
