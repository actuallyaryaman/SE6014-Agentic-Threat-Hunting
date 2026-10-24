
# A2 — Pull and Push Log Ingestion

**Module:** SE6014 — Security Monitoring and Threat Detection
**Project:** Agentic Threat Hunting on the ELK Stack
**Component:** A2 — Pull and Push Ingestion (T05–T08)

## 1. Overview

This component implements two log-ingestion methods using Logstash 8.19.23 and Elasticsearch 8.19.23.

- **Pull ingestion:** Automatically discovers and processes NDJSON files placed in a monitored directory.
- **Push ingestion:** Accepts JSON security events through a local HTTP endpoint, including events submitted using a Python sender.

Both methods forward events to Elasticsearch over HTTPS using configured credentials and a trusted CA certificate.

### Integration Capabilities

The pipelines support:

- Metadata enrichment using `labels.ingest_mode` and `labels.source_id`.
- Preservation of metadata supplied by upstream components.
- Elasticsearch document IDs derived from a supplied `event_id`.
- SHA-256 fingerprint-based document IDs when `event_id` is unavailable.
- Configurable index naming for standalone testing or integrated operation.
- Optional routing through Elasticsearch ingest pipelines selected by Group B.

A2 handles event transportation and indexing. Format recognition, schema generation, and automated source onboarding remain the responsibilities of Group B.

## 2. Project Structure

| Path | Purpose |
|---|---|
| `pipeline/pull.conf` | Logstash pull-ingestion configuration |
| `push-pipeline/push.conf` | Logstash HTTP push-ingestion configuration |
| `incoming/` | Monitored directory for NDJSON files |
| `samples/` | Sample security events for pull testing |
| `tools/push_sender.py` | Python HTTP event sender |
| `tools/push-test.json` | First push-test event |
| `tools/push-test-2.json` | Second push-test event |
| `tools/invalid-test.json` | Malformed JSON test fixture |
| `../docker-compose.pull.yaml` | Docker Compose configuration for both A2 services |

## 3. Prerequisites

- Docker Desktop and Docker Compose.
- Python 3.11 or a compatible Python 3 version for the sender.
- Running Elasticsearch 8.19.23 connected to the Docker network `elastic`.
- Root `.env` file containing Elasticsearch connection settings.
- Root `certs/http_ca.crt` from the local Elasticsearch environment.

The Elasticsearch connection requires the following environment variables:

| Variable | Purpose |
|---|---|
| `ELASTICSEARCH_URL` | Elasticsearch HTTPS endpoint |
| `ELASTICSEARCH_USER` | Elasticsearch username |
| `ELASTICSEARCH_PASSWORD` | Elasticsearch password |
| `A2_INDEX_PREFIX` | Optional shared index prefix |

The Elasticsearch URL must match a hostname or IP address covered by its TLS certificate.

Credentials, the `.env` file, and local certificate material must not be committed to Git.

## 4. Start A2 Services

Run the following commands from the repository root.

First, validate the Docker Compose configuration:

```bash
docker compose --env-file .env -f group_A/docker-compose.pull.yaml config --quiet
```

Then start both A2 services:

```bash
docker compose --env-file .env -f group_A/docker-compose.pull.yaml up -d
```

The services are:

- `logstash-a2-pull`
- `logstash-a2-push`

The push endpoint is available locally at:

`http://127.0.0.1:8088`

Check their status:

```bash
docker ps
```

Inspect logs using:

```bash
docker logs --tail 50 logstash-a2-pull
docker logs --tail 50 logstash-a2-push
```

### Integrated Elasticsearch Index

For standalone testing, A2 uses these default indices:

- Pull: `a2-pull-YYYY.MM.dd`
- Push: `a2-push-YYYY.MM.dd`

For integration with the other project components, add the following variable to the repository's root `.env` file:

```dotenv
A2_INDEX_PREFIX=security-events
```

Both ingestion methods will then write to:

`security-events-YYYY.MM.dd`

This shared naming convention allows downstream components to search the `security-events-*` index pattern.

After changing `.env`, recreate the A2 containers so they receive the updated environment variable:

```bash
docker compose --env-file .env -f group_A/docker-compose.pull.yaml up -d --force-recreate logstash-a2-pull logstash-a2-push
```

This preserves Elasticsearch data and the pull pipeline's persistent Docker volume.

Do not use `--remove-orphans` or `docker compose down -v` when other project containers or persistent state must be retained.

## 5. Pull Ingestion

### 5.1 Input and File Discovery

Pull ingestion monitors:

```text
group_A/a2/incoming/
```

The Logstash file input automatically discovers `.ndjson` files placed in this directory.

To test ingestion, copy a sample file:

```bash
cp group_A/a2/samples/a2-pull-test.ndjson group_A/a2/incoming/
```

The pull pipeline reads complete files using `mode => "read"`.

Processing state is maintained through a persistent Docker volume using a `sincedb` file. Completed files are preserved, and a completion log records processed file paths.

### 5.2 Metadata Handling

For each event, the pull pipeline checks the following metadata:

| Field | Behavior |
|---|---|
| `labels.ingest_mode` | Defaults to `pull` if absent |
| `labels.source_id` | Uses the file path if absent |
| `event_id` | Used as the Elasticsearch document ID when provided |
| `labels.ingest_pipeline` | Selects an Elasticsearch ingest pipeline when provided |

Existing `labels.ingest_mode` and `labels.source_id` values are preserved.

If neither a supported file-path field nor a supplied source ID is available, `labels.source_id` defaults to `a2-pull-local`.

### 5.3 Elasticsearch Output

The default standalone index is:

`a2-pull-YYYY.MM.dd`

When `A2_INDEX_PREFIX=security-events` is configured, events are written to:

`security-events-YYYY.MM.dd`

If `labels.ingest_pipeline` is present and non-empty, Logstash requests the named Elasticsearch ingest pipeline.

Otherwise, the event is indexed without an explicitly selected ingest pipeline.

The selected pipeline must already exist in Elasticsearch.

## 6. Push Ingestion

### 6.1 HTTP Input

The push pipeline accepts JSON events through Logstash's HTTP input on port `8088`.

The Docker Compose configuration publishes this port only on the host loopback interface:

`http://127.0.0.1:8088`

Events can be submitted using the Python sender:

```bash
python group_A/a2/tools/push_sender.py group_A/a2/tools/push-test.json
```

The sender checks the input file and JSON content before submitting the request.

### 6.2 Metadata Handling

The push pipeline handles these fields:

| Field | Behavior |
|---|---|
| `labels.ingest_mode` | Defaults to `push` if absent |
| `labels.source_id` | Defaults to `a2-push-local` if absent |
| `event_id` | Used as the Elasticsearch document ID when provided |
| `labels.ingest_pipeline` | Selects an Elasticsearch ingest pipeline when provided |

Metadata supplied by an upstream component is preserved.

During integrated operation, the onboarding component should provide a stable, source-specific `labels.source_id`.

### 6.3 Example Input

An event compatible with A2's integrated input format is:

```json
{
  "event_id": "EXAMPLE-001",
  "message": "192.0.2.10 - - [24/Oct/2026:20:50:00 +0800] \"GET /index.html HTTP/1.1\" 200 123 \"-\" \"TestClient/1.0\"",
  "labels": {
    "source_id": "apache-test-server",
    "ingest_pipeline": "apache-access"
  }
}
```

A2 adds `labels.ingest_mode` when it is missing.

The example requires an Elasticsearch ingest pipeline named `apache-access` to be installed before submission.

### 6.4 Elasticsearch Output

The default standalone index is:

`a2-push-YYYY.MM.dd`

When the shared index prefix is configured, events are written to:

`security-events-YYYY.MM.dd`

The pipeline supports optional Elasticsearch ingest-pipeline routing and otherwise indexes events normally.

### 6.5 Document IDs and Duplicate Prevention

Both ingestion methods apply the following document-ID strategy:

1. If a non-empty top-level `event_id` is provided, use it as the Elasticsearch document ID.
2. Otherwise, generate a SHA-256 fingerprint from `labels.source_id` and `message`.
3. Pass the resulting ID to the Elasticsearch output through `[@metadata][document_id]`.

Using a supplied deterministic `event_id` allows repeated ingestion of the same event to update the existing document instead of creating duplicates.

The SHA-256 fallback also produces identical IDs for identical messages from the same source.

However, separate events with identical messages and source IDs will produce the same fallback fingerprint. Upstream components should therefore supply unique, stable `event_id` values for reliable event-level deduplication.

## 7. Local Verification Results

### 7.1 Initial Functional Testing — 21 October 2026

The first testing phase verified standalone pull and push ingestion.

| Test | Observed result |
|---|---|
| First pull sample file | Successfully indexed |
| Second pull sample file | Automatically discovered and indexed |
| Pull index document count | 2 |
| First HTTP push request | HTTP 200; event indexed |
| Python push sender | HTTP 200; successful |
| Duplicate push submission | Matching index count remained 1 |
| Second distinct push event | Push index count increased to 2 |
| Missing sender input file | Rejected with file-not-found message |
| Malformed JSON input | Rejected before HTTP submission |

These tests established the initial functionality of both ingestion methods.

### 7.2 Integration Testing — 24 October 2026

The second testing phase validated the updated configurations against Elasticsearch 8.19.23.

#### Configuration Validation

Both Logstash pipeline configurations passed syntax validation.

Commands:

```bash
docker compose --env-file .env -f group_A/docker-compose.pull.yaml run --rm --no-deps logstash-a2-pull -t
docker compose --env-file .env -f group_A/docker-compose.pull.yaml run --rm --no-deps logstash-a2-push -t
```

Both returned:

```text
Configuration OK
Config Validation Result: OK
```

#### Ingestion and Metadata Tests

| Test | Observed result |
|---|---|
| Pull container initialization | Pipeline started and connected to Elasticsearch |
| Push container initialization | HTTP listener started on port 8088 and connected to Elasticsearch |
| Push metadata enrichment | Automatically added `labels.ingest_mode = push` |
| Push source metadata | Preserved supplied `labels.source_id` |
| Pull metadata enrichment | Automatically added `labels.ingest_mode = pull` |
| Pull source metadata | Populated `labels.source_id` from the file path |
| Push indexing with supplied `event_id` | Correct Elasticsearch `_id` verified |
| Pull indexing with supplied `event_id` | Correct Elasticsearch `_id` verified |
| Duplicate push using supplied `event_id` | Two submissions resulted in one matching document |
| Push SHA-256 fallback | Two identical submissions without `event_id` resulted in one matching document |

The fallback test initially produced two documents because the fingerprint included a dynamically generated `@timestamp`.

After updating the fallback to use `labels.source_id` and `message`, the repeated push test returned a document count of one.

The SHA-256 fallback was verified for push ingestion; an equivalent duplicate-count test for pull ingestion remains a separate validation item.

### 7.3 Shared Elasticsearch Index

Both ingestion methods were tested with:

```dotenv
A2_INDEX_PREFIX=security-events
```

The following documents were successfully retrieved:

| Ingestion mode | Index | Document ID |
|---|---|---|
| Push | `security-events-2026.10.24` | `A2-PUSH-SHARED-20261024-01` |
| Pull | `security-events-2026.10.24` | `A2-PULL-SHARED-20261024-01` |

Both Elasticsearch responses included:

```json
{
  "found": true
}
```

The stored documents also contained the expected ingestion-mode and source metadata.

This confirmed that both ingestion methods could use the shared index required by downstream components.

### 7.4 Group B1 Apache Parser Integration

A2 was also tested with the `apache-access` Elasticsearch ingest pipeline from Group B1.

The pipeline was installed in the local Elasticsearch environment for integration testing.

Events containing:

```json
{
  "labels": {
    "ingest_pipeline": "apache-access"
  }
}
```

were routed through the selected parser.

#### Push → B1 Integration

Test document:

`A2-B1-APACHE-20261024-01`

| Parsed field | Verified value |
|---|---|
| `source.ip` | `192.0.2.10` |
| `http.request.method` | `GET` |
| `http.response.status_code` | `200` |
| `event.dataset` | `apache.access` |
| `event.outcome` | `success` |
| `url.path` | `/index.html` |
| `labels.ingest_mode` | `push` |

The event was successfully retrieved from `security-events-2026.10.24`.

#### Pull → B1 Integration

Test document:

`A2-B1-APACHE-PULL-20261024-01`

| Parsed field | Verified value |
|---|---|
| `source.ip` | `198.51.100.20` |
| `http.request.method` | `POST` |
| `http.response.status_code` | `401` |
| `event.dataset` | `apache.access` |
| `event.outcome` | `failure` |
| `url.path` | `/login` |
| `labels.ingest_mode` | `pull` |

The event was successfully retrieved from `security-events-2026.10.24`.

Both tests preserved the original Apache log text and the supplied source metadata. Neither stored event contained a `_parse_failure` tag.

These results demonstrate successful local integration between A2 and the B1 Apache parser through both ingestion methods.

### 7.5 Integration Summary

| Capability | Status |
|---|---|
| Pull ingestion | Tested successfully |
| Push ingestion | Tested successfully |
| Elasticsearch connectivity | Tested successfully |
| Metadata enrichment | Tested successfully |
| Metadata preservation | Tested successfully |
| Supplied `event_id` document IDs | Tested successfully |
| SHA-256 fallback deduplication | Tested successfully for push |
| Shared Elasticsearch index | Tested successfully |
| B1 Apache parsing through push | Tested successfully |
| B1 Apache parsing through pull | Tested successfully |
| Other B1 parser types | Not yet tested through A2 |
| Complete automated B3 onboarding | Pending team integration |
| Complete A3 streaming integration | Pending team integration |

## 8. Limitations

### 8.1 Local Development Scope

The implementation has been tested primarily with synthetic events in a local Docker environment.

Further testing is required with larger datasets and realistic ingestion workloads.

### 8.2 HTTP Security

The push HTTP input does not independently provide TLS or client authentication.

Its Docker port binding restricts access to the host loopback interface for local development.

Additional security controls would be required for remote or production ingestion.

### 8.3 Retry and Batch Handling

The Python sender does not currently implement automatic retries or batch submissions.

Additional reliability mechanisms may be required for high-volume or unreliable network conditions.

### 8.4 Pull Source Coverage

The pull implementation monitors a local directory of NDJSON files.

It does not directly retrieve logs from remote APIs or other external services.

Remote source discovery and onboarding require coordination with upstream components.

### 8.5 Duplicate Handling

The preferred deduplication method requires a stable, unique `event_id` supplied by the upstream component.

The SHA-256 fallback uses source ID and message content, which can cause distinct events with identical content to share a document ID.

The fallback has been verified for repeated push submissions, but broader deduplication and replay scenarios require additional testing.

### 8.6 Elasticsearch Pipeline Dependencies

Optional parsing requires the selected ingest pipeline to be installed in Elasticsearch.

A2 does not implement automatic format recognition or schema generation.

The pipeline ID is currently taken from `labels.ingest_pipeline`. Integrated deployment should ensure this value is selected from approved, validated pipelines by a trusted upstream component.

The Apache parser was successfully tested, but the other B1 formats and dynamically generated B2 pipelines still require integration testing.

### 8.7 ECS Field Compatibility

The Logstash JSON codecs produce ECS compatibility warnings because no separate target field is configured.

During Apache push testing, metadata from the incoming HTTP request and the parsed Apache event appeared within related ECS structures.

These overlapping fields should be reviewed during final integration to ensure consistent field ownership and semantics.

### 8.8 Team Integration

A2 depends on A1 for Elasticsearch infrastructure and connectivity.

B1 provides known-format ingest pipelines. B2 provides unknown-schema generation, while B3 is responsible for automated source onboarding and pipeline selection.

A2's pull and push routes have been independently verified with B1's Apache parser. Complete end-to-end testing with B3 onboarding and the remaining team components is still pending.

---

**Verification dates:** 21 October 2026 and 24 October 2026
**Environment:** Docker Desktop, Logstash 8.19.23, Elasticsearch 8.19.23
**Component:** A2 — Pull and Push Log Ingestion
