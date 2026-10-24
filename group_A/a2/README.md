# A2 — Pull and Push Log Ingestion

**Module:** SE6014 — Security Monitoring and Threat Detection
**Project:** Agentic Threat Hunting on the ELK Stack
**Scope:** Group A, A2 (T05–T08)
**Test environment:** Logstash 8.19.23, Elasticsearch 8.19.23, Docker Desktop

## 1. Overview

A2 transports security events to Elasticsearch through two Logstash services:

- **Pull:** Automatically reads `.ndjson` files from `group_A/a2/incoming/`.
- **Push:** Accepts JSON events at `http://127.0.0.1:8088/`, including events forwarded by A3.

Both services use authenticated HTTPS to Elasticsearch, preserve upstream metadata, support optional Elasticsearch ingest pipelines, and can write to the shared `security-events-*` indices. **A2 handles ingestion, not format detection or schema generation**; parser and onboarding decisions belong to Group B.

## 2. Files and requirements

| Path (relative to `group_A/a2/`) | Purpose |
|---|---|
| `pipeline/pull.conf` | Pull Logstash pipeline |
| `push-pipeline/push.conf` | HTTP push Logstash pipeline |
| `incoming/` | Monitored NDJSON directory |
| `samples/` | Pull test files |
| `tools/push_sender.py` | Python HTTP sender |
| `tools/push-test*.json`, `tools/invalid-test.json` | Test fixtures |
| `../docker-compose.pull.yaml` | Both A2 services and persistent volumes |

**Required:** Docker Desktop/Compose, a running Elasticsearch service on the external Docker network `elastic`, the repository-root `.env`, and `group_A/certs/http_ca.crt`. Python 3 is needed only for the optional sender.

Configure the root `.env` with `ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, and `ELASTICSEARCH_PASSWORD`. For team integration, also use:

```dotenv
A2_INDEX_PREFIX=security-events
```

The Elasticsearch HTTPS hostname must match its TLS certificate. **Never commit `.env`, passwords, tokens, or private keys.**

## 3. Start and test

Run from the **repository root**:

```powershell
docker compose --env-file .env -f group_A/docker-compose.pull.yaml config --quiet
docker compose --env-file .env -f group_A/docker-compose.pull.yaml up -d
```

Validate Logstash configurations when making pipeline changes:

```powershell
docker compose --env-file .env -f group_A/docker-compose.pull.yaml run --rm --no-deps logstash-a2-pull -t
docker compose --env-file .env -f group_A/docker-compose.pull.yaml run --rm --no-deps logstash-a2-push -t
```

Check containers with `docker ps` or inspect `docker logs --tail 50 logstash-a2-pull` / `docker logs --tail 50 logstash-a2-push`.

**Pull test:** Copy a new NDJSON file into `group_A/a2/incoming/`:

```powershell
Copy-Item group_A/a2/samples/a2-pull-test.ndjson "group_A/a2/incoming/a2-pull-test-$(Get-Date -Format yyyyMMddHHmmss).ndjson"
```

The pull input reads completed files (`mode => "read"`), records completed paths, and stores its `sincedb` state in a persistent volume. The example generates a new filename to avoid conflicts with previous runs.

**Push test:**

```powershell
python group_A/a2/tools/push_sender.py group_A/a2/tools/push-test.json
```

The HTTP endpoint is bound to **host loopback only** (`127.0.0.1:8088`). An HTTP `ok` response confirms acceptance by Logstash, **not** successful Elasticsearch indexing.

If `.env` or Compose settings change, apply them with:

```powershell
docker compose --env-file .env -f group_A/docker-compose.pull.yaml up -d --force-recreate logstash-a2-pull logstash-a2-push
```

Do **not** use `--remove-orphans` or `docker compose down -v` on the shared project environment.

## 4. Event contract and indexing

| Field | A2 behavior |
|---|---|
| `labels.ingest_mode` | Preserves upstream value (including `stream`); defaults to `pull` or `push` |
| `labels.source_id` | Preserves upstream value; otherwise uses the pull file path or `a2-push-local` (pull fallback: `a2-pull-local`) |
| `event.id` | Preferred **unique occurrence ID** for deterministic document identification |
| `event_id` | Supported legacy top-level occurrence ID |
| `labels.ingest_pipeline` | Routes through the named Elasticsearch ingest pipeline if nonempty; it must already exist |

### Document IDs

A2 sets Elasticsearch `_id` using this priority:

1. **ECS `event.id`**: SHA-256 fingerprint of `labels.source_id` and `event.id`.
2. **Legacy `event_id`**: SHA-256 fingerprint of `labels.source_id` and `event_id`.
3. **No occurrence ID**: New UUID per ingested event.

Repeated events with the **same source and occurrence ID** update the same document; different sources stay distinct. With no occurrence ID, identical events remain separate and replays can create duplicates. Do **not** use event-type codes (e.g., Windows `4625`) as unique occurrence IDs.

### Example push payload

```json
{
  "event": { "id": "apache-001" },
  "message": "192.0.2.10 - - [24/Oct/2026:20:50:00 +0800] \"GET /index.html HTTP/1.1\" 200 123 \"-\" \"TestClient/1.0\"",
  "labels": {
    "source_id": "apache-test-server",
    "ingest_pipeline": "apache-access"
  }
}
```

This example requires the B1 `apache-access` pipeline to be installed. Without `labels.ingest_pipeline`, A2 indexes the event without selecting an additional ingest pipeline.

**Indices:** Standalone defaults are `a2-pull-YYYY.MM.dd` and `a2-push-YYYY.MM.dd`. With `A2_INDEX_PREFIX=security-events`, both use `security-events-YYYY.MM.dd` for downstream queries against `security-events-*`.

## 5. Failure handling and persistence

| Failure | Handling |
|---|---|
| Malformed JSON | Logstash tags `_jsonparsefailure` and sends it to `a2-quarantine-YYYY.MM.dd`, not the normal index |
| Elasticsearch document-level 400/404 (e.g., missing ingest pipeline) | Routed to the service's persistent **Dead Letter Queue (DLQ)** |
| Missing `labels.ingest_pipeline` | No explicitly requested parser; event indexed normally |

DLQs are enabled for both services through `DEAD_LETTER_QUEUE_ENABLE=true`. The pull service stores `sincedb`, completion logs, and DLQ data in `a2_pull_state`; push DLQ data resides in `a2_push_state`. Both mount `/usr/share/logstash/data`.

**DLQ limitations:** Entries are *retained*, not automatically replayed or indexed; a separate inspection/recovery procedure is required. DLQ coverage is limited to supported failures and is **not** a substitute for a persistent input queue. The observed default DLQ size limit was **1 GiB per service**, with `drop_newer` behavior when full.

Check DLQ statistics using:

```powershell
docker exec logstash-a2-push curl -s http://127.0.0.1:9600/_node/stats/pipelines/main
# Substitute logstash-a2-pull to inspect the pull DLQ.
```

## 6. Verification summary

**21 October 2026:** Basic pull file discovery, push HTTP/Python sender, Elasticsearch indexing, and sender-side invalid-file/JSON checks passed.

**24 October 2026:** Both Logstash configurations passed validation. Local Elasticsearch queries confirmed the following:

| Test | Expected | Observed | Status |
|---|---:|---:|---|
| Push, repeated ECS `event.id` | 1 | 1 | PASS |
| Push, repeated legacy `event_id` | 1 | 1 | PASS |
| Push, no event ID (two submissions) | 2 | 2 | PASS |
| Same occurrence ID from two sources | 2 | 2 | PASS |
| Push with A3-style `stream` metadata | 1 | 1 | PASS |
| Pull, repeated ECS `event.id` | 1 | 1 | PASS |
| Pull, no event ID (two records) | 2 | 2 | PASS |
| Pull, repeated legacy `event_id` | 1 | 1 | PASS |

Further checks passed:

- **Shared indexing:** Pull and push events were retrieved from `security-events-2026.10.24` with the expected metadata.
- **B1 Apache integration:** Both routes used `apache-access` and produced parsed ECS fields, including `source.ip`, `http.request.method`, `http.response.status_code`, `url.path`, `event.dataset`, and `event.outcome`.
- **Malformed JSON:** Both routes produced `_jsonparsefailure` events in `a2-quarantine-2026.10.24`, excluded from the normal index.
- **Push DLQ:** The missing-pipeline test produced a nonempty DLQ segment (3,879 bytes reported via API).
- **Pull DLQ:** Elasticsearch returned HTTP 400 for a nonexistent pipeline; Logstash explicitly logged `Events could not be indexed and routing to DLQ` with count 1, and created a nonempty segment (~2.6 KB).

## 7. Scope and remaining work

- **Team integration:** Validate the full A3 UDP → A2 HTTP → Elasticsearch path and B2/B3 parser selection/onboarding. Only B1's Apache parser has been integrated locally so far.
- **Operations:** Define a DLQ replay process, retention/size alerts, and handling for Elasticsearch outages or service restarts; the current sender has no automatic retry or batching.
- **Source coverage:** Pull reads local NDJSON files, not remote APIs. Large-volume workload tests remain outstanding.
- **Security:** The HTTP receiver has no independent TLS/client authentication; loopback binding is intended for local development. Elasticsearch connections are authenticated and CA-verified.
- **Schema:** Review Logstash JSON codec ECS warnings and field ownership with other groups before final integration.

**Verification dates:** 21 and 24 October 2026.
