# A1/A2 HTTPS onboarding integration — 2026-10-25

The unchanged A1 and A2 Logstash pipelines passed together with B1/B2/B3 in
an isolated authenticated HTTPS environment. This validates the configurations
and Python boundaries locally; it does not verify access to Ishaan's running
Elasticsearch deployment. A2 PR #2 remains open.

## Provenance and isolation

- Product code: `cb240476faa56271cc40f3e5ee091145c8a86f10` (Batch 6).
- A1 pipeline: `group_A/logstash/pipeline/logstash.conf` from merged main.
- A2 pull/push: exact git blobs from PR #2 head
  `8b86c10eb5ee5248f087aa6c8273c8fadb82758c`, extracted into a temporary directory.
  No A2 code is vendored or changed on this branch.
- Elasticsearch and Logstash: **8.19.23**, pinned images. Image digests,
  pipeline SHA-256 hashes, harness hash, timestamps and individual results are
  recorded in [A1_A2_RESULTS.json](A1_A2_RESULTS.json).
- Temporary CA and hostname/IP-valid server certificate; full certificate
  verification, HTTPS and authentication enabled. No insecure client switch.
- Separate B3 read/write API keys scoped to `security-events-*`. Logstash used
  a dedicated basic-auth user with index/template/ILM permissions on the test
  instance. No developer's credentials were reused.
- Dedicated Docker network, random loopback ports, temporary data, and at most
  two containers concurrently, each capped at 1.5 GiB with a 384 MiB heap.
- Only synthetic/public repository samples. No live LLM calls.

## Results

**22 checkpoints passed**, including **10 actual B3 → A2 → HTTPS ES cases**:

| Source | Pull events | Push events | Parser |
|---|---:|---:|---|
| Apache | 5 | 5 | Real B1 `apache-access` |
| Linux auth with ISO timestamp | 5 | 5 | Real B1 `linux-auth` |
| Windows JSON | 5 | 5 | Real B1 `windows-json` |
| Unknown JSON | 61 | 61 | Real B2 generation and registry reuse |
| Unknown CSV | 6 | 6 | Real B2 generation; header omitted |

All **164 events** were independently verified for logical ID, preserved raw
original, source ID, dataset, nonempty message and UTC timestamp. Additional
assertions check the exact source event time, ingestion mode, Apache source IP,
and that A2's fingerprint `_id` differs from B3's logical `event_id`.

Each case was onboarded, replayed with zero new submissions and unchanged
index count, then checked through verify-only. The generated JSON/CSV pipeline
IDs were reused across pull and push. The JSON case exceeds B3's 50-record
planning sample and confirms complete-source ingestion.

Other passed checkpoints:

- A1's unchanged baseline pipeline indexed its three repository sample events
  over HTTPS. These baseline indices were removed before B3 testing.
- Unauthenticated ES requests and connections without the test CA were rejected.
- The read key could not install a pipeline; the write key could not search.
- Yearless firewall sources stayed blocked pending an explicit year policy.
- A3 stream sources stayed blocked pending the agreed input contract.
- All **32 runs** (including blocked cases) had paired started/completed audit
  entries: **64 JSONL records**, with no raw synthetic message in the audit.

The ordinary regression suite also passed: **259 tests and 8 subtests**, with
**17 opt-in live cases skipped**. The integration harness above is a separate
live run, not part of that pytest count.

## Startup diagnosis

The first two full attempts passed pull but failed push before the first HTTP
acknowledgement. Monitoring-API readiness and a host TCP connection were
insufficient: Docker's published port could be reachable before Logstash's
HTTP input listened inside the container. A narrowed push run passed after
checking the internal listener. The final full run used B3's default adapters
and observed one internal connection refusal before readiness, then passed
all cases. Only the harness readiness gate changed; A1/A2 and B3 application
code were unchanged.

## Reproduce

Requirements: Linux user UID 1000 (matching the container runtime UID), Docker
access, OpenSSL, Group B's Python environment, and the pinned Git objects/images.
The harness provisions its own credentials, certificates, network and services.
It does not use root `.env` or an existing cluster.

```bash
docker pull docker.elastic.co/elasticsearch/elasticsearch:8.19.23
docker pull docker.elastic.co/logstash/logstash:8.19.23
git fetch origin feature/A2/pull-push-ingestion

group_B/.venv/bin/python group_B/scripts/check_a1_a2_integration.py \
  --output /tmp/smtd-a1-a2-results.json
```

`--a2-ref` accepts an explicitly selected commit instead of the pinned default.
`--modes push --skip-a1-baseline` runs a diagnostic subset and is not full-suite
evidence. Normal completion and test failures clean up owned resources; a
hard process/host kill may require manual removal of containers carrying the
`smtd.b3.integration` label. Do not remove unrelated services.

The final run removed its containers, network, data, credentials and private
keys. Existing Firefly services remained running. Downloaded images remain
cached. Only sanitized evidence was retained.

## Remaining work

- Repeat against the actual shared A1 deployment with its operator-provided
  endpoint, CA and separate keys; that deployment was unavailable here.
- Agree on A3's normalized/raw envelope, source-ID ownership and year policy.
  Firewall syslog and B3 streaming are not enabled by this result.
- Exercise the C1/C2 hunting boundary and the presentation demo.
- This harness does not verify A2 DLQ recovery, persistence across restarts,
  high-volume behavior, all failure inputs or live OpenRouter inference.
