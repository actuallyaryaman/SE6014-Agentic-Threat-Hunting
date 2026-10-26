# B3 → A3 raw stream contract v1

This is the bounded integration path. Existing A3 raw-log readers/parsers and
normalized-event forwarding remain supported. B3 sends raw records only when
an operator explicitly selects `--kind file --mode stream` (or an allowed HTTP
snapshot). Continuous `--kind stream` collection remains blocked.

## Responsibilities

- B3 captures the complete bounded source, recognizes it through B1, selects
  the approved B1 pipeline or generates/validates a B2 pipeline, prepares it
  in Elasticsearch, and assigns stable source/event IDs.
- A3 validates and forwards the envelope unchanged to A2, adding stream mode.
  It does not parse this raw path. Its existing normalized path is unchanged.
- A2 fingerprints source/event IDs and selects `labels.ingest_pipeline`.
- Elasticsearch runs B1/B2 parsing. B3 independently verifies every logical
  event ID, original-record hash, source ID, dataset and UTC timestamp.

## Envelope

```json
{
  "message": "<one original raw record>",
  "event_id": "<64 lowercase hex characters>",
  "event": {"id": "<same event_id>"},
  "labels": {
    "envelope": "b3.raw.v1",
    "source_id": "b3-<24 lowercase hex characters>",
    "run_id": "<B3 run identifier>",
    "ingest_mode": "stream",
    "ingest_pipeline": "<operator-approved pipeline>"
  }
}
```

The raw envelope intentionally has no parsed timestamp/dataset. B1/B2 derive
those fields. An optional `host.name` supplied to B3 is preserved.

Each UTF-8 JSON datagram is at most 4096 bytes, including metadata. B3 checks
all packets before sending any; oversized sources must use pull/push instead.
The initial supported deployment is local loopback; UDP provides no delivery
acknowledgement. A3 forwards each record synchronously with its existing HTTP
timeout. Loss/backpressure produces failed or incomplete ES verification,
not success. This is a bounded replay path, not a production lossless queue.

## Enable explicitly

Use separate terminals from the repository root. Configure A2/ES normally,
and install approved B1 pipelines before onboarding. Both groups' Python
environments must already be prepared.

A3 receiver (the raw path is disabled by default):

```bash
A3_ALLOW_B3_RAW=true A3_B3_PIPELINES=linux-auth,apache-access,windows-json \
  A3_UDP_PORT=9999 LOGSTASH_URL=http://127.0.0.1:8088 \
  python group_A/A3_Stream_Ingestion/receiver.py
```

B3 operator settings:

```bash
export A3_UDP_URL=udp://127.0.0.1:9999
export B3_ALLOWED_ROOTS=/absolute/path/to/approved/logs
# Also configure ES_URL, ES_CA_CERT, ES_READ_API_KEY and ES_WRITE_API_KEY.
# Read access is used only for verification; the write key prepares pipelines.
```

Use the B3 CLI with `--mode stream --execute`, an approved B1 mapping and an
allowed source file. Dry-run remains the default. For B2-generated pipelines,
obtain the selected ID from a plan and explicitly add that ID to the receiver's
`A3_B3_PIPELINES` before execution. The receiver never accepts arbitrary
pipeline names on this raw path.

## Identity and timestamp policy

B3 derives source IDs from the canonical source location and event IDs from
source ID, record ordinal and exact raw text. Replaying that same source
reuses IDs; changing its location or content represents a different source
or record. A3 preserves both IDs; A2 derives its own ES document `_id` from
them. Replaying existing records submits nothing after B3 preflight.

Yearless records remain blocked in B3 rather than silently using the current
year. A3's legacy parsers retain their existing behavior; this contract does
not redefine their year assumptions. ISO UTC samples are used for this path.

## Verification

The integration harness starts actual A3 on a temporary loopback port,
forwards through unchanged A2 over trusted HTTPS to ES, then runs actual C1,
pinned C2/C3 and C4. `--a3-stream` enables this path. It checks SSH hunting,
raw Apache, B2-generated JSON/CSV, replay and cleanup.
