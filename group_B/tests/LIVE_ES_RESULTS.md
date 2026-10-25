# Live Elasticsearch verification — 2026-10-24

Verified against a temporary single-node Elasticsearch **8.19.23** instance.

- Image: `docker.elastic.co/elasticsearch/elasticsearch:8.19.23`
- Digest: `sha256:4d0724bb8d78d7a2330693623e26ca4d621079d062ecc8a30b3e1fc180ec14c1`
- Authentication enabled; tests used an API key with `manage_pipeline` and no
  index privileges. Credentials were generated locally and were not committed.
- HTTP was bound only to a random host loopback port. This isolated test used
  HTTP without TLS; it does not verify A1's shared HTTPS/CA configuration.
- The container used a 1.5 GiB memory cap, 384 MiB Java heap and temporary data.

## Results

| Check | Result |
|---|---|
| Live tests selected with `-m integration` | **10 passed** |
| Full Group B suite with live ES enabled | **227 passed, no skips** |

Seven parser cases exercise JSON, CSV, KV, auditd, Dissect, Grok and regex
against the actual Elasticsearch `_simulate` API. Each checks valid records
and a malformed record, including required fields and the parse-failure tag.
CSV and auditd use the committed OTRF fixtures.

Three additional cases generate schemas through the real deterministic B2
JSON/CSV/KV heuristics, validate their compiled pipelines in Elasticsearch,
register them in a temporary local file registry with fresh live validation,
and confirm signature reuse. They do not call an LLM.

## Reproduce against an existing endpoint

Configure `ES_URL`, `ES_WRITE_API_KEY` (or `ES_API_KEY`) and, for HTTPS where
needed, `ES_CA_CERT` in the shell. Do not commit these values.

```bash
group_B/.venv/bin/python -m pytest -q group_B/tests/test_live_es.py -m integration

# Include all offline and live tests in one run.
group_B/.venv/bin/python -m pytest -q group_B -m 'integration or not integration'
```

The ordinary offline suite continues to skip these 10 cases when live tests
are not explicitly selected or `ES_URL` is absent.

## Remaining integration work

These checks validate pipeline compilation, heuristic generation and local
registry reuse against Elasticsearch. They do not install persistent server
pipelines, index documents, exercise A2/A3 transport, validate shared TLS or
credentials, or run B3 execution/verification/audit. Those remain Batch 6/7
integration checks. Live OpenRouter behavior is also untested.

The temporary test container, data and credentials were removed after testing.
The downloaded image remains cached locally.

## Batch 6 execution verification — 2026-10-25

A fresh temporary authenticated ES **8.19.23** instance was used for execution
checks. The test key had `manage_pipeline` plus read/write/create/delete-index
and index-metadata privileges restricted to `b3test-*`. This is an isolated
combined test credential; deployment still uses separate read/write keys.
The image/digest and loopback-only HTTP setup match the earlier run above.

| Check | Result |
|---|---|
| Existing parser/generation live cases | **10 passed** |
| B3 real install/index/verify/replay cases | **3 passed** |
| Full Group B suite with live ES enabled | **258 passed, no skips** |

The three B3 cases cover JSON, CSV with a header, and JSON with a malformed
record beyond the 50-record planning sample. Each captures and indexes **121
events**, installs the generated pipeline, performs live registry validation,
checks actual search results and parse-failure counts, then replays without
submitting new records or increasing the index count. A separate verify-only
run submits nothing and records audit completion. The malformed case verifies
preserved originals, timestamp, dataset, message and error evidence.

The first run passed the execution assertions but failed test cleanup because
ES prohibits wildcard index deletion by default. Cleanup now resolves and
deletes only explicitly named test indices; the corrected full run passed.
No server safeguard was disabled.

The 28 new offline execution cases cover dry-run side effects, whole-source
bounds, logical-ID verification with A2-style differing `_id` values, duplicate
matches, missing/corrupt required fields, read outages, partial transport errors,
CSV headers, audit failures, atomic file publication, pipeline conflicts and
CLI defaults. Ordinary CI runs **245 passed, 13 live cases skipped** without
an explicitly selected live endpoint.

These tests prove the direct-ES fallback and B3 execution controls against real
Elasticsearch. They do **not** run actual A2 Logstash pull/push or A3 UDP,
shared A1 HTTPS/CA/credential provisioning, B1's real recognition/pipelines, or
live OpenRouter inference. Those remain shared Batch 7 integration work.
The transport unit tests use temporary directories and an HTTP mock; they are
not evidence of the shared A2 service working end to end.

Reproduction uses the same commands above. Execution cases additionally need
index privileges restricted to `b3test-*`, including cleanup privileges. They
create only unique test prefixes and clean up their named indices/pipelines.


### Baseline after merging current main

After PR #20 merged, Batch 6 was synchronized with `main` at `e3adb7f`.
A fresh root-level `pytest -q group_B` run, now also collecting B1's tests,
passed **259 tests and 8 subtests**, with **17 live tests skipped**. The
working-directory Group B CI configuration selects `tests/` only; the extra
B1 cases account for the larger root-level total. Fixture checks passed.

A planning smoke check using the real B1 loader selected the approved Apache
pipeline and routed an unknown JSON source to B2 generation. This checks the
Python boundary only; it does not replace live B1 pipeline/A2/A1 verification.
The earlier 258-test live result above predates this merge and is not a fresh
live run against the combined B1 tree.
