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
