# B1: Log Recognition and Known Parsing Schemas

B1 recognises a known log format from a sample of raw lines and parses it into ECS fields with an
Elasticsearch ingest pipeline. Unknown formats are handled by B2.

## Supported formats

| Format | `format_id` | `dataset` | Pipeline ID | Input |
|---|---|---|---|---|
| Apache access log | `apache_access` | `apache.access` | `apache-access` | Combined log format, trailing response time optional |
| Windows / Sysmon JSON | `windows_json` | the event's `Channel` | `windows-json` | One JSON event per line (Mordor style, `EventID` and `Channel`) |
| Firewall syslog | `firewall_syslog` | `firewall` | `firewall-syslog` | `Oct 22 10:20:01 fw01 firewall: Blocked connection from A to B` |
| Linux auth | `linux_auth` | `linux.auth` | `linux-auth` | sshd, sudo, PAM lines, ISO or classic syslog timestamps |

Sysmon and Windows Security events share one pipeline.

## Recogniser

```python
from recognise import recognise          # also importable as recognizer.recognise

recognise(lines)   # lines: sequence of raw lines (a sample of 50 is enough)
```

Match:

```python
{"matched": True, "format_id": "firewall_syslog", "dataset": "firewall",
 "pipeline_id": "firewall-syslog", "confidence": 1.0}
```

No match (no other match fields):

```python
{"matched": False, "reason_code": "no_match"}
```

A format matches when at least 80% of the non-empty sample lines fit its rule. A UTF-8 byte order
mark at the start of a file is ignored.

## Raw input and what the pipelines do

Input is the common envelope `{"message": "<raw log line>"}` (one object per line for files).

Every pipeline:
- keeps the raw line in `message` and copies it to `event.original`;
- sets `@timestamp` (UTC) and `event.dataset`;
- fills other ECS fields only when the line contains the data;
- uses no script processors (only `set`, `grok`, `date`, `rename`, `convert`, `lowercase`,
  `append`, `remove`, `json`, with small `if:` conditions);
- has an `on_failure` handler: a record that fails to parse is still indexed with the four required
  fields, the tag `_parse_failure` and `error.message`.

Source metadata (`labels.ingest_mode`, `labels.source_id`) and the document `_id` come from the
ingestion route, not from the pipelines.

## Known limitations

- **Timestamps without a year** (firewall, classic Linux syslog): the pipeline assumes the current
  year at ingest, in UTC. A line from 31 December ingested on 1 January gets the wrong year.
  Prefer sources that send ISO 8601 timestamps with an offset (the Linux auth pipeline accepts them).
- Windows `event.category` is set only for a small list of event IDs (Sysmon 1, 3, 11, 12 to 14;
  Security 5145, 4624, 4625, 4688). Other events have no category.
- The firewall pipeline matches only the `Allowed|Blocked connection from X to Y` shape.

## Run it

Needs Python 3.11 and Elasticsearch on `localhost:9200`. Create the pipelines from
`Pipelines/*.json` (`PUT _ingest/pipeline/<id>` with the file as body), then:

```
python recognise.py <logfile>                  # which format and pipeline
python load_file.py <logfile> <testname>       # load into index b1-<testname> and check it
```

Elasticsearch connection settings are read from environment variables, so the same scripts work
with an authenticated HTTPS cluster:

| Variable | Meaning |
|---|---|
| `ES_URL` | address, default `http://localhost:9200` |
| `ES_API_KEY` | API key (encoded value), sent as `Authorization: ApiKey ...` |
| `ES_USER`, `ES_PASSWORD` | basic authentication (used when `ES_API_KEY` is not set) |
| `ES_CA_CERT` | path to the CA certificate that signed Elasticsearch's HTTPS certificate |

`load_file.py` reports: lines in file, indexed, documents with all four required fields present
and non-empty, empty values, documents tagged `_parse_failure`, and **Parsed OK**. Use a new
`<testname>` for each run.

## Tests

```
python -m unittest discover -s tests -v               # recogniser and pipeline policy
ES_URL=http://localhost:9200 python -m unittest discover -s tests -v   # also runs the pipelines
```

On Windows PowerShell set the variable first: `$env:ES_URL="http://localhost:9200"`.
CI runs the same tests on every pull request (`.github/workflows/b1-ci.yml`).

## Test results (local, fresh indices)

| Dataset | Lines | Required fields non-empty | Parse failures |
|---|---|---|---|
| Apache access (clean, 1,000,000 lines) | 1,000,000 | 1,000,000 | 0 |
| Windows / Sysmon, Mordor empire_mimikatz | 7,887 | 7,887 | 0 |
| Firewall sample (from A3) | 6 | 6 | 0 |
| Linux auth sample (Kali VM) | 19 | 19 | 0 |

Ground truth: the Windows file holds 4 known attack events (Event ID 5145, `RelativeTargetName`
`lsarpc`, 2020-10-22 18:33:36 UTC); the search `event.code : 5145 and RelativeTargetName : lsarpc`
returns 4 hits. Kibana shows times in local time; the data is UTC.

## Files

```
group_B/B1/
  recognise.py        recogniser (the code)
  recognizer.py       shim, re-exports recognise() under the allowlisted name
  load_file.py        load a file through the matching pipeline and check the result
  Pipelines/*.json    the four ingest pipelines
  tests/              unit tests and small sample files (tests/data)
```
