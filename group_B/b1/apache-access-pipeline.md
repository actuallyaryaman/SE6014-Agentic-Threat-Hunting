# Apache Access Log Pipeline (B1)

Elasticsearch ingest pipeline that parses Apache access log lines into the common normalized fields (see `shared/common-fields.md`).

## How to use
1. Open Kibana > Dev Tools.
2. Run the `PUT` request below to create the pipeline.
3. Run the `POST` request to test it with a sample line.

## Create the pipeline
```
PUT _ingest/pipeline/apache-access
{
  "description": "Apache access log to common fields",
  "processors": [
    {
      "grok": {
        "field": "message",
        "patterns": [
          """%{IPORHOST:source.ip} %{USER:apache.ident} %{USER:apache.auth} \[%{HTTPDATE:apache.timestamp}\] "%{WORD:http.request.method} %{DATA:url.path} HTTP/%{NUMBER:http.version}" %{NUMBER:http.response.status_code:int} (?:%{NUMBER:http.response.body.bytes:long}|-) "%{DATA:http.request.referrer}" "%{DATA:user_agent.original}" %{NUMBER:apache.response_time:long}"""
        ]
      }
    },
    {
      "date": {
        "field": "apache.timestamp",
        "formats": ["dd/MMM/yyyy:HH:mm:ss Z"],
        "target_field": "@timestamp"
      }
    },
    { "set": { "field": "event.original", "copy_from": "message" } },
    { "set": { "field": "event.dataset", "value": "apache.access" } },
    { "remove": { "field": ["apache.timestamp", "message"] } }
  ]
}
```

## Test it
```
POST _ingest/pipeline/apache-access/_simulate
{
  "docs": [
    {
      "_source": {
        "message": """76.103.128.42 - - [07/Apr/2017:00:00:00 +0530] "PUT /usr/admin HTTP/1.0" 404 4864 "http://www.parker-miller.org/tag/list/list/privacy/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4380.0 Safari/537.36 Edg/89.0.759.0" 4927"""
      }
    }
  ]
}
```

## Expected result (tested)
| Field | Value |
|---|---|
| `source.ip` | 76.103.128.42 |
| `http.request.method` | PUT |
| `url.path` | /usr/admin |
| `http.response.status_code` | 404 |
| `http.response.body.bytes` | 4864 |
| `@timestamp` | 2017-04-06T18:30:00.000Z (UTC) |
| `event.dataset` | apache.access |

## Notes
- The last number on each line (`4927`) is stored as `apache.response_time`. Its unit is not confirmed yet.
- `url.path` currently keeps the full URL including any `?query`, which is useful for spotting attacks.
- Test data: synthetic Apache access log (clean control). Attack file to be added.
