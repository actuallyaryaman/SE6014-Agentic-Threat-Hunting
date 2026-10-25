"""Offline Elasticsearch backend for C1 MCP tests; never used by the server CLI."""
from pathlib import Path
from tempfile import TemporaryDirectory

INDEX = "security-events-c1test"
TIMESTAMP = "2026-10-01T00:00:00Z"
ORIGINAL = "Example original authentication record"


class FakeElasticsearch:
    def __init__(self):
        self.indices = self
        self.requests = []

    def get_mapping(self, **kwargs):
        return {INDEX: {"mappings": {"properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {
                "dataset": {"type": "keyword"},
                "original": {"type": "keyword"},
            }},
            "host": {"properties": {"name": {"type": "keyword"}}},
        }}}}

    def search(self, **kwargs):
        self.requests.append(kwargs)
        result = {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{
            "_index": INDEX, "_id": "doc-1", "_source": self.document(),
        }]}}
        if "aggs" in kwargs:
            if "ds" in kwargs["aggs"]:
                result["aggregations"] = {"ds": {"buckets": [{
                    "key": "linux.auth", "doc_count": 1,
                    "min": {"value_as_string": TIMESTAMP},
                    "max": {"value_as_string": TIMESTAMP},
                }]}}
            else:
                result["aggregations"] = {"a": {"buckets": [{"key": "WS-01", "doc_count": 1}]}}
        return result

    def count(self, **kwargs):
        self.requests.append(kwargs)
        return {"count": 1}

    def get(self, **kwargs):
        self.requests.append(kwargs)
        return {"_index": INDEX, "_id": "doc-1", "_source": self.document()}

    @staticmethod
    def document():
        return {"@timestamp": TIMESTAMP, "host": {"name": "WS-01"},
                "event": {"dataset": "linux.auth", "original": ORIGINAL}}


if __name__ == "__main__":
    from es_mcp_server import server
    from threat_hunting import config

    with TemporaryDirectory(prefix="c1-mcp-test-") as directory:
        config.AUDIT_DIR = Path(directory)
        server.es_client = FakeElasticsearch
        server.build().run()
