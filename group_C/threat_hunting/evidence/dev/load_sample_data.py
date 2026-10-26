"""Development only: load the synthetic Windows sample into a local Elasticsearch.

The script writes only the five sample indices listed below. It first creates a
high-priority index template, so these ``logs-*-*`` names become plain indices
instead of data streams and keep their fixed ``_id`` values. The example hunt
bundles in tests/group_C/c3/fixtures/ can then be verified live:

    python group_C/threat_hunting/evidence/dev/load_sample_data.py --reset
    python -m group_C.threat_hunting.evidence.cli report \
        --bundle tests/group_C/c3/fixtures/hunt_bundle_confirmed.json --verify es
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SAMPLE = ROOT / "tests" / "sample_data" / "c3_windows_sample.ndjson"
INDICES = ["logs-sysmon-sysmon-endpoints", "logs-windows-security-dc", "logs-firewall-fw-edge",
           "logs-web-web-prod", "logs-auth-linux-ssh"]
TEMPLATE = {
    "index_patterns": INDICES,
    "priority": 500,
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "dynamic_templates": [{"strings": {"match_mapping_type": "string",
                                               "mapping": {"type": "keyword", "ignore_above": 2048}}}],
            "properties": {"@timestamp": {"type": "date"},
                           "source": {"properties": {"ip": {"type": "ip"}}},
                           "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
                           "event": {"properties": {"code": {"type": "long"}}}},
        },
    },
}


def request(method: str, url: str, body: bytes | None = None, content_type: str = "application/json") -> tuple[int, dict]:
    """Send one HTTP request to Elasticsearch and return (status, parsed JSON body)."""
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", content_type)
    if os.getenv("ES_API_KEY"):
        req.add_header("Authorization", f"ApiKey {os.environ['ES_API_KEY']}")
    elif os.getenv("ES_USERNAME"):
        token = base64.b64encode(f"{os.environ['ES_USERNAME']}:{os.getenv('ES_PASSWORD', '')}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.getenv("ES_URL", "http://localhost:9200"))
    parser.add_argument("--reset", action="store_true", help="delete and recreate the sample indices first")
    args = parser.parse_args()

    status, payload = request("PUT", f"{args.url}/_index_template/c3-dev-sample", json.dumps(TEMPLATE).encode())
    if status != 200:
        print(f"Could not create index template: {status} {payload}", file=sys.stderr)
        return 1
    for index in INDICES:
        if args.reset:
            request("DELETE", f"{args.url}/{index}")
        request("PUT", f"{args.url}/{index}")
    rows = [json.loads(x) for x in SAMPLE.read_text(encoding="utf-8").splitlines() if x.strip()]
    lines = []
    for row in rows:
        lines.append(json.dumps({"index": {"_index": row["_index"], "_id": row["_id"]}}))
        lines.append(json.dumps(row["_source"], sort_keys=True))
    status, payload = request("POST", f"{args.url}/_bulk?refresh=true", ("\n".join(lines) + "\n").encode(), "application/x-ndjson")
    if status != 200 or payload.get("errors"):
        print(f"Bulk load failed: {status} {json.dumps(payload)[:500]}", file=sys.stderr)
        return 1
    for index in INDICES:
        _, counted = request("GET", f"{args.url}/{index}/_count")
        print(f"{index}: {counted.get('count')} documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
