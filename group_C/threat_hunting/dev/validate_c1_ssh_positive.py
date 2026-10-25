"""Isolated local SSH fixture ingestion, C2 hunt and independent evidence checks."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from elasticsearch import Elasticsearch, helpers

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "c1_ssh_positive"
INDEX = "security-events-c1-ssh-positive-v1"
SOURCE_IP = "203.0.113.51"
HOST = "C1-SSH-POSITIVE"
NEGATIVE = ROOT / "runs" / "hunt-20261025-064437" / "result.json"


def fixture():
    docs = [json.loads(line) for line in (FIXTURE / "events.ndjson").read_text().splitlines() if line.strip()]
    assert len(docs) == 26
    assert len({d["event"]["id"] for d in docs}) == 26
    for i, doc in enumerate(docs):
        assert doc["event"]["id"] == f"c1-ssh-positive-{i + 1:02d}"
        assert doc["event"]["outcome"] == ("failure" if i < 25 else "success")
        assert doc["event"]["dataset"] == "linux.auth" and doc["event"]["action"] == "ssh_login"
        assert doc["source"]["ip"] == SOURCE_IP and doc["host"]["name"] == HOST
        assert doc["user"]["name"] == "admin" and doc["event"]["original"]
        assert doc["@timestamp"] == f"2026-10-02T06:{i:02d}:00Z"
    return docs


def client(*, write=False):
    # Reuse the existing local .env loader without printing connection secrets.
    from threat_hunting import config

    endpoint = urlsplit(config.ES_URL)
    if endpoint.hostname not in {"localhost", "127.0.0.1", "::1"} or endpoint.scheme not in {"http", "https"}:
        raise ValueError("Only an explicitly configured loopback Elasticsearch endpoint is permitted.")
    if endpoint.username or endpoint.password:
        raise ValueError("Use credential environment variables, not credentials embedded in ES_URL.")
    options = {"verify_certs": True, "request_timeout": 20}
    if config.ES_CA_CERT:
        options["ca_certs"] = config.ES_CA_CERT
    if write:
        key = os.environ.get("ES_WRITE_API_KEY")
        password = os.environ.get("ES_ADMIN_PASSWORD")
        if key:
            options["api_key"] = key
        elif password:
            options["basic_auth"] = (os.environ.get("ES_ADMIN_USER", "elastic"), password)
        else:
            raise ValueError("Ingestion requires ES_WRITE_API_KEY or ES_ADMIN_PASSWORD for the isolated local container.")
    else:
        if not config.ES_API_KEY:
            raise ValueError("ES_API_KEY must contain the read-only C1 key authorized for this dedicated index.")
        options["api_key"] = config.ES_API_KEY
    return Elasticsearch(config.ES_URL, **options)


def ingest(docs):
    with client(write=True) as es:
        if es.info()["version"]["number"] != "8.19.23":
            raise ValueError("Expected the isolated local Elasticsearch 8.19.23 container.")
        if es.indices.exists(index=INDEX):
            raise ValueError("Dedicated index already exists; refusing to modify it. Use verify or hunt instead.")
        body = json.loads((FIXTURE / "index.json").read_text())
        # Disable inherited default/final parsers: these records are already ECS-normalized.
        body["settings"].update({"index.default_pipeline": "_none", "index.final_pipeline": "_none"})
        es.indices.create(index=INDEX, **body)
        actions = ({"_op_type": "create", "_index": INDEX, "_id": d["event"]["id"], "_source": d} for d in docs)
        count, errors = helpers.bulk(es, actions, refresh="wait_for", raise_on_error=False)
        if count != 26 or errors:
            raise RuntimeError("Fixture ingestion was incomplete. The dedicated index is retained for diagnosis.")
    print(f"Created {INDEX}: 26 documents (create-only ingestion).")


def verify_index(docs):
    with client() as es:
        assert es.count(index=INDEX)["count"] == 26, "Unexpected document count"
        for outcome, expected in (("failure", 25), ("success", 1)):
            assert es.count(index=INDEX, query={"term": {"event.outcome": outcome}})["count"] == expected
        response = es.mget(index=INDEX, ids=[d["event"]["id"] for d in docs])
        for actual, expected in zip(response["docs"], docs, strict=True):
            assert actual.get("found") and actual["_index"] == INDEX
            assert actual["_id"] == expected["event"]["id"] and actual["_source"] == expected
        mapping = es.indices.get_mapping(index=INDEX)[INDEX]["mappings"]["properties"]
        assert mapping["source"]["properties"]["ip"]["type"] == "ip"
        assert mapping["@timestamp"]["type"] == "date"
    print("Verified exact IDs, original records, timestamps, ECS fields, mappings and 25/1 outcomes.")


@asynccontextmanager
async def c1_session(run_id):
    """Independent MCP connection to the C1 server, as C3 uses it (C2's client routes only the agent's tools)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "es_mcp_server.server"], cwd=str(ROOT),
                                   env={**os.environ, "HUNT_RUN_ID": run_id})
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()

            class Calls:
                @staticmethod
                async def call(tool, **args):
                    result = await session.call_tool(tool, args)
                    return json.loads(result.content[0].text)
            yield Calls


async def hunt_and_verify(docs):
    # Set exact scope before importing config/playbooks: IDX is bound at import time.
    os.environ["HUNT_INDEX"] = INDEX
    os.environ["HUNT_INDEX_PREFIX"] = "security-events-"
    os.environ["HUNT_ES_MCP_CMD"] = "python -m es_mcp_server.server"
    os.environ["HUNT_FORCE_RULES"] = "1"
    from threat_hunting import config
    config.HUNT_INDEX = INDEX
    config.ES_MCP_CMD = os.environ["HUNT_ES_MCP_CMD"]
    from threat_hunting.playbooks import BASE
    from threat_hunting.run import run_hunt

    assert BASE["bruteforce_min_failures"] == 20, "Expected unchanged 20-failure policy"
    run_id = datetime.now(timezone.utc).strftime("c1-ssh-positive-%Y%m%dT%H%M%S-%fZ")
    assert not (config.RUNS_DIR / run_id).exists()
    hypothesis = f"An external IP brute-forced SSH on {HOST} and then successfully logged in on 2026-10-02."
    print(f"Running C2 via C1; inspect runs/{run_id}/result.json and audit/{run_id}.jsonl if verification stops.")
    result = await run_hunt(hypothesis, run_id=run_id)
    saved = json.loads((config.RUNS_DIR / run_id / "result.json").read_text())
    assert saved == result
    assert saved["manifest"]["index"] == INDEX
    assert saved["manifest"]["mcp_servers"]["es"] == "python -m es_mcp_server.server"
    assert saved["verdict"]["label"] == "SUPPORTED", f"Unexpected verdict; inspect runs/{run_id}/result.json"
    assert not saved["self_check"]["failed"] and saved["claims"]
    assert saved["self_check"]["self_checked"] == len(saved["claims"])
    assert {c["technique"] for c in saved["claims"]} == {"T1110", "T1078"}
    for sid in (f"T1078-first-{SOURCE_IP}", f"T1078-b-{SOURCE_IP}"):
        assert saved["step_results"][sid]["status"] == "ok", f"Missing successful-login correlation: {sid}"
    assert saved["step_results"][f"T1078-b-{SOURCE_IP}"]["total"] == 1
    audit = [json.loads(line) for line in (config.AUDIT_DIR / f"{run_id}.jsonl").read_text().splitlines()]
    by_call = {record["call_id"]: record for record in audit}
    evidence = {entry["evidence_id"]: entry for entry in saved["evidence"]}
    trace = [json.loads(line) for line in (config.RUNS_DIR / run_id / "trace.jsonl").read_text().splitlines()]
    assert all(record["ok"] for record in trace)
    assert all(record["call_id"] in by_call for record in trace if record["server"] == "es")
    assert all(record["params"].get("index", record["params"].get("index_pattern", INDEX)) == INDEX for record in audit)
    for sid in ("T1110-a", "T1078-a"):
        record = by_call[saved["step_results"][sid]["call_id"]]
        assert record["total"] == 25
        assert json.loads(record["digest"])["result"] == [{"key": SOURCE_IP, "count": 25}]
    success_record = by_call[saved["step_results"][f"T1078-b-{SOURCE_IP}"]["call_id"]]
    assert {"field": "event.outcome", "op": "eq", "value": "success"} in success_record["params"]["filters"]
    assert success_record["returned_ids"] == [f"{INDEX}/c1-ssh-positive-26"]
    expected_docs = {f"{INDEX}/{doc['event']['id']}": doc for doc in docs}
    verified_ids = set()
    async with c1_session(run_id + "-verification") as mcp:
        for claim in saved["claims"]:
            assert claim["status"] == "self_checked"
            for evidence_id in claim["evidence_ids"]:
                entry = evidence[evidence_id]
                record = by_call[entry["call_id"]]
                assert record["ok"] and record["total"] == entry["total_hits"]
                assert set(entry["event_ids"]) <= set(record["returned_ids"])
            if claim["kind"] == "aggregate":
                replay = claim["replay"]
                actual = await mcp.call(replay["tool"], **replay["params"])
                assert "error" not in actual
                bucket = next(b for b in actual["result"] if str(b["key"]) == replay["bucket_key"])
                assert bucket["count"] == replay["count"] == 25
                assert claim["facts"]["count"] == "25" and claim["facts"]["bucket_key"] == SOURCE_IP
            for reference in claim["event_ids"]:
                assert reference in expected_docs
                index, event_id = reference.split("/", 1)
                actual = await mcp.call("get_event", index=index, event_id=event_id)
                assert "error" not in actual
                original = expected_docs[reference]
                for field, value in (("@timestamp", original["@timestamp"]), ("event.original", original["event"]["original"]),
                                     ("source.ip", SOURCE_IP), ("host.name", HOST), ("user.name", "admin")):
                    assert actual["event"][field] == value
                if claim["technique"] == "T1078":
                    assert original["event"]["outcome"] == "success"
                    assert original["@timestamp"] > docs[24]["@timestamp"]
                    assert claim["facts"] == {"source.ip": SOURCE_IP, "user.name": "admin", "host.name": HOST}
                verified_ids.add(reference)
    assert verified_ids == set(expected_docs), "Not all fixture documents were cited and independently retrieved"
    summary = {"run_id": run_id, "index": INDEX, "verdict": saved["verdict"],
               "claims": len(saved["claims"]), "verified_document_ids": sorted(verified_ids),
               "aggregate_replayed": True}
    path = config.RUNS_DIR / run_id / "c1-verification.json"
    path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Verified {len(saved['claims'])} grounded claims and all 26 document references: {path.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("check-fixture", "ingest", "verify", "hunt"))
    args = parser.parse_args()
    docs = fixture()
    before = hashlib.sha256(NEGATIVE.read_bytes()).hexdigest() if NEGATIVE.exists() else None
    try:
        if args.phase == "check-fixture":
            print("Fixture valid: 25 failures followed by 1 success; 26 unique IDs; fixed UTC timestamps.")
        elif args.phase == "ingest":
            ingest(docs)
        elif args.phase == "verify":
            verify_index(docs)
        else:
            verify_index(docs)
            asyncio.run(hunt_and_verify(docs))
    finally:
        if before is not None:
            assert hashlib.sha256(NEGATIVE.read_bytes()).hexdigest() == before, "Negative result changed"


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Backend exceptions can contain connection details. Keep terminal output secret-free.
        print(f"Validation stopped ({type(exc).__name__}); no existing indices were modified or deleted.")
        raise SystemExit(1)
