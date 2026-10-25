"""C1 promotion contract tests, including real MCP stdio and C2 routing."""
import asyncio
import json
import sys
from unittest.mock import Mock

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from es_mcp_server import server, tools
from dev.es_mcp_standin import server as standin
from tests.c1_mcp_fixture import FakeElasticsearch, INDEX, ORIGINAL, TIMESTAMP
from threat_hunting import config
from threat_hunting.hunter import HuntState, run_step
from threat_hunting.mcp_client import McpHunt
from threat_hunting.models import HuntPlan, PlanStep

REQUIRED_TOOLS = {"describe_data", "search", "count", "aggregate", "get_event",
                  "save_finding", "get_audit_log"}
WINDOW = {"index": INDEX, "time_from": TIMESTAMP, "time_to": "2026-10-02T00:00:00Z"}


@pytest.fixture
def backend(monkeypatch, tmp_path):
    es = FakeElasticsearch()
    monkeypatch.setattr(config, "AUDIT_DIR", tmp_path)
    monkeypatch.setattr(config, "HUNT_INDEX_PREFIX", "security-events-")
    monkeypatch.setattr(server, "es_client", lambda: es)
    monkeypatch.setattr(standin, "es_client", lambda: es)
    return es


def decode(result):
    # FastMCP may return (content, structuredContent); C2 consumes the first text block.
    content = result[0] if isinstance(result, tuple) else result
    assert content[0].type == "text"
    return json.loads(content[0].text)


def test_tool_schemas_match_standin(backend):
    async def check():
        promoted = {t.name: t.inputSchema for t in await server.build("new").list_tools()}
        original = {t.name: t.inputSchema for t in await standin.build("old").list_tools()}
        assert promoted.keys() == original.keys() == REQUIRED_TOOLS
        assert promoted == original

    asyncio.run(check())


def test_all_tools_return_c2_response_shapes(backend):
    async def check():
        mcp = server.build("shapes")

        async def call(name, **kwargs):
            result = decode(await mcp.call_tool(name, kwargs))
            assert result["tool"] == name and "error" not in result
            assert "call_id" in result
            return result

        discovery = await call("describe_data", index_pattern=INDEX)
        assert discovery["sources"] == [{"dataset": "linux.auth", "docs": 1,
                                          "first_event": TIMESTAMP, "last_event": TIMESTAMP}]
        assert "host.name:keyword" in discovery["fields"]
        found = await call("search", **WINDOW, fields=["@timestamp", "host.name"], size=999)
        assert found["total"] == found["returned"] == 1 and not found["truncated"]
        assert found["hits"] == [{"index": INDEX, "event_id": "doc-1",
                                   "fields": {"@timestamp": TIMESTAMP, "host.name": "WS-01"}}]
        assert found["dsl"]["size"] == backend.requests[-1]["size"] == 200
        counted = await call("count", **WINDOW)
        assert counted["total"] == 1 and "query" in counted["dsl"]
        aggregated = await call("aggregate", **WINDOW, agg="terms", field="host.name")
        assert aggregated["total"] == 1 and aggregated["result"] == [{"key": "WS-01", "count": 1}]
        event = await call("get_event", index=INDEX, event_id="doc-1")
        assert event["event"]["event.original"] == ORIGINAL and event["total"] == 1
        saved = await call("save_finding", claim="Example finding", evidence_ids=[f"{INDEX}/doc-1"])
        assert saved["saved"] and saved["total"] == 1
        audit = await call("get_audit_log")
        assert audit["n"] == 6
        assert audit["records"][1]["returned_ids"] == [f"{INDEX}/doc-1"]
        assert audit["records"][1]["dsl"] == found["dsl"]

    asyncio.run(check())


def test_filters_and_error_envelope_are_preserved(backend):
    async def check():
        mcp = server.build("filters")
        filters = [{"field": "host.name", "op": "wildcard", "value": "*WS*"}]
        result = decode(await mcp.call_tool("search", {**WINDOW, "filters": filters}))
        assert result["dsl"]["query"]["bool"]["filter"][1] == {
            "wildcard": {"host.name": {"value": "*WS*", "case_insensitive": True}}}
        result = decode(await mcp.call_tool("count", {**WINDOW, "index": ".security"}))
        assert result["call_id"] and result["tool"] == "count" and isinstance(result["error"], str)
        result = decode(await mcp.call_tool("save_finding", {"claim": "No evidence", "evidence_ids": []}))
        assert result["call_id"] and "error" in result

    asyncio.run(check())


@pytest.mark.parametrize("url, ca", [("https://localhost:9200", "cluster-ca.crt"),
                                     ("https://localhost:9200", ""),
                                     ("http://127.0.0.1:9200", "")])
def test_client_configuration_keeps_tls_verification(monkeypatch, url, ca):
    constructor = Mock()
    monkeypatch.setattr(tools, "Elasticsearch", constructor)
    monkeypatch.setattr(config, "ES_URL", url)
    monkeypatch.setattr(config, "ES_API_KEY", "test-only-api-key")
    monkeypatch.setattr(config, "ES_CA_CERT", ca)
    assert tools.es_client() is constructor.return_value
    expected = {"api_key": "test-only-api-key", "verify_certs": True,
                "request_timeout": config.QUERY_TIMEOUT_S}
    if ca:
        expected["ca_certs"] = ca
    constructor.assert_called_once_with(url, **expected)


def test_production_entrypoint_over_real_stdio(tmp_path):
    async def check():
        # No ES request is made: initialize, discover tools and call a local audit helper.
        # Run the actual module entry point with an isolated audit directory.
        bootstrap = ("import runpy; from pathlib import Path; from threat_hunting import config; "
                     f"config.AUDIT_DIR = Path({str(tmp_path)!r}); "
                     "runpy.run_module('es_mcp_server.server', run_name='__main__')")
        params = StdioServerParameters(command=sys.executable, args=["-c", bootstrap],
                                       cwd=str(config.ROOT), env={
                                           "ES_URL": "https://localhost:9200", "ES_API_KEY": "",
                                           "ES_CA_CERT": "", "HUNT_RUN_ID": "stdio-discovery"})
        async with asyncio.timeout(30):
            async with stdio_client(params) as (reader, writer):
                async with ClientSession(reader, writer) as client:
                    await client.initialize()
                    assert {t.name for t in (await client.list_tools()).tools} == REQUIRED_TOOLS
                    result = await client.call_tool("save_finding", {"claim": "Transport test",
                                                                    "evidence_ids": [f"{INDEX}/doc-1"]})
                    assert not result.isError
                    body = json.loads(result.content[0].text)
                    assert body["tool"] == "save_finding" and body["saved"] and body["call_id"]

    asyncio.run(check())


def test_real_c2_client_and_hunter_consume_c1_responses(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    monkeypatch.setenv("HUNT_INDEX_PREFIX", "security-events-")
    monkeypatch.setenv("HUNT_INDEX", INDEX)

    async def check():
        async with asyncio.timeout(30):
            async with McpHunt("c1-client", servers={"es": "python -m tests.c1_mcp_fixture"}) as client:
                assert set(client.route) == REQUIRED_TOOLS
                discovery = await client.call("describe_data", index_pattern=INDEX)
                assert discovery["sources"][0]["dataset"] == "linux.auth"
                step = PlanStep(step_id="s1", technique="T1110", tool="search", purpose="C1 compatibility",
                                params={**WINDOW, "fields": ["@timestamp", "host.name"]})
                plan = HuntPlan(hypothesis="Test", techniques=["T1110"], required_sources=["auth"],
                                time_range={"from": WINDOW["time_from"], "to": WINDOW["time_to"]},
                                steps=[step], success_criteria=[], refutation_criteria=[])
                state = HuntState(plan)
                result = await run_step(client, state, step)
                assert result["total"] == 1 and state.step_results["s1"]["status"] == "ok"
                assert state.evidence[0].event_ids == [f"{INDEX}/doc-1"]
                counted = await client.call("count", **WINDOW)
                assert counted["total"] == 1
                aggregated = await client.call("aggregate", **WINDOW, agg="terms", field="host.name")
                assert aggregated["result"] == [{"key": "WS-01", "count": 1}]
                event = await client.call("get_event", index=INDEX, event_id="doc-1")
                assert event["event"]["event.original"] == ORIGINAL
                await client.call("save_finding", claim="Client test", evidence_ids=[f"{INDEX}/doc-1"])
                assert (await client.call("get_audit_log"))["n"] == 6
        trace = [json.loads(line) for line in client.trace_path.read_text().splitlines()]
        assert len(trace) == 7 and all(r["ok"] and r["request_hash"] for r in trace)

    asyncio.run(check())
