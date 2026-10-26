"""Tool allowlist at start-up (DESIGN.md threat T7). Starts the real MCP servers over stdio; no Elasticsearch call is made."""
import asyncio
import pytest
from threat_hunting import config
from threat_hunting.mcp_client import ALLOWED, McpHunt


def _connect(servers):
    async def go():
        async with McpHunt("pytest-allowlist", servers) as m:
            return dict(m.route), list(m.ignored)
    return asyncio.run(go())


def test_only_allowlisted_tools_are_routed():
    route, ignored = _connect({"es": config.ES_MCP_CMD, "analytics": config.ANALYTICS_MCP_CMD})
    assert set(route) == set(ALLOWED["es"]) | set(ALLOWED["analytics"])
    assert {"es.save_finding", "es.get_audit_log", "es.get_event"} <= set(ignored)


def test_a_server_without_the_required_tools_is_refused():
    with pytest.raises(RuntimeError, match="does not offer required tools"):
        _connect({"es": config.ES_MCP_CMD, "analytics": config.ES_MCP_CMD})
