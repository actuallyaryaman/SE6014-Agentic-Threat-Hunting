"""Stand-in for the C1 MCP server (tests only): the hunt tools over the synthetic sample, via stdio."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # repo root

from tests.group_C.c3.fake_tools import FakeHuntTools  # noqa: E402
from tests.group_C.c3.mini_es import MiniES  # noqa: E402

try:  # MCP SDK v2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # MCP SDK v1
    from mcp.server.fastmcp import FastMCP as _Server

tools = FakeHuntTools(MiniES(), run_id="mcp-verify")
server = _Server("fake-c1-hunt-tools")


@server.tool()
def get_event(index: str, event_id: str) -> dict:
    """Fetch one event by index and id."""
    return tools.get_event(index, event_id)


@server.tool()
def search(index: str, time_from: str, time_to: str, filters: Optional[list[dict[str, Any]]] = None,
           must_not: Optional[list[dict[str, Any]]] = None, any_of: Optional[list[dict[str, Any]]] = None,
           fields: Optional[list[str]] = None, size: int = 50, sort: str = "asc") -> dict:
    """Search events."""
    return tools.search(index, time_from, time_to, filters, must_not, any_of, fields, size, sort)


@server.tool()
def count(index: str, time_from: str, time_to: str, filters: Optional[list[dict[str, Any]]] = None,
          must_not: Optional[list[dict[str, Any]]] = None, any_of: Optional[list[dict[str, Any]]] = None) -> dict:
    """Count events."""
    return tools.count(index, time_from, time_to, filters, must_not, any_of)


@server.tool()
def aggregate(index: str, time_from: str, time_to: str, agg: str = "terms", field: Optional[str] = None,
              filters: Optional[list[dict[str, Any]]] = None, must_not: Optional[list[dict[str, Any]]] = None,
              any_of: Optional[list[dict[str, Any]]] = None, size: int = 20, sum_field: Optional[str] = None,
              distinct_field: Optional[str] = None) -> dict:
    """Aggregate events."""
    return tools.aggregate(index, time_from, time_to, agg, field, filters, must_not, any_of, size, sum_field, distinct_field)


@server.tool()
def coverage_check(indices: list[str], time_from: str, time_to: str, bucket_minutes: int = 60) -> dict:
    """Events per time bucket."""
    return tools.coverage_check(indices, time_from, time_to, bucket_minutes)


@server.tool()
def check_ioc(value: str) -> dict:
    """Threat-intel lookup."""
    return tools.check_ioc(value)


if __name__ == "__main__":
    server.run()
