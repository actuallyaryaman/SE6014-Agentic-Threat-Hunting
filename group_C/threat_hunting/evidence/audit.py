"""The result hash that the C1 MCP server writes for every tool call.

A replayed query counts as identical when it returns the same result IDs and
the same total, which means the same ``result_hash``. The formula has to match
the server's byte for byte, or every replay would look like a mismatch.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

REPLAYABLE_TOOLS = {"search", "aggregate", "count", "check_ioc", "lookup_attack", "coverage_check", "gap_check"}


def result_hash(ids: list[str], total: int | None) -> str:
    """First 16 hex characters of sha256([sorted ids, total]).

    The default json.dumps spacing is deliberate: the server hashes the same bytes.
    """
    return hashlib.sha256(json.dumps([sorted(ids), total]).encode()).hexdigest()[:16]


def result_ids(tool: str, response: Mapping[str, Any]) -> list[str]:
    """Return the IDs the server records for this tool's response."""
    if tool == "search":
        return [f'{h["index"]}/{h["event_id"]}' for h in response.get("hits", [])]
    if tool == "aggregate":
        return [json.dumps(response.get("result"), sort_keys=True, default=str)]
    if tool == "coverage_check":
        per = response.get("coverage", {}) or {}
        return [json.dumps({k: v.get("total") for k, v in per.items()}, sort_keys=True)]
    if tool == "check_ioc":
        return [m["value"] for m in response.get("matches", [])]
    if tool == "lookup_attack":
        return sorted(response.get("techniques", {}) or {})
    if tool == "get_event":
        return [f'{response.get("index", "")}/{response.get("event_id", "")}'] if response.get("event_id") else []
    return []  # count and anything else


def response_hash(tool: str, response: Mapping[str, Any]) -> str:
    """Hash a tool response the way the server hashes it."""
    return result_hash(result_ids(tool, response), response.get("total"))
