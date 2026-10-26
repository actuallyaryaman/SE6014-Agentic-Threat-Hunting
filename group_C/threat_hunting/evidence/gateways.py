"""Gateways: the ways C3 reaches the log store to re-check claims. All of them are read-only.

* ``MCPGateway``     a second, independent connection to the C1 MCP server. Its
                     calls go to their own audit file (for example "<run>-verify").
                     It can also connect to C2's analytics server (check_ioc,
                     gap_check, lookup_attack).
* ``ESGateway``      talks to Elasticsearch directly and replays the DSL recorded in
                     the audit log. Only GET _doc, POST _search and POST _count can
                     leave this client.
* ``OfflineGateway`` has no access. Claims stay "unverified" and the verdict is
                     Inconclusive. It is useful for previewing a report.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .contracts import AuditRecord
from .esclient import DocRef, ReadOnlyES, SourceUnavailable


class GatewayUnavailable(RuntimeError):
    """The log store cannot be reached, or the gateway is offline."""


class NotReplayable(RuntimeError):
    """This gateway cannot re-run that kind of call, for example a threat-intel lookup over plain Elasticsearch."""


@dataclass
class EventFetch:
    """The result of fetching one event: the event, or None with an error message."""

    event: Optional[dict[str, Any]]
    error: str = ""


class Gateway(Protocol):
    """What the verifier needs from a gateway."""

    mode: str

    async def get_event(self, index: str, event_id: str) -> EventFetch: ...

    async def rerun(self, record: AuditRecord) -> dict[str, Any]:
        """Re-run an audited call and return the response in the C1 tool shape."""


class OfflineGateway:
    """A gateway that refuses every call, so nothing gets re-verified."""

    mode = "offline"

    async def get_event(self, index: str, event_id: str) -> EventFetch:
        raise GatewayUnavailable("offline: no log store configured")

    async def rerun(self, record: AuditRecord) -> dict[str, Any]:
        raise GatewayUnavailable("offline: no log store configured")


class MCPGateway:
    """Independent stdio connection to the C1 MCP server.

    Use it as ``async with MCPGateway(...) as gateway:``. Tool names and arguments
    follow the C1 server: get_event(index, event_id), search(...), aggregate(...) and so on.
    """

    mode = "mcp"

    ANALYTICS_TOOLS = {"check_ioc", "gap_check", "lookup_attack"}

    def __init__(self, command: str, args: list[str], run_id: str = "c3-verify", env: Optional[dict[str, str]] = None,
                 analytics: Optional[tuple[str, list[str]]] = None, cwd: Optional[str] = None):
        self.command, self.args, self.cwd = command, args, cwd
        self.analytics = analytics            # (command, args) for the analytics server, if there is one
        self.env = {**os.environ, **(env or {}), "HUNT_RUN_ID": run_id}
        self._stack = None
        self.session = None
        self.analytics_session = None
        self.calls = 0

    @classmethod
    def from_env(cls, run_id: str = "c3-verify") -> "MCPGateway":
        """Build a gateway from the C3_MCP_* environment variables."""
        analytics = None
        if os.getenv("C3_MCP_ANALYTICS_ARGS"):
            analytics = (os.getenv("C3_MCP_ANALYTICS_COMMAND", "python"), os.getenv("C3_MCP_ANALYTICS_ARGS", "").split())
        return cls(os.getenv("C3_MCP_COMMAND", "python"), os.getenv("C3_MCP_ARGS", "-m dev.es_mcp_standin.server").split(), run_id,
                   analytics=analytics, cwd=os.getenv("C3_MCP_CWD") or None)

    async def __aenter__(self) -> "MCPGateway":
        try:
            from contextlib import AsyncExitStack

            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:  # pragma: no cover
            raise GatewayUnavailable("the 'mcp' package is not installed") from exc
        self._stack = AsyncExitStack()
        try:
            read, write = await self._stack.enter_async_context(
                stdio_client(StdioServerParameters(command=self.command, args=self.args, env=self.env, cwd=self.cwd)))
            self.session = await self._stack.enter_async_context(ClientSession(read, write))
            await self.session.initialize()
            if self.analytics:
                analytics_read, analytics_write = await self._stack.enter_async_context(
                    stdio_client(StdioServerParameters(command=self.analytics[0], args=self.analytics[1], env=self.env, cwd=self.cwd)))
                self.analytics_session = await self._stack.enter_async_context(ClientSession(analytics_read, analytics_write))
                await self.analytics_session.initialize()
        except Exception as exc:
            await self._stack.aclose()
            raise GatewayUnavailable(f"cannot start MCP server: {type(exc).__name__}: {exc}") from exc
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._stack:
            await self._stack.aclose()

    async def call(self, tool: str, **args: Any) -> dict[str, Any]:
        """Call one tool and return its answer as a dict. Errors come back as {"error": ...}."""
        if self.session is None:
            raise GatewayUnavailable("MCPGateway used outside 'async with'")
        args = {k: v for k, v in args.items() if v is not None}
        session = self.session
        if tool in self.ANALYTICS_TOOLS:
            if self.analytics_session is None:
                raise NotReplayable(f"{tool} lives on the analytics server, which is not configured (C3_MCP_ANALYTICS_ARGS)")
            session = self.analytics_session
        reply = await session.call_tool(tool, args)
        self.calls += 1
        structured = getattr(reply, "structuredContent", None) or getattr(reply, "structured_content", None)
        if isinstance(structured, dict):
            return structured["result"] if set(structured) == {"result"} and isinstance(structured["result"], dict) else structured
        text = getattr(reply.content[0], "text", None) if getattr(reply, "content", None) else None
        if not text:
            return {"error": f"{tool} returned no text"}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"error": text[:300]}

    async def get_event(self, index: str, event_id: str) -> EventFetch:
        response = await self.call("get_event", index=index, event_id=event_id)
        if "error" in response:
            return EventFetch(None, str(response["error"])[:120])
        return EventFetch(dict(response.get("event") or {}))

    async def rerun(self, record: AuditRecord) -> dict[str, Any]:
        return await self.call(record.tool, **record.params)


@dataclass
class ESGateway:
    """Replays recorded queries straight against Elasticsearch through the read-only client."""

    client: ReadOnlyES = field(default_factory=lambda: ReadOnlyES.from_env())  # type: ignore[arg-type]
    mode: str = "elasticsearch"

    @classmethod
    def from_env(cls) -> "ESGateway":
        """Build a gateway from the ES_* environment variables."""
        return cls(ReadOnlyES.from_env())  # type: ignore[arg-type]

    async def __aenter__(self) -> "ESGateway":
        if not self.client.available():
            raise GatewayUnavailable(f"Elasticsearch unreachable at {self.client.url}")
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def get_event(self, index: str, event_id: str) -> EventFetch:
        try:
            docs = self.client.fetch_documents([DocRef(index, event_id)])
        except SourceUnavailable as exc:
            raise GatewayUnavailable(str(exc)) from exc
        doc = next(iter(docs.values()))
        return EventFetch(flatten_event(doc)) if doc is not None else EventFetch(None, "not found")

    async def rerun(self, record: AuditRecord) -> dict[str, Any]:
        """Replay the DSL recorded for the call and return a response in the C1 tool shape."""
        dsl = record.dsl
        if not isinstance(dsl, dict) or not dsl:
            raise NotReplayable(f"{record.tool}: no recorded DSL to replay")
        try:
            if record.tool == "search":
                response = self.client.post(record.params["index"], "_search", dsl)
                hits = [{"event_id": h["_id"], "index": h["_index"], "fields": flatten_event(h.get("_source") or {})}
                        for h in response["hits"]["hits"]]
                return {"total": _total(response), "returned": len(hits), "hits": hits}
            if record.tool == "count":
                response = self.client.post(record.params["index"], "_count", {"query": dsl["query"]})
                return {"total": response["count"]}
            if record.tool == "aggregate":
                response = self.client.post(record.params["index"], "_search", dsl)
                agg = response["aggregations"]["a"]
                if "buckets" in agg:
                    result: Any = [{"key": b.get("key_as_string", b["key"]), "count": b["doc_count"],
                                    **({"sum": b["s"]["value"]} if "s" in b else {}),
                                    **({"distinct": b["d"]["value"]} if "d" in b else {})} for b in agg["buckets"]]
                else:
                    result = dict(agg)
                return {"total": _total(response), "result": result}
            if record.tool == "coverage_check":
                per_index = {}
                for index, body in dsl.items():
                    response = self.client.post(index, "_search", {**body, "track_total_hits": True})
                    buckets = [{"start": x["key_as_string"], "docs": x["doc_count"]} for x in response["aggregations"]["h"]["buckets"]]
                    per_index[index] = {"total": _total(response), "buckets": buckets,
                                        "empty_buckets": [x["start"] for x in buckets if x["docs"] == 0]}
                return {"total": sum(v["total"] for v in per_index.values()), "coverage": per_index}
        except SourceUnavailable as exc:
            raise GatewayUnavailable(str(exc)) from exc
        raise NotReplayable(f"{record.tool} cannot be replayed over plain Elasticsearch (use the MCP gateway)")


def flatten_event(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested objects into dotted keys, as the C1 server's get_event does. Lists stay as values."""
    out: dict[str, Any] = {}
    for key, value in doc.items():
        if isinstance(value, dict):
            out.update(flatten_event(value, f"{prefix}{key}."))
        else:
            out[f"{prefix}{key}"] = value
    return out


def _total(response: dict[str, Any]) -> int:
    """Read the hit total, which Elasticsearch returns either as a number or as {"value": ...}."""
    total = response["hits"]["total"]
    return int(total["value"] if isinstance(total, dict) else total)


def gateway_from_name(name: str, run_id: str = "c3-verify"):
    """Return the gateway for a --verify value. Unknown names fall back to offline."""
    name = (name or "offline").lower()
    if name in ("es", "elasticsearch"):
        return ESGateway.from_env()
    if name == "mcp":
        return MCPGateway.from_env(run_id)
    return OfflineGateway()


__all__ = ["Gateway", "OfflineGateway", "MCPGateway", "ESGateway", "ReadOnlyES", "EventFetch",
           "GatewayUnavailable", "NotReplayable", "gateway_from_name"]
