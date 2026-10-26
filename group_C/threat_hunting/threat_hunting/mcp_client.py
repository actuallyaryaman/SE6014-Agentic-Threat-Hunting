"""Async MCP client. Starts the ES MCP server (C1's, or the dev stand-in) and C2's analytics server over stdio, routes each
tool to the server that offers it, and appends every call to runs/<run_id>/trace.jsonl. The agent reaches data only here.
Ported from the prototype's src/hunt/mcpclient.py (one server) and extended to two servers plus the client-side trace."""
from __future__ import annotations
import hashlib, json, os, shlex, sys
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from . import config

ES_ENV = ("ES_URL", "ES_API_KEY", "ES_CA_CERT", "HUNT_INDEX", "HUNT_INDEX_PREFIX")
# Tools the agent may call, per server, with the parameters it relies on (DESIGN.md threat T7). Anything else a server offers is
# never routed; a missing tool or parameter stops the run at start-up.
ALLOWED = {
    "es": {"describe_data": {"index_pattern"}, "search": {"index", "time_from", "time_to", "filters", "must_not", "any_of", "fields", "size"},
           "count": {"index", "time_from", "time_to", "filters"}, "aggregate": {"index", "time_from", "time_to", "agg", "field", "interval"}},
    "analytics": {"gap_check": {"buckets"}, "lookup_attack": {"query"}, "check_ioc": {"value"}},
}


def request_hash(tool: str, args: dict) -> str:
    """Canonical request hash: the same tool with the same arguments always hashes the same (used to compare runs)."""
    return hashlib.sha256(json.dumps({"tool": tool, "args": args}, sort_keys=True, default=str).encode()).hexdigest()


class McpHunt:
    def __init__(self, run_id: str, servers: dict[str, str] | None = None):
        self.run_id, self.calls = run_id, 0
        self.servers = servers or {"es": config.ES_MCP_CMD, "analytics": config.ANALYTICS_MCP_CMD}
        self.route: dict[str, tuple[str, ClientSession]] = {}
        self.ignored: list[str] = []           # offered by a server but not on the allowlist
        self.trace_path = config.RUNS_DIR / run_id / "trace.jsonl"
        self._stack = AsyncExitStack()

    async def __aenter__(self):
        for name, cmd in self.servers.items():
            argv = shlex.split(cmd)
            if argv[0] == "python":
                argv[0] = sys.executable
            env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(config.ROOT), "HUNT_RUN_ID": self.run_id}
            if name == "es":                       # only the ES server gets Elasticsearch settings
                env.update({k: os.environ[k] for k in ES_ENV if k in os.environ})
            params = StdioServerParameters(command=argv[0], args=argv[1:], cwd=str(config.ROOT), env=env)
            r, w = await self._stack.enter_async_context(stdio_client(params))
            session = await self._stack.enter_async_context(ClientSession(r, w))
            await session.initialize()
            allowed = ALLOWED.get(name, {})
            for t in (await session.list_tools()).tools:
                if t.name not in allowed:
                    self.ignored.append(f"{name}.{t.name}")
                    continue
                if t.name in self.route:
                    raise RuntimeError(f"tool {t.name!r} is offered by both {self.route[t.name][0]} and {name}")
                missing = allowed[t.name] - set((t.inputSchema or {}).get("properties", {}))
                if missing:
                    raise RuntimeError(f"{name}.{t.name} lacks the parameters the agent relies on: {sorted(missing)}")
                self.route[t.name] = (name, session)
            absent = sorted(set(allowed) - {k for k, (srv, _) in self.route.items() if srv == name})
            if absent:
                raise RuntimeError(f"MCP server {name!r} ({self.servers[name]}) does not offer required tools {absent}")
        self.trace_path.parent.mkdir(parents=True, exist_ok=True)
        return self

    async def __aexit__(self, *a):
        await self._stack.aclose()

    async def call(self, tool: str, **args) -> dict:
        args = {k: v for k, v in args.items() if v is not None}
        server = self.route.get(tool, ("?", None))[0]
        if tool not in self.route:
            out = {"error": f"no MCP server offers tool {tool!r}", "tool": tool}
        else:
            res = await self.route[tool][1].call_tool(tool, args)
            text = res.content[0].text if res.content else "{}"
            try:
                out = json.loads(text)
            except Exception:
                out = {"error": text[:300], "tool": tool}
        self.calls += 1
        rec = {"seq": self.calls, "server": server, "tool": tool, "args": args, "request_hash": request_hash(tool, args),
               "call_id": out.get("call_id"), "ok": "error" not in out, "total": out.get("total"), "dsl": out.get("dsl"),
               **({"error": out["error"]} if "error" in out else {})}
        with open(self.trace_path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        return out
