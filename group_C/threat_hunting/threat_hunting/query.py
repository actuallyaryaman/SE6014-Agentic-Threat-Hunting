"""Structured filter language -> Elasticsearch query DSL. Raw DSL, scripts and unbounded queries are impossible by construction.

A filter is {field, op, value}; op in eq|neq|in|wildcard|prefix|contains|gte|lte|gt|lt|exists. `known` maps field -> ES type
(from the index mapping, including multi-field subfields such as "url.original.keyword").
Ported from the prototype's src/mcp_server/guards.py; used by both ES MCP servers (C1's and the dev stand-in) and by the agent's validator."""
from __future__ import annotations
import difflib, ipaddress, re
from datetime import datetime, timezone, timedelta
from . import config

OPS = {"eq", "neq", "in", "wildcard", "prefix", "contains", "gte", "lte", "gt", "lt", "exists"}
FORBIDDEN_KEYS = {"script", "runtime_mappings", "script_fields", "scripted_metric"}
_PART = r"[a-z0-9*_.-]+"


class ToolError(ValueError):
    pass


def interval_seconds(interval: str) -> float:
    m = re.fullmatch(r"(\d+)(ms|s|m|h|d)", interval or "")
    if not m or int(m.group(1)) == 0:
        raise ToolError(f"interval must look like 30s, 15m, 1h or 1d (got {interval!r})")
    return int(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def check_index(index: str, prefix: str | None = None) -> str:
    prefix = prefix or config.HUNT_INDEX_PREFIX
    p = re.escape(prefix) + _PART
    if not isinstance(index, str) or ".." in index or not re.fullmatch(f"{p}(,{p})*", index):
        raise ToolError(f"index must be one or more patterns starting with '{prefix}' (got {index!r})")
    return index


def parse_time(s: str) -> datetime:
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        raise ToolError(f"time must be ISO-8601, e.g. 2026-10-01T13:00:00Z (got {s!r})")
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def check_range(t_from: str, t_to: str) -> tuple[str, str]:
    a, b = parse_time(t_from), parse_time(t_to)
    if b <= a:
        raise ToolError("time_to must be after time_from")
    if b - a > timedelta(days=config.MAX_WINDOW_DAYS):
        raise ToolError(f"time window too large (max {config.MAX_WINDOW_DAYS} days)")
    f = lambda d: d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return f(a), f(b)


def check_field(field: str, known) -> str:
    if known and field not in known:
        hint = difflib.get_close_matches(field, known, n=3)
        raise ToolError(f"unknown field {field!r}" + (f"; did you mean {hint}?" if hint else "; call describe_data to list fields"))
    return field


def exact_field(field: str, known) -> str:
    """Term, wildcard, prefix and aggregations need a keyword field: use the .keyword subfield of a text field when it exists."""
    if isinstance(known, dict) and known.get(field) == "text" and known.get(f"{field}.keyword") == "keyword":
        return f"{field}.keyword"
    return field


def tiebreak_field(known) -> str | None:
    """Secondary sort key so equal timestamps always come back in the same order."""
    for f in ("event.original", "event.original.keyword"):
        if isinstance(known, dict) and known.get(f) == "keyword":
            return f
    return None


def _is_cidr(v) -> bool:
    if not isinstance(v, str) or "/" not in v:
        return False
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def _clause(f: dict, known) -> dict:
    if not isinstance(f, dict) or set(f) - {"field", "op", "value"} or "field" not in f:
        raise ToolError(f"filter must be {{field, op, value}}, got {f!r}")
    op, field, val = f.get("op", "eq"), check_field(f["field"], known), f.get("value")
    if op not in OPS:
        raise ToolError(f"op must be one of {sorted(OPS)}")
    if op == "exists":
        return {"exists": {"field": field}}
    if val is None:
        raise ToolError(f"filter on {field} needs a value")
    ftype = known.get(field) if isinstance(known, dict) else None
    if op == "eq":
        if _is_cidr(val) and ftype not in (None, "ip"):
            # a CIDR on a keyword/text field silently matches nothing; fail loudly instead
            raise ToolError(f"CIDR value {val!r} needs an ip-typed field; {field} is {ftype}")
        if isinstance(val, str) and ftype in (None, "keyword", "text"):
            return {"term": {exact_field(field, known): {"value": val, "case_insensitive": True}}}
        return {"term": {field: val}}
    if op == "neq":
        return {"bool": {"must_not": [_clause({"field": field, "op": "eq", "value": val}, known)]}}
    if op == "in":
        if not isinstance(val, list) or not val:
            raise ToolError("op 'in' needs a non-empty list")
        return {"bool": {"should": [_clause({"field": field, "op": "eq", "value": v}, known) for v in val], "minimum_should_match": 1}}
    if op in ("wildcard", "prefix"):
        xf = exact_field(field, known)
        if ftype is not None and known.get(xf) != "keyword":
            raise ToolError(f"op {op} only works on keyword fields; {field} is {ftype}")
        return {op: {xf: {"value": str(val), "case_insensitive": True}}}
    if op == "contains":
        if ftype == "keyword":      # a phrase match on a keyword only matches the whole value
            return {"wildcard": {field: {"value": f"*{val}*", "case_insensitive": True}}}
        return {"match_phrase": {field: str(val)}}
    return {"range": {field: {op: val}}}


def build_query(t_from: str, t_to: str, filters=None, must_not=None, any_of=None, known=None) -> dict:
    known = known or {}
    a, b = check_range(t_from, t_to)
    bool_q: dict = {"filter": [{"range": {"@timestamp": {"gte": a, "lt": b}}}]}
    for f in filters or []:
        bool_q["filter"].append(_clause(f, known))
    if must_not:
        bool_q["must_not"] = [_clause(f, known) for f in must_not]
    if any_of:
        bool_q["filter"].append({"bool": {"should": [_clause(f, known) for f in any_of], "minimum_should_match": 1}})
    q = {"bool": bool_q}
    _no_forbidden(q)
    return q


def _no_forbidden(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in FORBIDDEN_KEYS:
                raise ToolError(f"{k} is not allowed")
            _no_forbidden(v)
    elif isinstance(o, list):
        for v in o:
            _no_forbidden(v)


def cap_size(size: int) -> int:
    if not isinstance(size, int) or size < 0:
        raise ToolError("size must be a non-negative integer")
    return min(size, config.MAX_RESULT_SIZE)


def flatten(d: dict, prefix="") -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def compact(src: dict, fields: list[str] | None, limit=300) -> tuple[dict, bool]:
    flat = flatten(src)
    flat.pop("event.original", None)
    if fields:
        flat = {k: v for k, v in flat.items() if k in fields}
    trunc = False
    for k, v in list(flat.items()):
        if isinstance(v, str) and len(v) > limit:
            flat[k] = v[:limit] + "…"; trunc = True
    return flat, trunc
