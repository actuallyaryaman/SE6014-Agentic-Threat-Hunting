"""Test double for the C1 hunt tools (same names, arguments and response shapes) and a gateway over them."""

from __future__ import annotations

import json
from typing import Any, Optional

from group_C.threat_hunting.evidence.audit import result_hash
from group_C.threat_hunting.evidence.contracts import AuditRecord
from group_C.threat_hunting.evidence.gateways import EventFetch, NotReplayable, flatten_event

from .mini_es import MiniES

IOCS = [{"value": "203.0.113.50", "note": "known C2 server (synthetic)"}]


def _clause(f: dict) -> dict:
    op, field, val = f.get("op", "eq"), f["field"], f.get("value")
    if op == "exists":
        return {"exists": {"field": field}}
    if op == "eq":
        return {"term": {field: {"value": val, "case_insensitive": True}}} if isinstance(val, str) else {"term": {field: val}}
    if op == "neq":
        return {"bool": {"must_not": [_clause({"field": field, "op": "eq", "value": val})]}}
    if op == "in":
        return {"bool": {"should": [_clause({"field": field, "op": "eq", "value": v}) for v in val], "minimum_should_match": 1}}
    if op == "wildcard":
        return {"wildcard": {field: {"value": str(val), "case_insensitive": True}}}
    if op == "prefix":
        return {"prefix": {field: {"value": str(val)}}}
    if op in ("gt", "gte", "lt", "lte"):
        return {"range": {field: {op: val}}}
    raise ValueError(op)


def build_query(time_from: str, time_to: str, filters=None, must_not=None, any_of=None) -> dict:
    q: dict[str, Any] = {"filter": [{"range": {"@timestamp": {"gte": time_from, "lt": time_to}}}]}
    q["filter"] += [_clause(f) for f in filters or []]
    if must_not:
        q["must_not"] = [_clause(f) for f in must_not]
    if any_of:
        q["filter"].append({"bool": {"should": [_clause(f) for f in any_of], "minimum_should_match": 1}})
    return {"bool": q}


class FakeHuntTools:
    """Implements search / count / aggregate / get_event / coverage_check / check_ioc and audits every call."""

    def __init__(self, es: MiniES, run_id: str = "hunt-test", iocs: Optional[list[dict]] = None) -> None:
        self.es, self.run_id, self.iocs = es, run_id, IOCS if iocs is None else iocs
        self.audit: list[AuditRecord] = []

    def _record(self, tool: str, params: dict, dsl: Any, out: dict, ids: list[str], ok: bool = True, error: str = "") -> dict:
        call_id = f"{self.run_id}-{len(self.audit) + 1:04d}"
        total = out.get("total") if ok else None
        digest = json.dumps(out, default=str, sort_keys=True) if ok else ""
        self.audit.append(AuditRecord(call_id=call_id, ts="2026-10-21T00:00:00Z", tool=tool, params=params, dsl=dsl,
                                      total=total, returned_ids=ids[:500], result_hash=result_hash(ids, total),
                                      ok=ok, error=error, digest=digest[:20000]))
        return {"call_id": call_id, "tool": tool, "dsl": dsl, **out} if ok else {"call_id": call_id, "tool": tool, "error": error}

    def search(self, index, time_from, time_to, filters=None, must_not=None, any_of=None, fields=None, size=50, sort="asc"):
        params = dict(index=index, time_from=time_from, time_to=time_to, filters=filters, must_not=must_not, any_of=any_of,
                      fields=fields, size=size, sort=sort)
        dsl = {"query": build_query(time_from, time_to, filters, must_not, any_of), "size": size,
               "sort": [{"@timestamp": {"order": sort}}], "track_total_hits": True}
        r = self.es.search(index, dsl)
        hits = [{"event_id": h["_id"], "index": h["_index"], "fields": flatten_event(h["_source"])} for h in r["hits"]["hits"]]
        total = r["hits"]["total"]["value"]
        out = {"total": total, "returned": len(hits), "truncated": total > len(hits), "hits": hits}
        return self._record("search", params, dsl, out, [f'{h["index"]}/{h["event_id"]}' for h in hits])

    def count(self, index, time_from, time_to, filters=None, must_not=None, any_of=None):
        params = dict(index=index, time_from=time_from, time_to=time_to, filters=filters, must_not=must_not, any_of=any_of)
        dsl = {"query": build_query(time_from, time_to, filters, must_not, any_of)}
        return self._record("count", params, dsl, {"total": self.es.count(index, dsl)["count"]}, [])

    def aggregate(self, index, time_from, time_to, agg="terms", field=None, filters=None, must_not=None, any_of=None,
                  size=20, sum_field=None, distinct_field=None):
        params = dict(index=index, time_from=time_from, time_to=time_to, agg=agg, field=field, filters=filters,
                      must_not=must_not, any_of=any_of, size=size, sum_field=sum_field, distinct_field=distinct_field)
        a: dict[str, Any] = {"terms": {"field": field, "size": size}}
        if sum_field:
            a["aggs"] = {"s": {"sum": {"field": sum_field}}}
        elif distinct_field:
            a["aggs"] = {"d": {"cardinality": {"field": distinct_field}}}
        dsl = {"query": build_query(time_from, time_to, filters, must_not, any_of), "size": 0, "aggs": {"a": a}}
        r = self.es.search(index, dsl)
        result = [{"key": b["key"], "count": b["doc_count"], **({"sum": b["s"]["value"]} if "s" in b else {}),
                   **({"distinct": b["d"]["value"]} if "d" in b else {})} for b in r["aggregations"]["a"]["buckets"]]
        out = {"total": r["hits"]["total"]["value"], "result": result}
        return self._record("aggregate", params, dsl, out, [json.dumps(result, sort_keys=True, default=str)])

    def get_event(self, index, event_id):
        params = dict(index=index, event_id=event_id)
        doc = self.es.get(index, event_id)
        if doc is None:
            return self._record("get_event", params, None, {}, [], ok=False, error=f"NotFoundError: {index}/{event_id}")
        return self._record("get_event", params, None, {"total": 1, "event": flatten_event(doc)}, [f"{index}/{event_id}"])

    def coverage_check(self, indices, time_from, time_to, bucket_minutes=60):
        from datetime import datetime, timedelta
        params = dict(indices=indices, time_from=time_from, time_to=time_to, bucket_minutes=bucket_minutes)
        end_incl = (datetime.fromisoformat(time_to.replace("Z", "+00:00")) - timedelta(milliseconds=1)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        dsl, per = {}, {}
        for idx in indices:
            dsl[idx] = {"query": {"range": {"@timestamp": {"gte": time_from, "lt": time_to}}}, "size": 0,
                        "aggs": {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": f"{bucket_minutes}m",
                                                          "min_doc_count": 0, "extended_bounds": {"min": time_from, "max": end_incl}}}}}
            r = self.es.search(idx, dsl[idx])
            bk = [{"start": x["key_as_string"], "docs": x["doc_count"]} for x in r["aggregations"]["h"]["buckets"]]
            per[idx] = {"total": r["hits"]["total"]["value"], "buckets": bk, "empty_buckets": [x["start"] for x in bk if x["docs"] == 0]}
        out = {"total": sum(v["total"] for v in per.values()), "coverage": per}
        return self._record("coverage_check", params, dsl, out, [json.dumps({k: v["total"] for k, v in per.items()}, sort_keys=True)])

    def check_ioc(self, value):
        m = [i for i in self.iocs if i["value"].lower() == value.strip().lower()]
        return self._record("check_ioc", {"value": value}, None, {"total": len(m), "matches": m}, [i["value"] for i in m])


class FakeGateway:
    """Verifier gateway over FakeHuntTools, with knobs to tamper with or delete events."""

    mode = "fake"

    def __init__(self, es: MiniES, tamper: Optional[dict[str, dict]] = None, missing: Optional[set[str]] = None,
                 no_replay: bool = False) -> None:
        self.tools = FakeHuntTools(es, run_id="hunt-test-verify")
        self.tamper, self.missing, self.no_replay = tamper or {}, missing or set(), no_replay
        self.fetched: list[str] = []

    async def get_event(self, index: str, event_id: str) -> EventFetch:
        ref = f"{index}/{event_id}"
        self.fetched.append(ref)
        if ref in self.missing:
            return EventFetch(None, "NotFoundError")
        r = self.tools.get_event(index, event_id)
        if "error" in r:
            return EventFetch(None, r["error"])
        event = dict(r["event"])
        event.update(self.tamper.get(ref, {}))
        return EventFetch(event)

    async def rerun(self, record: AuditRecord) -> dict[str, Any]:
        if self.no_replay:
            raise NotReplayable("replay disabled in this test")
        return getattr(self.tools, record.tool)(**record.params)
