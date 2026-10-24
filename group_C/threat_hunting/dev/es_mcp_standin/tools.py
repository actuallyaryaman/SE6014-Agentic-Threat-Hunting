"""Read-only hunting tools over Elasticsearch. Business logic is separate from MCP wiring so it is unit-testable.
TEMPORARY STAND-IN for C1's ES MCP server; ported from the prototype's src/mcp_server/hunt_tools.py (coverage_check, lookup_attack
and check_ioc moved to C2's analytics server; describe_data now groups by event.dataset)."""
from __future__ import annotations
import json
from datetime import timedelta
from elasticsearch import Elasticsearch
from threat_hunting import config
from threat_hunting.query import (ToolError, build_query, cap_size, check_field, check_index, check_range, compact, exact_field,
                                  flatten, parse_time, tiebreak_field)
from .audit import Audit

AGGS = {"terms", "rare_terms", "cardinality", "stats", "date_histogram", "sum", "max"}


def es_client() -> Elasticsearch:
    """Read-only API key; CA certificate when the cluster uses TLS (team stack: Elastic 8.19 with security on)."""
    kw = {"api_key": config.ES_API_KEY} if config.ES_API_KEY else {}
    if config.ES_CA_CERT:
        kw["ca_certs"] = config.ES_CA_CERT
    return Elasticsearch(config.ES_URL, request_timeout=config.QUERY_TIMEOUT_S, **kw)


class HuntTools:
    def __init__(self, es, audit: Audit):
        self.es, self.audit = es, audit
        self._fields: dict[str, dict[str, str]] = {}

    # ---- helpers
    def _known(self, index: str) -> dict[str, str]:
        if index not in self._fields:
            try:
                m = self.es.indices.get_mapping(index=index, expand_wildcards="open")
            except Exception:
                return {}
            names: dict[str, str] = {}
            def walk(props, pre=""):
                for k, v in props.items():
                    if "properties" in v:
                        walk(v["properties"], f"{pre}{k}.")
                    else:
                        names[f"{pre}{k}"] = v.get("type", "object")
                        for sub, sv in v.get("fields", {}).items():
                            names[f"{pre}{k}.{sub}"] = sv.get("type", "keyword")
            for idx in m.values():
                walk(idx["mappings"].get("properties", {}))
            self._fields[index] = names
        return self._fields[index]

    def _run(self, tool, params, dsl, fn):
        try:
            out = fn()
            ids = out.pop("_ids", [])
            dsl = out.pop("_dsl", dsl)
            digest = json.dumps(out, default=str, sort_keys=True)     # lets a verifier trace numbers back to a cited call
            call_id = self.audit.record(tool, params, dsl, ids, out.get("total"), digest=digest)
            return {"call_id": call_id, "tool": tool, "dsl": dsl, **out}
        except ToolError as e:
            call_id = self.audit.record(tool, params, dsl, [], None, ok=False, error=str(e))
            return {"call_id": call_id, "tool": tool, "error": str(e)}
        except Exception as e:
            msg = getattr(e, "message", None) or str(e)
            call_id = self.audit.record(tool, params, dsl, [], None, ok=False, error=f"{type(e).__name__}: {msg}"[:400])
            return {"call_id": call_id, "tool": tool, "error": f"backend error: {type(e).__name__}: {str(msg)[:300]}"}

    def _sort(self, index: str, order: str) -> list:
        srt = [{"@timestamp": {"order": "desc" if order == "desc" else "asc"}}]
        tb = tiebreak_field(self._known(index))
        return srt + ([{tb: {"order": "asc"}}] if tb else [])

    # ---- tools
    def describe_data(self, index_pattern: str = config.HUNT_INDEX) -> dict:
        params = {"index_pattern": index_pattern}
        def fn():
            check_index(index_pattern)
            known = self._known(index_pattern)
            res = self.es.search(index=index_pattern, size=0, track_total_hits=True, aggs={
                "ds": {"terms": {"field": exact_field("event.dataset", known), "size": 100}, "aggs": {
                    "min": {"min": {"field": "@timestamp"}}, "max": {"max": {"field": "@timestamp"}}}}})
            sources = [{"dataset": b["key"], "docs": b["doc_count"], "first_event": b["min"].get("value_as_string"),
                        "last_event": b["max"].get("value_as_string")} for b in res["aggregations"]["ds"]["buckets"]]
            fields = sorted(f"{f}:{t}" for f, t in known.items() if not f.endswith(".keyword"))
            return {"total": res["hits"]["total"]["value"], "sources": sources, "fields": fields}
        return self._run("describe_data", params, None, fn)

    def _base(self, index, time_from, time_to, filters, must_not, any_of):
        check_index(index)
        return build_query(time_from, time_to, filters, must_not, any_of, known=self._known(index))

    def search(self, index: str, time_from: str, time_to: str, filters: list | None = None, must_not: list | None = None,
               any_of: list | None = None, fields: list | None = None, size: int = 50, sort: str = "asc") -> dict:
        params = dict(index=index, time_from=time_from, time_to=time_to, filters=filters, must_not=must_not, any_of=any_of,
                      fields=fields, size=size, sort=sort)
        dsl: dict = {}
        def fn():
            nonlocal dsl
            q = self._base(index, time_from, time_to, filters, must_not, any_of)
            n = cap_size(size)
            srt = self._sort(index, sort)
            dsl = {"query": q, "size": n, "sort": srt, "track_total_hits": True}
            r = self.es.search(index=index, query=q, size=n, sort=srt, track_total_hits=True)
            hits, trunc = [], False
            for h in r["hits"]["hits"]:
                f, t = compact(h["_source"], fields)
                trunc |= t
                hits.append({"event_id": h["_id"], "index": h["_index"], "fields": f})
            total = r["hits"]["total"]["value"]
            return {"total": total, "returned": len(hits), "truncated": trunc or total > len(hits), "hits": hits, "_dsl": dsl,
                    "_ids": [f'{h["index"]}/{h["event_id"]}' for h in hits]}
        return self._run("search", params, dsl, fn)

    def count(self, index: str, time_from: str, time_to: str, filters: list | None = None, must_not: list | None = None,
              any_of: list | None = None) -> dict:
        params = dict(index=index, time_from=time_from, time_to=time_to, filters=filters, must_not=must_not, any_of=any_of)
        dsl: dict = {}
        def fn():
            nonlocal dsl
            q = self._base(index, time_from, time_to, filters, must_not, any_of)
            dsl = {"query": q}
            return {"total": self.es.count(index=index, query=q)["count"], "_dsl": dsl}
        return self._run("count", params, dsl, fn)

    def aggregate(self, index: str, time_from: str, time_to: str, agg: str, field: str | None = None, filters: list | None = None,
                  must_not: list | None = None, any_of: list | None = None, size: int = 20, interval: str = "1h",
                  sum_field: str | None = None, distinct_field: str | None = None) -> dict:
        params = dict(index=index, time_from=time_from, time_to=time_to, agg=agg, field=field, filters=filters, must_not=must_not,
                      any_of=any_of, size=size, interval=interval, sum_field=sum_field, distinct_field=distinct_field)
        dsl: dict = {}
        def fn():
            nonlocal dsl
            if agg not in AGGS:
                raise ToolError(f"agg must be one of {sorted(AGGS)}")
            q = self._base(index, time_from, time_to, filters, must_not, any_of)
            known = self._known(index)
            if agg != "date_histogram" and not field:
                raise ToolError("field is required")
            fx = exact_field(check_field(field, known), known) if field else None
            if agg == "terms":
                a = {"terms": {"field": fx, "size": min(size, 100)}}
                if sum_field and distinct_field:
                    raise ToolError("use either sum_field or distinct_field")
                if sum_field:
                    check_field(sum_field, known)
                    a["terms"]["order"] = {"s": "desc"}
                    a["aggs"] = {"s": {"sum": {"field": sum_field}}}
                if distinct_field:
                    a["terms"]["order"] = {"d": "desc"}
                    a["aggs"] = {"d": {"cardinality": {"field": exact_field(check_field(distinct_field, known), known)}}}
            elif agg == "rare_terms": a = {"rare_terms": {"field": fx, "max_doc_count": 2}}
            elif agg == "date_histogram":
                lo, hi = check_range(time_from, time_to)
                hi_incl = (parse_time(hi) - timedelta(milliseconds=1)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"   # no extra bucket at the end
                a = {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0,
                                        "extended_bounds": {"min": lo, "max": hi_incl}}}
            else: a = {agg: {"field": fx}}
            dsl = {"query": q, "size": 0, "aggs": {"a": a}}
            r = self.es.search(index=index, query=q, size=0, aggs={"a": a}, track_total_hits=True)
            agg_res = r["aggregations"]["a"]
            if "buckets" in agg_res:
                out = [{"key": b.get("key_as_string", b["key"]), "count": b["doc_count"],
                        **({"sum": b["s"]["value"]} if "s" in b else {}), **({"distinct": b["d"]["value"]} if "d" in b else {})}
                       for b in agg_res["buckets"]]
            else:
                out = {k: v for k, v in agg_res.items()}
            return {"total": r["hits"]["total"]["value"], "result": out, "_dsl": dsl, "_ids": [json.dumps(out, sort_keys=True, default=str)]}
        return self._run("aggregate", params, dsl, fn)

    def get_event(self, index: str, event_id: str) -> dict:
        params = dict(index=index, event_id=event_id)
        def fn():
            check_index(index)
            if "*" in index or "," in index:
                raise ToolError("get_event needs an exact index name")
            d = self.es.get(index=index, id=event_id)
            return {"total": 1, "event": flatten(d["_source"]), "_ids": [f"{index}/{event_id}"]}
        return self._run("get_event", params, None, fn)

    def save_finding(self, claim: str, evidence_ids: list[str]) -> dict:
        params = dict(claim=claim, evidence_ids=evidence_ids)
        def fn():
            if not evidence_ids:
                raise ToolError("a finding needs at least one evidence id (call_id or index/event_id)")
            return {"total": 1, "saved": True, "_ids": evidence_ids}
        return self._run("save_finding", params, None, fn)

    def get_audit_log(self, run_id: str | None = None) -> dict:
        recs = Audit.read(run_id or self.audit.run_id)
        return {"call_id": None, "tool": "get_audit_log", "run_id": run_id or self.audit.run_id, "n": len(recs), "records": recs}
