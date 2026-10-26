"""A tiny Elasticsearch query evaluator for tests (only the DSL the C1 tools generate).

Supports: bool (filter / must / must_not / should + minimum_should_match), range on
any field, term (plain or {"value", "case_insensitive"}), terms, wildcard, prefix,
exists; size; aggregations "terms" (with sum / cardinality sub-aggs) and
"date_histogram" on @timestamp with fixed_interval and extended_bounds.
"""

from __future__ import annotations

import copy
import fnmatch
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from group_C.threat_hunting.evidence.gateways import flatten_event

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "c3_windows_sample.ndjson"


def load_sample(path: Path = SAMPLE) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _ts(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def _values(flat: dict, field: str) -> list[Any]:
    v = flat.get(field)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _eq(a: Any, b: Any, ci: bool) -> bool:
    if ci and isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b or str(a) == str(b)


def matches(flat: dict, q: dict) -> bool:
    if not q:
        return True
    (kind, body), = q.items()
    if kind == "bool":
        if any(not matches(flat, c) for c in body.get("filter", []) + body.get("must", [])):
            return False
        if any(matches(flat, c) for c in body.get("must_not", [])):
            return False
        should = body.get("should", [])
        if should and sum(matches(flat, c) for c in should) < int(body.get("minimum_should_match", 1)):
            return False
        return True
    if kind == "match_all":
        return True
    if kind == "exists":
        return bool(_values(flat, body["field"]))
    (field, spec), = body.items()
    vals = _values(flat, field)
    if kind == "term":
        want, ci = (spec.get("value"), bool(spec.get("case_insensitive"))) if isinstance(spec, dict) else (spec, False)
        return any(_eq(v, want, ci) for v in vals)
    if kind == "terms":
        return any(_eq(v, w, False) for v in vals for w in spec)
    if kind == "wildcard":
        pat, ci = (spec.get("value"), bool(spec.get("case_insensitive"))) if isinstance(spec, dict) else (spec, False)
        return any(fnmatch.fnmatchcase(str(v).lower() if ci else str(v), pat.lower() if ci else pat) for v in vals)
    if kind == "prefix":
        pre = spec.get("value") if isinstance(spec, dict) else spec
        return any(str(v).lower().startswith(str(pre).lower()) for v in vals)
    if kind == "range":
        for v in vals:
            ok = True
            for op, bound in spec.items():
                if op not in ("gte", "gt", "lte", "lt"):
                    continue
                if field == "@timestamp":
                    a, b = _ts(str(v)), _ts(str(bound))
                else:
                    a, b = float(v), float(bound)
                ok &= {"gte": a >= b, "gt": a > b, "lte": a <= b, "lt": a < b}[op]
            if ok:
                return True
        return False
    raise ValueError(f"mini_es does not support {kind}")


class MiniES:
    def __init__(self, docs: list[dict] | None = None) -> None:
        self.docs = copy.deepcopy(docs if docs is not None else load_sample())

    def _in_index(self, pattern: str, index: str) -> bool:
        return any(fnmatch.fnmatchcase(index, p) for p in pattern.split(","))

    def select(self, index: str, query: dict) -> list[dict]:
        out = [d for d in self.docs if self._in_index(index, d["_index"]) and matches(flatten_event(d["_source"]), query or {})]
        return sorted(out, key=lambda d: (d["_source"].get("@timestamp", ""), d["_id"]))

    def get(self, index: str, doc_id: str) -> dict | None:
        for d in self.docs:
            if d["_index"] == index and d["_id"] == doc_id:
                return copy.deepcopy(d["_source"])
        return None

    def count(self, index: str, body: dict) -> dict:
        return {"count": len(self.select(index, body.get("query", {})))}

    def search(self, index: str, body: dict) -> dict:
        hits = self.select(index, body.get("query", {}))
        size = int(body.get("size", 10))
        resp: dict[str, Any] = {"hits": {"total": {"value": len(hits), "relation": "eq"},
                                         "hits": [{"_index": h["_index"], "_id": h["_id"], "_source": copy.deepcopy(h["_source"])}
                                                  for h in hits[:size]]}}
        if body.get("aggs"):
            resp["aggregations"] = {name: self._agg(spec, hits) for name, spec in body["aggs"].items()}
        return resp

    def _agg(self, spec: dict, hits: list[dict]) -> dict:
        if "terms" in spec:
            field, size = spec["terms"]["field"], int(spec["terms"].get("size", 10))
            groups: dict[Any, list[dict]] = {}
            for h in hits:
                for v in _values(flatten_event(h["_source"]), field):
                    groups.setdefault(v, []).append(h)
            buckets = []
            for key, members in groups.items():
                b: dict[str, Any] = {"key": key, "doc_count": len(members)}
                for sub, sspec in (spec.get("aggs") or {}).items():
                    if "sum" in sspec:
                        b[sub] = {"value": float(sum(float(flatten_event(m["_source"]).get(sspec["sum"]["field"], 0) or 0) for m in members))}
                    elif "cardinality" in sspec:
                        f = sspec["cardinality"]["field"]
                        b[sub] = {"value": len({str(v) for m in members for v in _values(flatten_event(m["_source"]), f)})}
                buckets.append(b)
            buckets.sort(key=lambda b: (-b["doc_count"], str(b["key"])))
            return {"buckets": buckets[:size]}
        if "date_histogram" in spec:
            dh = spec["date_histogram"]
            step = timedelta(minutes=int(dh["fixed_interval"].rstrip("m")))
            lo, hi = _ts(dh["extended_bounds"]["min"]), _ts(dh["extended_bounds"]["max"])
            buckets, t = [], lo
            while t <= hi:
                n = sum(1 for h in hits if t <= _ts(h["_source"]["@timestamp"]) < t + step)
                buckets.append({"key_as_string": t.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "key": int(t.timestamp() * 1000), "doc_count": n})
                t += step
            return {"buckets": buckets}
        raise ValueError(f"mini_es does not support aggregation {list(spec)}")
