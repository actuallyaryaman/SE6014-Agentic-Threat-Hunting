"""A gateway that answers from a C2 run's own recordings. It stands in for a log store that has not changed.

We do not have C2's Elasticsearch data, only what its run left behind. This gateway rebuilds what C3 needs:

  rerun(record)  returns exactly what the audit log recorded for that call (result IDs, aggregate buckets,
                 total), so every replay of an untouched run is "identical" by construction
  get_event(ref) returns a document rebuilt from the evidence excerpts and the quoted facts of the original
                 claims. It is not C2's real document. It has only the fields C3 compares.

The gateway is built from the original run folder, and the tampered copies are checked against it.
Whatever differs from the original is an error that C3 should find.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from group_C.threat_hunting.evidence.contracts import AuditRecord, HuntBundle, bundle_from_run_dir
from group_C.threat_hunting.evidence.gateways import EventFetch, NotReplayable

C2_RUNS = Path(__file__).with_name("c2_runs")
RUN_IDS = ("share-ssh-bruteforce", "share-lsass-lateral")
_NOT_FIELDS = {"n_connections", "ioc", "bucket_key", "count"}


def run_paths(run_id: str, root: Path = C2_RUNS) -> tuple[Path, Path, Path, Path]:
    d = root / "runs" / run_id
    return d / "plan.json", d / "result.json", root / "audit" / f"{run_id}.jsonl", d / "trace.jsonl"


def load_run(run_id: str, root: Path = C2_RUNS) -> HuntBundle:
    plan, result, audit, trace = run_paths(run_id, root)
    return bundle_from_run_dir(plan, result, audit, trace)


def _canon(tool: str, params: dict[str, Any]) -> str:
    return tool + json.dumps(params, sort_keys=True, default=str)


class RecordedGateway:
    mode = "recorded"

    def __init__(self, original: HuntBundle) -> None:
        self.by_call = {r.call_id: r for r in original.audit}
        self.by_request = {_canon(r.tool, r.params): r for r in original.audit}
        self.analytics = {_canon(t.tool, t.args): t.total for t in original.trace if t.server == "analytics"}
        self.docs = self._rebuild_documents(original)
        self.fetched: list[str] = []

    @staticmethod
    def _rebuild_documents(b: HuntBundle) -> dict[str, dict[str, Any]]:
        docs: dict[str, dict[str, Any]] = {}
        for ev in b.evidence:                       # excerpt rows line up with the first event ids of the call
            for ref, row in zip(ev.event_ids, ev.excerpt):
                docs.setdefault(ref, {}).update(row)
        for c in b.claims:                          # then the facts the (honest) original claim quotes
            event_field = c.replay.get("event_field")
            for i, ref in enumerate(c.event_ids):
                doc = docs.setdefault(ref, {})
                if event_field and c.replay.get("bucket_key") is not None:
                    doc.setdefault(event_field, c.replay["bucket_key"])
                for key, value in c.facts.items():
                    if key in _NOT_FIELDS:
                        continue
                    doc.setdefault(key, value[i % len(value)] if isinstance(value, list) else value)
        return docs

    async def get_event(self, index: str, event_id: str) -> EventFetch:
        ref = f"{index}/{event_id}"
        self.fetched.append(ref)
        doc = self.docs.get(ref)
        return EventFetch(dict(doc)) if doc is not None else EventFetch(None, "not found")

    async def rerun(self, record: AuditRecord) -> dict[str, Any]:
        rec = self.by_call.get(record.call_id) or self.by_request.get(_canon(record.tool, record.params))
        if rec is not None:
            return self._response(rec)
        total = self.analytics.get(_canon(record.tool, record.params))
        if total is not None:
            return {"total": total, "matches": [{"value": record.params.get("value", "")}] if record.tool == "check_ioc" else []}
        if record.tool == "check_ioc":      # the threat-intel feed only knows the indicators the run looked up
            return {"total": 0, "matches": []}
        raise NotReplayable(f"{record.tool}: not in the recording")

    @staticmethod
    def _response(rec: AuditRecord) -> dict[str, Any]:
        if rec.tool == "search":
            hits = [{"index": ref.split("/", 1)[0], "event_id": ref.split("/", 1)[1], "fields": {}} for ref in rec.returned_ids]
            return {"total": rec.total, "returned": len(hits), "hits": hits}
        if rec.tool == "aggregate":
            return {"total": rec.total, "result": json.loads(rec.returned_ids[0])}
        if rec.tool == "coverage_check":
            return {"total": rec.total, "coverage": {}}
        return {"total": rec.total}
