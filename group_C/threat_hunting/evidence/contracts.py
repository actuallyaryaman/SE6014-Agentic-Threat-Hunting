"""Data contracts between C2 (the hunter) and C3 (this package).

C2 works from a playbook. The planner picks ATT&CK techniques, every query
sits in a playbook step, and code turns the step results into most of the
claims. At the end of a run C2 hands C3 a hunt bundle made of these parts:

    HuntPlan      the techniques, requirement groups, steps and criteria that were planned
    Evidence      one record per step result, pointing to an audited tool call
    Claim         one finding: technique, quoted facts, and cited event refs "<index>/<_id>"
    AuditRecord   one MCP tool call, with params, DSL, total and result_hash
    HuntNotes     C2's notes on coverage, gaps, untested checks and missing entities

C3 re-verifies the claims, decides a verdict for each requirement group
(Confirmed, Refuted or Inconclusive) and writes the report. Field names are
the same as in C2's output, so a C2 run loads without conversion.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"


class _Open(BaseModel):
    """Base class for C2 objects. Extra keys are kept instead of causing an error."""

    model_config = ConfigDict(extra="allow")


# What C2 produces. Field names match the hunter.


class PlanStep(_Open):
    step_id: str
    technique: str
    tool: str = "search"                      # search | aggregate | count | coverage_check
    params: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""
    role: Literal["indicator", "benign_check", "context"] = "indicator"
    claim_template: str = ""
    analysis: dict[str, Any] = Field(default_factory=dict)
    must_have: bool = False
    requires: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    need: str = ""                            # plain-language data requirement, e.g. "Sysmon event 10"


class HuntPlan(_Open):
    hypothesis: str
    techniques: list[str] = Field(default_factory=list)
    required_techniques: list[str] = Field(default_factory=list)
    context_techniques: list[str] = Field(default_factory=list)
    entities: dict[str, Any] = Field(default_factory=dict)   # hosts, technique_names, requirement_groups, ...
    required_sources: list[str] = Field(default_factory=list)
    time_range: dict[str, str] = Field(default_factory=dict)  # {"from": ..., "to": ...}
    window_minutes: int = 60
    steps: list[PlanStep] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    refutation_criteria: list[str] = Field(default_factory=list)
    planner: str = "rules"


class Evidence(_Open):
    evidence_id: str
    call_id: str
    step_id: str
    index: str = ""
    event_ids: list[str] = Field(default_factory=list)
    total_hits: int = 0
    excerpt: list[dict[str, Any]] = Field(default_factory=list)


# C3 only writes the last four states. C2 sends claims as "unverified" (design) or
# "self_checked" (what the prototype writes). Both mean C2 has checked the claim and C3 has not.
ClaimStatus = Literal["unverified", "self_checked", "verified", "unsupported", "contradicted"]
PENDING_STATUSES = ("unverified", "self_checked")


class Claim(_Open):
    claim_id: str
    text: str
    technique: str
    evidence_ids: list[str] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)       # checkable field -> value quoted in the claim
    confidence: Literal["low", "medium", "high"] = "medium"
    step_id: str = ""
    kind: Literal["events", "aggregate", "ioc"] = "events"
    first_seen: str = ""
    event_ids: list[str] = Field(default_factory=list)        # "<index>/<event_id>"
    replay: dict[str, Any] = Field(default_factory=dict)       # how to re-check aggregate / ioc claims
    context_only: bool = False
    origin: Literal["playbook", "llm"] = "playbook"
    status: ClaimStatus = "unverified"
    c2_status: str = ""                                       # the status C2 set; C3 keeps it here when it overwrites `status`
    verifier_notes: str = ""


class AuditRecord(_Open):
    call_id: str
    ts: str = ""
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    dsl: Optional[Any] = None
    total: Optional[int] = None
    returned_ids: list[str] = Field(default_factory=list)
    result_hash: str = ""
    ok: bool = True
    error: str = ""
    digest: str = ""


class UntestedCheck(_Open):
    step_id: str = ""
    purpose: str = ""
    need: str = ""
    role: str = "indicator"


class IndexCoverage(_Open):
    total: int = 0
    buckets: list[dict[str, Any]] = Field(default_factory=list)
    empty_buckets: list[str] = Field(default_factory=list)
    n_buckets: Optional[int] = None          # C2 reports the bucket count without the bucket list
    coverage_ratio: Optional[float] = None
    bucket_minutes: Optional[int] = None
    first: Optional[str] = None
    last: Optional[str] = None


class HuntNotes(_Open):
    entity_missing: list[str] = Field(default_factory=list)
    untested: dict[str, list[UntestedCheck]] = Field(default_factory=dict)
    coverage: dict[str, IndexCoverage] = Field(default_factory=dict)
    coverage_gaps: dict[str, str] = Field(default_factory=dict)    # index -> reason
    gaps: list[str] = Field(default_factory=list)
    dated: bool = True
    data_sources: dict[str, Any] = Field(default_factory=dict)
    selected_sources: list[str] = Field(default_factory=list)
    out_of_scope: Optional[str] = None
    in_scope_without_playbook: Optional[str] = None
    min_support: dict[str, int] = Field(default_factory=dict)      # technique -> independent indicators needed
    technique_sources: dict[str, list[str]] = Field(default_factory=dict)   # technique -> log sources (auth, sysmon, ...)
    missing_fields: dict[str, Any] = Field(default_factory=dict)
    info: list[str] = Field(default_factory=list)


class C2Verdict(_Open):
    """The verdict C2 drafted from its playbook rules. C3 reviews it and never replaces it silently."""

    label: str = ""                    # SUPPORTED | NOT_SUPPORTED | INCONCLUSIVE | INSUFFICIENT_DATA
    confidence: str = ""
    requires_analyst_review: bool = False
    reasons: list[str] = Field(default_factory=list)
    review_reasons: list[str] = Field(default_factory=list)     # why C2 asks for analyst review (schema 0.2)


class TraceCall(_Open):
    """One line of runs/<id>/trace.jsonl. Analytics-server calls show up only here and not in the audit log."""

    seq: int = 0
    server: str = ""                   # es | analytics
    tool: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    request_hash: str = ""
    call_id: str = ""
    ok: bool = True
    total: Optional[int] = None
    phase: str = ""                    # planning | execution | ... (schema 0.2)
    step_id: str = ""
    purpose: str = ""


class HuntBundle(_Open):
    """Everything C3 needs from one hunt. C2 writes it at the end of a run."""

    schema_version: str = SCHEMA_VERSION
    run_id: str
    plan: HuntPlan
    evidence: list[Evidence] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    audit: list[AuditRecord] = Field(default_factory=list)
    step_results: dict[str, dict[str, Any]] = Field(default_factory=dict)
    dynamic_steps: list[PlanStep] = Field(default_factory=list)
    weak_signals: dict[str, list[str]] = Field(default_factory=dict)
    notes: HuntNotes = Field(default_factory=HuntNotes)
    hunt_notes: list[str] = Field(default_factory=list)
    baselines: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    c2_verdict: Optional[C2Verdict] = None
    c2_self_check: dict[str, Any] = Field(default_factory=dict)
    trace: list[TraceCall] = Field(default_factory=list)
    analytics_audit: list[AuditRecord] = Field(default_factory=list)   # audit/<run_id>-analytics.jsonl (schema 0.2)
    queries: list[dict[str, Any]] = Field(default_factory=list)        # result.json queries[]: every MCP call, one list
    c2_findings: dict[str, Any] = Field(default_factory=dict)          # result.json findings (e.g. prompt_injection)

    def all_steps(self) -> list[PlanStep]:
        """Planned steps followed by the steps C2 added during the run."""
        return list(self.plan.steps) + list(self.dynamic_steps)

    def find_step(self, step_id: str) -> Optional[PlanStep]:
        """Return the plan step behind a step id, or None.

        C2 expands some steps per entity (``T1078-b-203.0.113.99``, ``T1021.002-b-WS-01``)
        and does not list the expanded ids in the plan. When there is no exact match,
        the longest plan step id that prefixes the given id is used.
        """
        steps = {s.step_id: s for s in self.all_steps()}
        base = step_id.split("@")[0]
        for key in (step_id, base):
            if key in steps:
                return steps[key]
        prefixes = [k for k in steps if base.startswith(k + "-")]
        return steps[max(prefixes, key=len)] if prefixes else None

    def audit_by_id(self) -> dict[str, AuditRecord]:
        """Index the audit records by call id."""
        return {r.call_id: r for r in self.audit}


# Loading C2 output


def _read_jsonl(path: str | Path) -> list[Any]:
    """Parse a JSON-lines file into a list of objects. A missing file gives an empty list."""
    file = Path(path)
    if not file.exists():
        return []
    return [json.loads(line) for line in file.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_audit_jsonl(path: str | Path) -> list[AuditRecord]:
    """Load an audit log written by the MCP server."""
    return [AuditRecord.model_validate(row) for row in _read_jsonl(path)]


def read_trace_jsonl(path: str | Path) -> list[TraceCall]:
    """Load a schema 0.1 trace file."""
    return [TraceCall.model_validate(row) for row in _read_jsonl(path)]


def _trace_from_queries(queries: list[dict[str, Any]]) -> list[TraceCall]:
    """Convert result.json queries[] (schema 0.2) to trace calls. It replaces trace.jsonl."""
    return [TraceCall(seq=q.get("seq", 0), server=q.get("server", ""), tool=q.get("tool", ""), args=q.get("request", {}) or {},
                      request_hash=q.get("request_hash", ""), call_id=q.get("query_id", "") or "", ok=bool(q.get("ok", True)),
                      total=q.get("total"), phase=q.get("phase", ""), step_id=q.get("step_id") or "", purpose=q.get("purpose") or "")
            for q in queries]


def _coverage_from_result(res: dict[str, Any]) -> tuple[dict[str, IndexCoverage], dict[str, str], list[str], list[str], dict[str, Any], dict[str, Any]]:
    """Read the coverage block of result.json.

    The current C2 shape is {"data_sources": {...}, "coverage": {<source>: {total, n_buckets,
    empty_buckets, coverage_ratio}}, "gaps": [...], "missing_fields": {...}, "entity_missing": [...]}.
    The older flat shape {<index>: {buckets, empty_buckets}} still loads.
    """
    block = res.get("coverage", {}) or {}
    nested = isinstance(block.get("coverage"), dict)
    per_source = block["coverage"] if nested else block
    coverage: dict[str, IndexCoverage] = {}
    cov_gaps: dict[str, str] = {}
    for name, c in per_source.items():
        coverage[name] = IndexCoverage.model_validate({k: v for k, v in c.items() if k in IndexCoverage.model_fields} | c)
        n = int(c.get("n_buckets") or len(c.get("buckets", [])))
        empty = len(c.get("empty_buckets", []))
        if n and empty * 20 > n:      # INTERFACES 4.3: fewer than 95% of the hourly buckets have events. Integer math avoids float edge cases.
            cov_gaps[name] = f"{empty}/{n} buckets have no events"
    gaps = list(block.get("gaps", []) if nested else res.get("gaps", []) or [])
    entity_missing = list(block.get("entity_missing", []) if nested else [])
    data_sources = dict(block.get("data_sources", {}) if nested else res.get("data_sources", {}) or {})
    missing_fields = dict(block.get("missing_fields", {}) if nested else {})
    return coverage, cov_gaps, gaps, entity_missing, data_sources, missing_fields


def bundle_from_run_dir(plan_json: str | Path, result_json: str | Path, audit_jsonl: str | Path,
                        trace_jsonl: str | Path | None = None, analytics_audit_jsonl: str | Path | None = None) -> HuntBundle:
    """Build a bundle from a C2 run folder.

    The inputs are plan.json, result.json and audit/<run_id>.jsonl, plus
    audit/<run_id>-analytics.jsonl when it exists. Schema 0.1 runs have
    trace.jsonl in place of queries[].

    result.json does not carry every planner note, so some are rebuilt here:
    coverage gaps come from empty coverage buckets, and min_support and sources
    come from the technique table.
    """
    plan = HuntPlan.model_validate_json(Path(plan_json).read_text(encoding="utf-8"))
    result = json.loads(Path(result_json).read_text(encoding="utf-8"))
    coverage, cov_gaps, gaps, entity_missing, data_sources, missing_fields = _coverage_from_result(result)
    rows = result.get("techniques", []) or []
    entity_missing = entity_missing or plan.entities.get("entity_missing", []) or []
    notes = HuntNotes(
        entity_missing=entity_missing,
        untested=result.get("untested", {}) or {},
        coverage=coverage,
        coverage_gaps=cov_gaps,
        gaps=gaps,
        dated=bool(result.get("dated", True)),
        data_sources=data_sources,
        selected_sources=result.get("selected_sources", []) or [],
        out_of_scope=result.get("out_of_scope"),
        min_support={r["technique"]: int(r.get("min_support", 1)) for r in rows if "technique" in r},
        technique_sources={r["technique"]: list(r["sources"]) for r in rows if r.get("sources")},
        missing_fields=missing_fields,
    )
    run_id = result.get("run_id") or Path(result_json).parent.name
    run_notes = [n for n in (result.get("notes") or []) if isinstance(n, str)] if isinstance(result.get("notes"), list) else []
    trace_path = Path(trace_jsonl) if trace_jsonl else Path(result_json).with_name("trace.jsonl")
    queries = [q for q in (result.get("queries") or []) if isinstance(q, dict)]
    trace = _trace_from_queries(queries) if queries else read_trace_jsonl(trace_path)
    analytics_path = Path(analytics_audit_jsonl) if analytics_audit_jsonl else Path(audit_jsonl).with_name(f"{Path(audit_jsonl).stem}-analytics.jsonl")
    return HuntBundle(
        run_id=run_id,
        plan=plan,
        evidence=result.get("evidence", []),
        claims=[{**c, "c2_status": c.get("status", "")} for c in result.get("claims", [])],
        audit=read_audit_jsonl(audit_jsonl),
        step_results=result.get("step_results", {}) or {},
        dynamic_steps=result.get("dynamic_steps", []) or [],
        weak_signals={r["technique"]: r.get("weak", []) for r in rows if r.get("weak")},
        notes=notes,
        hunt_notes=run_notes,
        baselines=list(result.get("baselines", []) or []) + run_notes,    # C2's free-text notes count as baseline remarks
        limitations=result.get("limitations", []) or [],
        meta=result.get("manifest") or result.get("meta") or {},
        c2_verdict=result.get("verdict") or None,
        c2_self_check=result.get("self_check", {}) or {},
        trace=trace,
        analytics_audit=read_audit_jsonl(analytics_path) if analytics_path.exists() else [],
        queries=queries,
        c2_findings=result.get("findings") or {},
    )
