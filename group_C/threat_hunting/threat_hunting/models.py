"""Hunt data models (plan, evidence, claims)."""
from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel


class PlanStep(BaseModel):
    step_id: str
    technique: str
    tool: Literal["search", "aggregate", "count"]
    params: dict[str, Any]
    purpose: str
    role: Literal["indicator", "benign_check", "context"] = "indicator"
    claim_template: str = ""      # used when the step yields hits
    analysis: dict[str, Any] = {}  # group_by, min_count, bucket_min_count, bucket_min_sum, bucket_min_distinct, drilldown, ioc_enrich
    must_have: bool = False


class HuntPlan(BaseModel):
    hypothesis: str
    techniques: list[str]
    required_techniques: list[str] = []
    context_techniques: list[str] = []
    entities: dict[str, Any] = {}
    required_sources: list[str]    # log types (keys of playbooks.DATASETS)
    time_range: dict[str, str]
    window_minutes: int = 60
    steps: list[PlanStep]
    success_criteria: list[str]
    refutation_criteria: list[str]
    planner: str = "rules"


class Evidence(BaseModel):
    evidence_id: str
    call_id: str
    step_id: str
    index: str = ""
    event_ids: list[str] = []
    total_hits: int = 0
    excerpt: list[dict[str, Any]] = []


class Claim(BaseModel):
    claim_id: str
    text: str
    technique: str
    evidence_ids: list[str]
    facts: dict[str, Any] = {}     # checkable key/values quoted in the claim
    confidence: Literal["low", "medium", "high"] = "medium"
    step_id: str = ""
    kind: Literal["events", "aggregate", "ioc"] = "events"
    first_seen: str = ""
    event_ids: list[str] = []      # "<index>/<event_id>"
    replay: dict[str, Any] = {}    # how a verifier (C3) re-checks aggregate / ioc claims
    context_only: bool = False     # context techniques never decide the verdict
    origin: Literal["playbook", "llm"] = "playbook"   # llm = from an investigator query: a lead, never proof (same field as C3's)
    # self_checked = passed C2's structural self-check; verified/unsupported/contradicted are set by C3's verifier
    status: Literal["unverified", "self_checked", "verified", "unsupported", "contradicted"] = "unverified"
    verifier_notes: str = ""


ACCEPTED = ("self_checked", "verified")
