"""Verdict rules. Rules over verified claims and coverage decide the verdict, never the LLM.

The planner splits the hypothesis into requirement groups. A group is either one
ATT&CK technique or a tactic whose techniques are alternatives ("any of"). The
verdict follows from the groups:

  Confirmed     every group has a technique with at least ``min_support``
                independent verified indicators. Independent means distinct
                playbook steps, so the same step found in two time windows
                counts once.
  Refuted       no group shows a verified signal or below-threshold activity,
                and every group could be tested over data without gaps
  Inconclusive  everything else. The report says why and what data would settle it.

Guardrails:
  * Only verified claims count. Unsupported, contradicted and unverified ones never do.
  * Findings produced only by LLM-proposed queries are leads, never proof.
  * If the LLM chose every technique (the hypothesis named no known behaviour),
    the verdict is Inconclusive.
  * A host named in the hypothesis with no telemetry makes the hunt Inconclusive,
    because the absence of events cannot be interpreted.
  * Confidence is high only when the supporting claims come from at least two
    independent playbook steps (DESIGN section 4.1) and every supported technique
    is fully covered. A team that wants a stricter rule can set C3_MIN_LOG_SOURCES=2,
    which also asks for events from two log sources.
  * Every Confirmed verdict needs analyst review before anyone acts on it.

C2 drafts its own verdict (SUPPORTED, NOT_SUPPORTED, INCONCLUSIVE or
INSUFFICIENT_DATA) from the playbook rules. C3 computes a verdict from the claims
it verified itself and then compares the two. The final verdict can stay the same
or become more cautious. It never becomes less cautious.

  both agree                     keep it, with the lower of the two confidences
  C3 finds less than C2 said     downgrade to Inconclusive, or to the lower confidence
  C2 is more cautious than C3    keep C2's Inconclusive
  they contradict each other     Inconclusive, analyst review
"""

from __future__ import annotations

import os
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from .contracts import PENDING_STATUSES, Claim, HuntBundle, PlanStep

VerdictName = Literal["Confirmed", "Refuted", "Inconclusive"]


class TechniqueRow(BaseModel):
    technique: str
    name: str
    required: bool
    group: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    verified_claims: int = 0
    llm_claims: int = 0
    llm_only: bool = False
    supporting_steps: list[str] = Field(default_factory=list)
    min_support: int = 1
    supported: bool = False
    any_signal: bool = False
    testable: bool = False
    covered: bool = False
    gaps: list[str] = Field(default_factory=list)
    not_tested: list[dict[str, str]] = Field(default_factory=list)
    weak: list[str] = Field(default_factory=list)


class GroupResult(BaseModel):
    label: str
    kind: str = "technique"
    techniques: list[str]
    supported: bool = False
    any_signal: bool = False
    covered: bool = False
    untestable: list[str] = Field(default_factory=list)
    weak: list[str] = Field(default_factory=list)
    llm_leads: bool = False


class C2Review(BaseModel):
    """How C3's own result compares with the verdict C2 drafted."""

    c2_label: str = ""                    # as C2 wrote it
    c2_verdict: Optional[VerdictName] = None
    c2_confidence: str = ""
    own_verdict: VerdictName = "Inconclusive"
    own_confidence: Literal["high", "medium", "low"] = "low"
    outcome: Literal["no_c2_verdict", "agrees", "downgraded", "kept_c2_caution", "contradicts"] = "no_c2_verdict"
    note: str = ""


class Decision(BaseModel):
    verdict: VerdictName
    confidence: Literal["high", "medium", "low"]
    review: Optional[C2Review] = None
    rows: list[TechniqueRow]
    groups: list[GroupResult]
    reasons: list[str]
    next_steps: list[str]
    analyst_review: bool
    review_reasons: list[str] = Field(default_factory=list)   # why an analyst must look (INTERFACES 4.3)


def _indices(params: dict[str, Any]) -> list[str]:
    """Split a comma-separated ``index`` parameter into a list of index names."""
    raw = params.get("index") or ""
    return [i for i in str(raw).split(",") if i]


def indicator_step_ids(bundle: HuntBundle, tech: str, claims: list[Claim]) -> list[str]:
    """Return the indicator step ids of a technique.

    That means the planned indicator steps plus any step C2 created at run time
    that produced a claim, for example one drill-down per attacker IP. Run-time
    steps are missing from the plan, but they still count as indicators.
    """
    ids = [s.step_id for s in bundle.all_steps() if s.technique == tech and s.role == "indicator"]
    dynamic = {c.step_id.split("@")[0] for c in claims if c.technique == tech and c.step_id and bundle.find_step(c.step_id) is None}
    return ids + sorted(dynamic - set(ids))


def technique_rows(bundle: HuntBundle, claims: list[Claim]) -> list[TechniqueRow]:
    """Build one row per required or context technique, with its support and coverage."""
    plan, notes = bundle.plan, bundle.notes
    names = plan.entities.get("technique_names", {}) or {}
    group_of = {t: g["label"] for g in plan.entities.get("requirement_groups", []) or [] for t in g["techniques"]}
    rows: list[TechniqueRow] = []
    for tech in list(plan.required_techniques) + list(plan.context_techniques):
        step_ids = indicator_step_ids(bundle, tech, claims)
        steps = [s for s in bundle.all_steps() if s.step_id in step_ids]
        sources = sorted(notes.technique_sources.get(tech) or {i for s in steps for i in _indices(s.params)})
        untested = [u for u in notes.untested.get(tech, []) if u.role == "indicator"]

        gaps: list[str] = []
        if not step_ids:
            needs = sorted({u.need for u in untested if u.need})
            gaps.append("no selected data can test it" + (f" (needs {'; '.join(needs)})" if needs else ""))
        gaps += [f"{idx}: {notes.coverage_gaps[idx]}" for idx in sources if idx in notes.coverage_gaps]
        lead_ids = {c.step_id for c in claims if c.origin == "llm"}               # an LLM-proposed step is a lead and never counts as coverage
        unfinished = [sid for sid in step_ids if sid not in lead_ids and bundle.step_results.get(sid, {}).get("status") != "ok"]
        if unfinished:
            gaps.append(f"steps did not complete: {unfinished}")

        verified = [c for c in claims if c.technique == tech and c.status == "verified" and c.kind != "ioc"]
        independent = sorted({c.step_id.split("@")[0] for c in verified})
        need = int(notes.min_support.get(tech, 1))
        rows.append(TechniqueRow(
            technique=tech,
            name=names.get(tech, tech),
            required=tech in plan.required_techniques,
            group=group_of.get(tech),
            sources=sources,
            verified_claims=len(verified),
            llm_claims=sum(c.origin == "llm" for c in verified),
            llm_only=bool(verified) and all(c.origin == "llm" for c in verified),
            supporting_steps=independent,
            min_support=need,
            supported=len(independent) >= need,
            any_signal=bool(verified),
            testable=bool(step_ids),
            covered=bool(step_ids) and not gaps,
            gaps=gaps,
            not_tested=[{"step": u.step_id, "purpose": u.purpose, "need": u.need} for u in untested],
            weak=list(bundle.weak_signals.get(tech, [])),
        ))
    return rows


def requirement_groups(bundle: HuntBundle, rows: list[TechniqueRow]) -> list[tuple[GroupResult, list[TechniqueRow]]]:
    """Combine technique rows into the requirement groups from the plan."""
    by_tech = {r.technique: r for r in rows}
    defined = bundle.plan.entities.get("requirement_groups") or [
        {"label": t, "kind": "technique", "techniques": [t]} for t in bundle.plan.required_techniques]
    out = []
    for g in defined:
        members = [by_tech[t] for t in g["techniques"] if t in by_tech]
        result = GroupResult(
            label=g["label"], kind=g.get("kind", "technique"), techniques=list(g["techniques"]),
            supported=any(r.supported for r in members),
            any_signal=any(r.any_signal for r in members),
            covered=any(r.covered for r in members),
            untestable=[r.technique for r in members if not r.testable],
            weak=[w for r in members for w in r.weak],
        )
        # Support that comes only from LLM-proposed queries is a lead, not proof.
        if result.supported and not any(r.supported and not r.llm_only for r in members):
            result.supported, result.llm_leads = False, True
        out.append((result, members))
    return out


_C2_LABELS: dict[str, VerdictName] = {
    "SUPPORTED": "Confirmed", "NOT_SUPPORTED": "Refuted", "INCONCLUSIVE": "Inconclusive", "INSUFFICIENT_DATA": "Inconclusive",
    "CONFIRMED": "Confirmed", "REFUTED": "Refuted",
}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}

_SOURCE_FAMILIES = (("sysmon", "sysmon"), ("firewall", "firewall"), ("auth", "auth"), ("apache", "web"), ("nginx", "web"),
                    ("web", "web"), ("access", "web"), ("security", "windows-security"))


def log_source(claim: Claim, bundle: HuntBundle) -> str:
    """Name the log source a claim's events come from.

    The source is the dataset named in the filters of the claim's step. For a step
    C2 created at run time, which is not in the plan, the filters of the audited
    call behind the evidence are used. If neither names a dataset, the index is used.
    """
    step = bundle.find_step(claim.step_id)
    param_sets = [step.params] if step else []
    if not param_sets:
        evidence = {e.evidence_id: e for e in bundle.evidence}
        audit = bundle.audit_by_id()
        param_sets = [audit[evidence[e].call_id].params for e in claim.evidence_ids
                      if e in evidence and evidence[e].call_id in audit]
    for params in param_sets:
        for f in params.get("filters") or []:
            if f.get("field") == "event.dataset":
                raw = f.get("value")
                name = (raw[0] if isinstance(raw, list) and raw else str(raw)).lower()
                return next((fam for key, fam in _SOURCE_FAMILIES if key in name), name)
    return claim.event_ids[0].split("/")[0] if claim.event_ids else ""


class _Review:
    """C3's reconciliation with C2: the public C2Review plus the final verdict, confidence and reasons."""

    def __init__(self, review: C2Review, final_verdict: VerdictName, final_confidence: str, reasons: list[str], analyst_review: bool):
        self.outcome = review.outcome
        self._review = review
        self.final_verdict, self.final_confidence = final_verdict, final_confidence
        self.reasons, self.analyst_review = reasons, analyst_review

    def public(self) -> C2Review:
        return self._review


def review_c2_verdict(bundle: HuntBundle, own: VerdictName, own_conf: str) -> _Review:
    """Compare C3's own result with C2's draft. The outcome stays the same or becomes more cautious."""
    c2_draft = bundle.c2_verdict
    if c2_draft is None or not c2_draft.label:
        review = C2Review(own_verdict=own, own_confidence=own_conf)  # type: ignore[arg-type]
        return _Review(review, own, own_conf, [], False)
    mapped = _C2_LABELS.get(c2_draft.label.upper())
    c2_conf = c2_draft.confidence.lower() if c2_draft.confidence.lower() in _CONF_RANK else ""
    base = dict(c2_label=c2_draft.label, c2_verdict=mapped, c2_confidence=c2_conf, own_verdict=own, own_confidence=own_conf)
    review_flag = bool(c2_draft.requires_analyst_review)
    if mapped is None:
        review = C2Review(**base, outcome="no_c2_verdict", note=f"C2 label {c2_draft.label!r} is not recognised; C3's own result is used.")  # type: ignore[arg-type]
        return _Review(review, own, own_conf, [review.note], review_flag)
    if mapped == own:
        final_conf = own_conf if not c2_conf else min(own_conf, c2_conf, key=_CONF_RANK.__getitem__)
        if final_conf != c2_conf and c2_conf:
            note = (f"C2 reported {c2_draft.label} with {c2_conf} confidence; C3 re-verified the claims and supports it with "
                    f"{final_conf} confidence" + ((" (C3's stricter option is on: high also needs events from "
                      f"{min_log_sources()} log sources.)" if min_log_sources() > 1 else " (high needs two independent verified steps and full coverage).")
                     if own == "Confirmed" else "."))
            outcome = "downgraded"
        else:
            note, outcome = f"C2 reported {c2_draft.label} ({c2_conf or 'no confidence given'}); C3's re-verification agrees.", "agrees"
        review = C2Review(**base, outcome=outcome, note=note)  # type: ignore[arg-type]
        return _Review(review, own, final_conf, [note], review_flag)
    if mapped == "Inconclusive":
        note = f"C2 reported {c2_draft.label}; C3 does not upgrade a C2 verdict, so the result stays Inconclusive."
        review = C2Review(**base, outcome="kept_c2_caution", note=note)  # type: ignore[arg-type]
        return _Review(review, "Inconclusive", "low", [note], True)
    if own == "Inconclusive":
        note = (f"C2 reported {c2_draft.label} ({c2_conf or 'no confidence given'}), but C3 could not confirm it from the log store; "
                "the verdict is downgraded to Inconclusive.")
        review = C2Review(**base, outcome="downgraded", note=note)  # type: ignore[arg-type]
        return _Review(review, "Inconclusive", "low", [note], True)
    note = f"C2 reported {c2_draft.label} but C3's re-verification points to {own}; the two contradict each other, so the result is Inconclusive."
    review = C2Review(**base, outcome="contradicts", note=note)  # type: ignore[arg-type]
    return _Review(review, "Inconclusive", "low", [note], True)


def _group_name(g: GroupResult, members: list[TechniqueRow]) -> str:
    """A readable name for a group in report text."""
    if g.kind == "tactic":
        return f"{g.label} (any of {len(g.techniques)} techniques)"
    return f"{g.label} {members[0].name}".strip() if members else g.label


def min_log_sources() -> int:
    """Return the number of log sources high confidence needs. The default of 1 follows DESIGN section 4.1."""
    try:
        return max(1, int(os.environ.get("C3_MIN_LOG_SOURCES", "1")))
    except ValueError:
        return 1


def decide(bundle: HuntBundle, claims: list[Claim], flags: Optional[list[dict[str, Any]]] = None,
           offline: bool = False) -> Decision:
    """Decide the verdict, confidence and review reasons for a hunt."""
    notes = bundle.notes
    rows = technique_rows(bundle, claims)
    groups = requirement_groups(bundle, rows)
    reasons: list[str] = []
    next_steps: list[str] = []

    if not groups:
        why = notes.out_of_scope or notes.in_scope_without_playbook
        reasons.append("No playbook matched the hypothesis, so nothing could be tested." + (f" ({why})" if why else ""))
        leads = [c for c in claims if c.origin == "llm" and c.status == "verified"]
        if leads:
            reasons.append(f"LLM-proposed queries found {len(leads)} verified finding(s); they are worth a manual review "
                           "but cannot decide the verdict without a vetted playbook.")
        next_steps.append("Rephrase the hypothesis around attacker behaviour the logs can show (credential dumping, lateral "
                          "movement, persistence, log clearing, brute force, web exploitation, exfiltration).")
        review = review_c2_verdict(bundle, "Inconclusive", "low")
        return Decision(verdict=review.final_verdict if review.outcome != "no_c2_verdict" else "Inconclusive",  # type: ignore[attr-defined]
                        confidence="low", review=review.public(), rows=rows, groups=[],
                        reasons=reasons + review.reasons, next_steps=next_steps, analyst_review=True,
                        review_reasons=["confidence is low"])

    pending = [c for c in claims if c.status in PENDING_STATUSES and not c.context_only]
    if offline:
        verdict: VerdictName = "Inconclusive"
        reasons.append("The claims and queries were not re-checked against the log store (offline mode); "
                       "run the report with --verify es or --verify mcp to reach a verdict.")
        next_steps.append("Re-run the report with access to Elasticsearch or the MCP server.")
    elif all(g.kind == "llm" for g, _ in groups):
        verdict = "Inconclusive"
        found = [g.label for g, _ in groups if g.any_signal]
        reasons.append("The hypothesis names no behaviour the playbooks test; the language model chose "
                       + ", ".join(g.label for g, _ in groups) + ". "
                       + (f"Findings for {', '.join(found)} are leads to review, not a verdict." if found
                          else "None of them shows activity."))
        next_steps.append("Name the attacker behaviour you suspect so the hypothesis can be confirmed or refuted.")
    elif notes.entity_missing:
        verdict = "Inconclusive"
        reasons.append(f"No telemetry exists for named entities {notes.entity_missing}; absence of events cannot be interpreted.")
        next_steps.append(f"Check the host name spelling or ingest logs from {', '.join(notes.entity_missing)}.")
    elif all(g.supported for g, _ in groups):
        verdict = "Confirmed"
        reasons.append("Every part of the hypothesis has a technique with at least the minimum number of "
                       "independent verified indicators.")
    elif not any(g.any_signal or g.weak for g, _ in groups) and all(g.covered for g, _ in groups) and not pending:
        verdict = "Refuted"
        reasons.append("Every part of the hypothesis was testable over gap-free data and no verified indicator exists.")
        untestable = sorted({t for g, _ in groups for t in g.untestable})
        if untestable:
            reasons.append(f"Not testable with the selected data (no evidence either way): {', '.join(untestable)}.")
    else:
        verdict = "Inconclusive"
        if pending:
            reasons.append(f"{len(pending)} claim(s) could not be re-verified; until they are, the hypothesis cannot be refuted.")
        for g, members in groups:
            if g.supported:
                continue
            name = _group_name(g, members)
            with_signal = [r for r in members if r.any_signal]
            needs = sorted({u["need"] for r in members for u in r.not_tested if u.get("need")})
            if g.llm_leads:
                reasons.append(f"{name}: only LLM-proposed queries found related events; they are leads to review, not proof.")
                if needs:
                    next_steps.append(f"To test {name} with a vetted playbook, ingest: " + "; ".join(needs[:6]) + ".")
            elif with_signal:
                for r in with_signal:
                    reasons.append(f"{name}: {r.technique} has {len(r.supporting_steps)} of {r.min_support} independent "
                                   f"indicators needed ({', '.join(r.supporting_steps)}).")
                    if r.not_tested:
                        next_steps.append(f"{r.technique}: a second, independent indicator could come from "
                                          + "; ".join(sorted({u['need'] for u in r.not_tested if u.get('need')})) +
                                          ", which the selected data does not contain.")
                    else:
                        next_steps.append(f"{r.technique}: review the verified finding(s) by hand; the other indicators "
                                          "were searched and found nothing.")
            elif not g.covered:
                reasons.append(f"{name}: could not be tested over gap-free data.")
                reasons += [f"  {r.technique}: {gap}" for r in members for gap in r.gaps]
                if needs:
                    next_steps.append(f"To settle {name}, ingest: " + "; ".join(needs[:6]) + ".")
                if any("no events" in gap for r in members for gap in r.gaps):
                    next_steps.append("Narrow the hypothesis to a time where every source has data, or fill the data gap.")
            elif g.weak:
                reasons.append(f"{name}: activity was found but stays below the reporting threshold, so it can be "
                               "neither reported nor ruled out: " + " | ".join(g.weak[:3]))
                next_steps.append(f"{name}: review the below-threshold activity by hand.")
            else:
                reasons.append(f"{name}: no verified indicator.")

    if notes.entity_missing and any(c.status == "verified" for c in claims):
        reasons.append("Context findings exist but concern other entities than the ones named in the hypothesis.")

    # High confidence (DESIGN 4.1) needs two independent verified playbook steps and full coverage.
    # If the team sets C3_MIN_LOG_SOURCES, it also needs events from that many log sources.
    supported = [r for g, members in groups for r in members if r.supported]
    supported_techs = {r.technique for r in supported}
    verified = [c for c in claims if c.status == "verified" and c.technique in supported_techs and c.kind != "ioc"]
    n_steps = len({c.step_id for c in verified})
    sources = {log_source(c, bundle) for c in verified if c.event_ids}
    if verdict == "Confirmed":
        enough = n_steps >= 2 and all(r.covered for r in supported) and len(sources) >= min_log_sources()
        confidence = "high" if enough else "medium"
    elif verdict == "Refuted" and not any(g.untestable for g, _ in groups):
        confidence = "medium"
    else:
        confidence = "low"

    analyst_review = verdict == "Confirmed"
    narrative = [f for f in flags or [] if f.get("code") == "narrative_unsupported_entity"]
    if narrative:
        reasons.append(f"{len(narrative)} statement(s) written by C2 name entities that appear in no evidence: "
                       + "; ".join(f["message"] for f in narrative) + ".")
        analyst_review = True
    hostile = [f for f in flags or [] if f.get("code") == "hostile_event_text"]
    if hostile:
        reasons.append(f"{len(hostile)} cited event(s) contain text addressed to an AI; it was treated as data only.")
        analyst_review = True

    c2_inj = [f for f in flags or [] if f.get("code") == "c2_prompt_injection"]
    if c2_inj:
        reasons.append(c2_inj[0]["message"] + "; it was treated as data only and never reached a verdict.")
        analyst_review = True

    review = review_c2_verdict(bundle, verdict, confidence)
    if review.outcome != "no_c2_verdict":
        verdict, confidence = review.final_verdict, review.final_confidence  # type: ignore[attr-defined]
    # INTERFACES 4.3 requires review for a Confirmed verdict, low confidence, a coverage gap, hostile text
    # in the window, or a claim that failed a check. Every cause that applies is listed.
    why: list[str] = []
    if verdict == "Confirmed":
        why.append("a Confirmed verdict is never acted on automatically")
    if confidence == "low":
        why.append("confidence is low")
    gap_rows = [r.technique for g, members in groups for r in members if r.gaps]
    if gap_rows:
        why.append("coverage gap for " + ", ".join(dict.fromkeys(gap_rows)))
    rejected = [c.claim_id for c in claims if c.status in ("unsupported", "contradicted")]
    if rejected:
        why.append(f"{len(rejected)} claim(s) failed verification ({', '.join(rejected[:5])})")
    if hostile or c2_inj:
        why.append("the window or cited events contain text aimed at an AI")
    if narrative:
        why.append("C2's free text names entities that appear in no evidence")
    if review.analyst_review and not why:
        why.append("C2 asked for analyst review")
    return Decision(verdict=verdict, confidence=confidence, review=review.public(), rows=rows,  # type: ignore[arg-type]
                    groups=[g for g, _ in groups], reasons=list(dict.fromkeys(reasons + review.reasons)),
                    next_steps=list(dict.fromkeys(next_steps)),
                    analyst_review=analyst_review or review.analyst_review or bool(why), review_reasons=why)
