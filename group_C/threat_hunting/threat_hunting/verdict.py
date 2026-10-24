"""Verdict is assigned by rules from self-checked evidence and coverage, never by free-text LLM output.
Ported from the prototype's src/hunt/verdict.py; labels follow DESIGN.md section 4.1 and INSUFFICIENT_DATA is new."""
from __future__ import annotations
from . import playbooks
from .hunter import HuntState
from .models import ACCEPTED, HuntPlan
from .planner import GAP_THRESHOLD, MIN_SUPPORT


def technique_table(plan: HuntPlan, st: HuntState, notes: dict) -> list[dict]:
    present = set(notes["data_sources"])
    cov = notes.get("coverage", {})
    rows = []
    for t in plan.required_techniques + plan.context_techniques:
        srcs = playbooks.SOURCES[t]
        gaps, usable = [], []
        for s in srcs:
            miss = notes.get("missing_fields", {}).get(f"{t}/{s}", [])
            if s not in present:
                gaps.append(f"no '{s}' data ingested")
            elif s in cov and not cov[s]["total"]:
                gaps.append(f"no '{s}' events in the hunt window")
            elif miss:
                gaps.append(f"'{s}' events lack required fields {miss}")
            else:
                usable.append(s)
            c = cov.get(s)
            if c and c["n_buckets"] and 1 - c["coverage_ratio"] > GAP_THRESHOLD:
                gaps.append(f"'{s}' has empty time buckets ({len(c['empty_buckets'])}/{c['n_buckets']})")
        steps = [s for s in plan.steps + st.dynamic_steps if s.technique == t and s.role == "indicator"]
        errored = [s.step_id for s in steps if st.step_results.get(s.step_id, {}).get("status") != "ok"]
        if errored:
            gaps.append(f"steps did not complete: {errored}")
        ok = [c for c in st.claims if c.technique == t and c.status in ACCEPTED and c.kind != "ioc"]
        distinct = sorted({c.step_id for c in ok})
        need = MIN_SUPPORT.get(t, 1)
        rows.append({"technique": t, "name": plan.entities["technique_names"].get(t, t), "required": t in plan.required_techniques,
                     "sources": srcs, "usable_sources": usable, "accepted_claims": len(ok), "supporting_steps": distinct, "min_support": need,
                     "supported": len(distinct) >= need, "any_signal": bool(ok), "covered": not gaps, "gaps": gaps})
    return rows


def decide(plan: HuntPlan, st: HuntState, notes: dict) -> dict:
    rows = technique_table(plan, st, notes)
    req = [r for r in rows if r["required"]]
    reasons = []
    if not req:
        return {"verdict": "INCONCLUSIVE", "confidence": "low", "rows": rows,
                "reasons": ["No playbook matched the hypothesis, so nothing could be tested."], "requires_analyst_review": False}
    if all(not r["usable_sources"] for r in req):
        verdict = "INSUFFICIENT_DATA"
        reasons += [f"{r['technique']}: {'; '.join(r['gaps'])}" for r in req]
    elif notes["entity_missing"]:
        reasons.append(f"No telemetry exists for named entities {notes['entity_missing']}; absence of events cannot be interpreted.")
        verdict = "INCONCLUSIVE"
    elif all(r["supported"] for r in req):
        verdict = "SUPPORTED"
        reasons.append("Every required technique has at least the minimum number of independent self-checked indicators.")
    elif not any(r["any_signal"] for r in req) and all(r["covered"] for r in req):
        verdict = "NOT_SUPPORTED"
        reasons.append("All required sources and fields were covered for the full window and no indicator exists for any required technique.")
    else:
        verdict = "INCONCLUSIVE"
        for r in req:
            if not r["supported"]:
                reasons.append(f"{r['technique']}: {len(r['supporting_steps'])}/{r['min_support']} independent indicators; gaps: {r['gaps'] or 'none'}")
    if any(n.startswith("budget exhausted") for n in st.notes):
        reasons.append(f"The tool-call budget ({st.max_calls}) was exhausted before every step ran.")
    if notes["entity_missing"] and any(c.status in ACCEPTED for c in st.claims):
        reasons.append("Context findings exist but concern other entities than the ones named in the hypothesis.")
    # DESIGN.md 4.1: high = supported, fully covered, and corroborated by more than one independent query
    n_steps = len({s for r in req for s in r["supporting_steps"]})
    full = all(r["covered"] for r in req)
    conf = "high" if verdict == "SUPPORTED" and full and n_steps >= 2 else "medium" if verdict in ("SUPPORTED", "NOT_SUPPORTED") else "low"
    return {"verdict": verdict, "confidence": conf, "rows": rows, "reasons": reasons, "requires_analyst_review": verdict == "SUPPORTED"}
