"""Verdict rules on hand-built plans and states (no Elasticsearch)."""
from threat_hunting import verdict
from threat_hunting.hunter import HuntState
from threat_hunting.models import Claim, HuntPlan, PlanStep

TR = {"from": "2026-10-01T08:00:00Z", "to": "2026-10-01T18:00:00Z"}
FULL = {"n_buckets": 10, "empty_buckets": [], "coverage_ratio": 1.0, "total": 600}


def _state(claims=(), steps_ok=("T1110-a",), required=("T1110",)):
    steps = [PlanStep(step_id=s, technique=s.split("-")[0], tool="aggregate", params={}, purpose="x") for s in steps_ok]
    plan = HuntPlan(hypothesis="h", techniques=list(required), required_techniques=list(required), required_sources=["auth"],
                    time_range=TR, steps=steps, success_criteria=[], refutation_criteria=[], entities={"technique_names": {}})
    st = HuntState(plan)
    st.step_results = {s: {"status": "ok"} for s in steps_ok}
    st.claims = list(claims)
    return plan, st


def _notes(**kw):
    n = {"data_sources": {"auth": 600}, "coverage": {"auth": FULL}, "gaps": [], "missing_fields": {}, "entity_missing": []}
    n.update(kw)
    return n


def _claim(step, status="self_checked", technique="T1110"):
    return Claim(claim_id=f"C-{step}", text="t", technique=technique, evidence_ids=["E"], step_id=step, status=status)


def test_supported_and_flagged_for_review():
    plan, st = _state([_claim("T1110-a"), _claim("T1078-b", technique="T1078")], steps_ok=("T1110-a", "T1078-b"), required=("T1110", "T1078"))
    d = verdict.decide(plan, st, _notes())
    assert d["verdict"] == "SUPPORTED" and d["confidence"] == "high" and d["requires_analyst_review"]
    assert d["review_reasons"] == ["SUPPORTED verdicts always require analyst review"]


def test_clean_not_supported_needs_no_review():
    plan, st = _state()
    d = verdict.decide(plan, st, _notes())
    assert d["verdict"] == "NOT_SUPPORTED" and not d["requires_analyst_review"] and d["review_reasons"] == []


def test_low_confidence_gaps_injection_and_failed_claims_force_review():
    plan, st = _state()
    d = verdict.decide(plan, st, _notes(missing_fields={"T1110/auth": ["event.outcome"]}))
    assert d["requires_analyst_review"] and "low confidence" in d["review_reasons"]
    assert any(r.startswith("coverage gaps") for r in d["review_reasons"])
    d = verdict.decide(plan, st, _notes(), guard={"findings": [{"event_id": "i/e"}]})
    assert d["verdict"] == "NOT_SUPPORTED" and d["review_reasons"] == ["1 event(s) in the window contain prompt-injection-like text"]
    d = verdict.decide(plan, st, _notes(), check={"failed": [{"claim_id": "C-1"}]})
    assert d["review_reasons"] == ["1 claim(s) failed the self-check"]


def test_single_query_support_is_medium_confidence():
    plan, st = _state([_claim("T1110-a")])
    assert verdict.decide(plan, st, _notes())["confidence"] == "medium"


def test_claims_that_failed_the_self_check_do_not_count():
    plan, st = _state([_claim("T1110-a", status="unsupported")])
    assert verdict.decide(plan, st, _notes())["verdict"] == "NOT_SUPPORTED"


def test_not_supported_needs_full_coverage():
    plan, st = _state()
    assert verdict.decide(plan, st, _notes())["verdict"] == "NOT_SUPPORTED"
    gappy = {"n_buckets": 10, "empty_buckets": list("abc"), "coverage_ratio": 0.7, "total": 400}
    assert verdict.decide(plan, st, _notes(coverage={"auth": gappy}))["verdict"] == "INCONCLUSIVE"


def test_missing_required_fields_is_insufficient_data():
    plan, st = _state()
    d = verdict.decide(plan, st, _notes(missing_fields={"T1110/auth": ["event.outcome"]}))
    assert d["verdict"] == "INSUFFICIENT_DATA" and "event.outcome" in " ".join(d["reasons"])


def test_missing_source_is_insufficient_data():
    plan, st = _state()
    assert verdict.decide(plan, st, _notes(data_sources={"web": 10}, coverage={}))["verdict"] == "INSUFFICIENT_DATA"


def test_empty_window_is_insufficient_data():
    plan, st = _state()
    empty = {"n_buckets": 24, "empty_buckets": ["x"] * 24, "coverage_ratio": 0.0, "total": 0}
    d = verdict.decide(plan, st, _notes(coverage={"auth": empty}))
    assert d["verdict"] == "INSUFFICIENT_DATA" and "no 'auth' events in the hunt window" in " ".join(d["reasons"])


def test_named_entity_without_telemetry_is_inconclusive():
    plan, st = _state()
    d = verdict.decide(plan, st, _notes(entity_missing=["HR-LAPTOP-99"]))
    assert d["verdict"] == "INCONCLUSIVE" and "HR-LAPTOP-99" in " ".join(d["reasons"])


def test_failed_step_is_inconclusive():
    plan, st = _state()
    st.step_results["T1110-a"] = {"status": "error"}
    assert verdict.decide(plan, st, _notes())["verdict"] == "INCONCLUSIVE"


def test_no_refutation_without_a_readable_mapping():
    """Team-stack finding: without view_index_metadata the ES server cannot type fields and ip filters match nothing."""
    plan, st = _state()
    d = verdict.decide(plan, st, _notes(mapping_missing=True))
    assert d["verdict"] == "INCONCLUSIVE" and any("mapping could not be read" in g for r in d["rows"] for g in r["gaps"])
