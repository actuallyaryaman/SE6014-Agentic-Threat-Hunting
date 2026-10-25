"""Skeptic (benign explanations lower confidence only) and action drafts (Sigma rendering, replay, response proposals)."""
import asyncio

from threat_hunting import act, llm, skeptic, verdict
from threat_hunting.models import Claim, PlanStep
from tests.test_agent import FakeMcp, _rows_plan, setup


def _claims():
    return [Claim(claim_id="C-001", text="203.0.113.99 failed 30 times", technique="T1110", evidence_ids=["E"], step_id="T1110-a",
                  status="self_checked", kind="aggregate", facts={"bucket_key": "203.0.113.99", "count": "30"}),
            Claim(claim_id="C-002", text="203.0.113.99 logged in as admin", technique="T1078", evidence_ids=["E"], step_id="T1078-b",
                  status="self_checked", facts={"source.ip": "203.0.113.99", "user.name": "admin"}, event_ids=["security-events-c2test/e1"])]


def test_benign_condition_parser():
    assert skeptic._holds(">0", 1) and skeptic._holds("==0", 0) and not skeptic._holds(">=5", 4) and skeptic._holds("bogus", 1) is None


def test_skeptic_tests_alternatives_and_caps_confidence(fake_llm):
    test = {"action": "search", "technique": "T1078", "purpose": "earlier admin logins from the same IP",
            "params": {"filters": [{"field": "user.name", "op": "eq", "value": "admin"}]}}
    fake_llm({"skeptic": [{"alternatives": [
        {"claim_id": "C-002", "explanation": "admin works from this IP every day", "benign_if": ">0", "action": test},
        {"claim_id": "C-999", "explanation": "no such claim", "benign_if": ">0", "action": test},
        {"claim_id": "C-001", "explanation": "a scanner we run", "benign_if": "maybe", "action": test}]}]})
    plan, st, notes = _rows_plan(_claims())
    notes.update({"index_types": setup()[1]["index_types"], "llm_notes": []})
    llm.start_trace(None)
    sk = asyncio.run(skeptic.challenge(FakeMcp(), plan, st, notes, {"findings": []}))
    assert [a["outcome"] for a in sk["alternatives"]] == ["supported", "not_tested", "not_tested"]
    assert sk["alternatives"][0]["step_id"] == "SK-01" and len(st.claims) == 2          # skeptic tests create no claims
    plain = verdict.decide(plan, st, notes)
    capped = verdict.decide(plan, st, notes, skeptic=sk)
    assert plain["confidence"] == "high" and capped["confidence"] == "medium" and capped["verdict"] == "SUPPORTED"
    assert any("benign explanation not ruled out for C-002" in r for r in capped["review_reasons"])


def test_sigma_rendering_of_filters_and_thresholds():
    step = PlanStep(step_id="T1110-a", technique="T1110", tool="aggregate", purpose="x",
                    params={"index": "i", "time_from": "2026-10-01T08:00:00Z", "time_to": "2026-10-01T18:00:00Z", "agg": "terms",
                            "field": "source.ip", "filters": [{"field": "event.outcome", "op": "eq", "value": "failure"},
                                                              {"field": "host.name", "op": "in", "value": ["DEMO-SSH"]},
                                                              {"field": "user.name", "op": "neq", "value": "svc"}],
                            "any_of": [{"field": "message", "op": "contains", "value": "Failed"}],
                            "must_not": [{"field": "source.ip", "op": "eq", "value": "10.0.0.0/8"}]},
                    analysis={"bucket_min_count": 20})
    base, corr = act.to_sigma(step, "id-1", {"title": "t", "description": "d", "falsepositives": [], "level": "high"}, "auth")
    det = base["detection"]
    assert det["sel1"] == {"event.outcome": "failure"} and det["any1"] == {"message|contains": "Failed"}
    assert det["excl1"] == {"source.ip|cidr": "10.0.0.0/8"} and "host.name" not in str(det)          # host scope removed
    assert det["condition"] == "sel1 and not sel2 and 1 of any* and not 1 of excl*" and base["logsource"]["product"] == "linux"
    assert corr["correlation"] == {"type": "event_count", "rules": ["id-1"], "group-by": ["source.ip"], "timespan": "10h",
                                   "condition": {"gte": 20}}


def test_response_proposals_must_target_cited_facts(fake_llm, tmp_path):
    fake_llm({"responder": [{"rules": [{"rule": "T1078-b", "title": "SSH login after brute force", "level": "high"}],
                             "response": [{"action": "block_ip", "target": "203.0.113.99", "claim_ids": ["C-002"], "reason": "attacker"},
                                          {"action": "block_ip", "target": "8.8.8.8", "claim_ids": ["C-002"], "reason": "made up"},
                                          {"action": "wipe_host", "target": "admin", "claim_ids": ["C-002"]}]}]})
    plan, st, notes = _rows_plan(_claims())
    plan.steps.append(PlanStep(step_id="T1078-b", technique="T1078", tool="search", purpose="logins",
                               params={"index": "i", "time_from": "2026-10-01T00:00:00Z", "time_to": "2026-10-02T00:00:00Z"}))
    notes.update({"llm_notes": [], "datasets": []})
    llm.start_trace(None)
    out = asyncio.run(act.draft(FakeMcp(), plan, st, notes, None, tmp_path / "runs" / "r1", {"verdict": "SUPPORTED", "leads": []}))
    assert [(r["action"], r["target"]) for r in out["response"]] == [("block_ip", "203.0.113.99")]
    assert len([n for n in out["notes"] if n.startswith("response proposal dropped")]) == 2
    rule = next(d for d in out["detections"] if d["from_step"] == "T1078-b")
    assert rule["title"] == "SSH login after brute force" and rule["metadata_by"] == "llm" and rule["validation"]["ok"]


def test_rejected_skeptic_tests_get_one_repair_round(fake_llm):
    bad = {"action": "search", "technique": "T1078", "purpose": "earlier logins", "params": {"user": "admin"}}
    good = {"action": "search", "technique": "T9999", "purpose": "earlier logins",
            "params": {"filters": [{"field": "user.name", "op": "eq", "value": "admin"}]}}
    fake = fake_llm({"skeptic": [{"alternatives": [{"claim_id": "C-002", "explanation": "admin works from home", "benign_if": ">0", "action": bad}]},
                                 {"alternatives": [{"claim_id": "C-002", "explanation": "admin works from home", "benign_if": ">0", "action": good}]}]})
    plan, st, notes = _rows_plan(_claims())
    notes.update({"index_types": setup()[1]["index_types"], "llm_notes": []})
    llm.start_trace(None)
    sk = asyncio.run(skeptic.challenge(FakeMcp(), plan, st, notes, {"findings": []}))
    first, second = sk["alternatives"]
    assert first["superseded"] and "unknown params ['user']" in first["reason"]
    assert second["outcome"] == "supported" and second["step_id"] == "SK-01"          # technique comes from the claim, not the LLM
    assert "unknown params ['user']" in fake.prompts["skeptic"][1][1]
