"""Analyst memory: only analysts add lessons, entities come from the claim, benign matches flag but never suppress."""
import json

import pytest

from threat_hunting import config, feedback, verdict
from threat_hunting.models import Claim
from tests.test_agent import _rows_plan


@pytest.fixture
def memory(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MEMORY_FILE", tmp_path / "memory" / "lessons.jsonl")
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "runs")
    run = tmp_path / "runs" / "r1"
    run.mkdir(parents=True)
    (run / "plan.json").write_text(json.dumps({"steps": [{"step_id": "T1110-a", "params": {"field": "source.ip"}}]}))
    (run / "result.json").write_text(json.dumps({"dynamic_steps": [], "claims": [
        {"claim_id": "C-001", "technique": "T1110", "step_id": "T1110-a", "text": "t", "facts": {"bucket_key": "10.0.9.5", "count": "40"}},
        {"claim_id": "C-002", "technique": "T1078", "step_id": "T1078-b", "text": "t", "facts": {"source.ip": "10.0.9.5", "user.name": "svc"}}]}))
    return tmp_path


def test_lessons_take_entities_from_the_claim_and_can_be_revoked(memory):
    a = feedback.add("r1", "C-001", "benign", "Nessus scanner run by IT", "dat")
    assert a["id"] == "L-001" and a["entities"] == [{"field": "source.ip", "value": "10.0.9.5"}]
    b = feedback.add("r1", "C-002", "useful_pivot", "check svc logins", "dat")
    assert {"field": "user.name", "value": "svc"} in b["entities"]
    feedback.revoke("L-002", "dat")
    assert [x["status"] for x in feedback.load()] == ["active", "revoked"]
    with pytest.raises(SystemExit):
        feedback.add("r1", "C-001", "harmless", "bad label", "dat")


def test_benign_lessons_flag_matching_findings_for_review(memory):
    feedback.add("r1", "C-001", "benign", "Nessus scanner run by IT", "dat")
    claim = Claim(claim_id="C-001", text="t", technique="T1110", evidence_ids=["E"], step_id="T1110-a", status="self_checked",
                  kind="aggregate", facts={"bucket_key": "10.0.9.5", "count": "33"})
    plan, st, notes = _rows_plan([claim])
    lessons = feedback.relevant(plan)
    assert [x["id"] for x in lessons] == ["L-001"] and "claim_text" not in feedback.for_prompt(lessons)[0]
    flags = feedback.benign_matches(lessons, st.claims)
    d = verdict.decide(plan, st, notes, lesson_flags=flags)
    assert flags == {"C-001": ["L-001"]} and len(st.claims) == 1          # flagged, not suppressed
    assert any("matches analyst lesson(s) L-001 labelled benign" in r for r in d["review_reasons"])
