"""Agent mode end to end over MCP on the c2test index, with a scripted LLM (python -m dev.setup_test_es first)."""
import asyncio, json

import pytest
import yaml

from threat_hunting import config
from threat_hunting.run import run_hunt

pytestmark = [pytest.mark.es, pytest.mark.skipif(not config.ES_API_KEY or not (config.SCENARIO_DIR / "ground_truth.yml").exists(),
                                                 reason="c2test artifacts missing: run python -m dev.setup_test_es")]
GT = yaml.safe_load((config.SCENARIO_DIR / "ground_truth.yml").read_text()) if (config.SCENARIO_DIR / "ground_truth.yml").exists() else {}
H = GT.get("hypotheses", {})

PIVOT = {"thought": "What else did the brute-forcing source do?", "action": "search", "technique": "T1078",
         "purpose": "Every event from 203.0.113.99 in the window, any dataset",
         "params": {"filters": [{"field": "source.ip", "op": "eq", "value": "203.0.113.99"},
                                {"field": "event.outcome", "op": "eq", "value": "success"}],
                    "fields": ["@timestamp", "event.dataset", "host.name", "user.name"]},
         "claim": {"template": "{source.ip} had a successful {event.dataset} event as {user.name} on {host.name}",
                   "group_by": ["source.ip", "event.dataset", "user.name", "host.name"]}}
POISON = {"thought": "Check the web source that sent odd user agents", "action": "search", "technique": "T1078",
          "purpose": "Web requests from 192.0.2.77", "params": {"filters": [{"field": "source.ip", "op": "eq", "value": "192.0.2.77"}],
                                                               "fields": ["@timestamp", "url.path", "user_agent.original"]}}


@pytest.fixture(scope="module")
def runs():
    from tests.fake_llm import FakeLLM
    from threat_hunting import llm
    fake = FakeLLM({"intake": lambda s, u: {}, "investigator": [PIVOT, POISON, {"thought": "done", "action": "stop", "reason": "enough"}]})
    rules = asyncio.run(run_hunt(H["ssh"], "pytest-agent-rules"))
    llm.set_override(fake)
    try:
        agentic = asyncio.run(run_hunt(H["ssh"], "pytest-agent"))
    finally:
        llm.set_override(None)
    return rules, agentic, fake


def test_agent_adds_leads_without_changing_the_playbook_verdict(runs):
    rules, agentic, _ = runs
    assert agentic["verdict"]["label"] == rules["verdict"]["label"] == "SUPPORTED"
    pb = lambda r: [c["text"] for c in r["claims"] if c["origin"] == "playbook"]
    assert pb(agentic) == pb(rules)
    leads = [c for c in agentic["claims"] if c["origin"] == "llm"]
    assert leads and leads[0]["step_id"] == "AG-01" and agentic["verdict"]["leads"] == [c["claim_id"] for c in leads if c["technique"] == "T1078"]
    assert not agentic["self_check"]["failed"]


def test_agent_steps_queries_and_llm_trace_are_recorded(runs):
    _, agentic, _ = runs
    a = agentic["agent"]
    assert a["enabled"] and [s["status"] for s in a["steps"]] == ["ran", "ran", "stop"]
    q = [x for x in agentic["queries"] if x["phase"] == "agent"]
    assert [x["step_id"] for x in q] == ["AG-01", "AG-02"] and all(x["dsl"] for x in q)
    trace = (config.RUNS_DIR / agentic["run_id"] / "llm.jsonl").read_text().splitlines()
    assert len(trace) == agentic["manifest"]["llm"]["calls"] == 4
    assert [json.loads(line)["role"] for line in trace] == ["intake", "investigator", "investigator", "investigator"]


def test_injected_log_text_is_withheld_from_the_llm(runs):
    _, agentic, fake = runs
    third = fake.prompts["investigator"][2][1]
    assert "withheld" in third and "IGNORE ALL PREVIOUS" not in third.upper()
    assert agentic["findings"]["prompt_injection"]["findings"]
