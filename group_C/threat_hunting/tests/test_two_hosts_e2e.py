"""PR #29's two-host check end to end over MCP, on security-events-c2test-twohost (python -m dev.setup_test_es first): PR #29's
exact DEMO-SSH / BENIGN-SSH lines through B1's linux-auth pipeline. Its gate: the events cited by all claims of the DEMO-SSH hunt
are exactly the 31 attack events, also when the investigator runs a follow-up query without a host filter."""
import asyncio

import pytest
import yaml

from dev.setup_test_es import TWO_INDEX, doc_id
from scenarios.generate import two_host_lines
from tests.test_scope import UNSCOPED_COUNTS, UNSCOPED_LOGINS
from threat_hunting import config, llm
from threat_hunting.run import run_hunt

GT_FILE = config.SCENARIO_DIR / "ground_truth.yml"
TWO = (yaml.safe_load(GT_FILE.read_text()) if GT_FILE.exists() else {}).get("two_hosts", {})
pytestmark = [pytest.mark.es, pytest.mark.skipif(not config.ES_API_KEY or not TWO, reason="c2test artifacts missing: run python -m dev.setup_test_es")]
ATTACK = {f"{TWO_INDEX}/{doc_id('auth', i, line)}" for i, line in enumerate(two_host_lines()[:31])}


@pytest.fixture
def two_hosts(monkeypatch):
    monkeypatch.setenv("HUNT_INDEX", TWO_INDEX)
    monkeypatch.setattr(config, "HUNT_INDEX", TWO_INDEX)


def cited(r):
    return {e for c in r["claims"] for e in c["event_ids"]}


def test_rules_mode_cites_exactly_the_attack_and_refutes_the_benign_host(two_hosts):
    attack = asyncio.run(run_hunt(TWO["hypotheses"]["attack"], "pytest-twohost-rules-attack"))
    assert attack["verdict"]["label"] == "SUPPORTED" and cited(attack) == ATTACK and len(ATTACK) == TWO["attack_lines"]
    benign = asyncio.run(run_hunt(TWO["hypotheses"]["benign"], "pytest-twohost-rules-benign"))
    assert benign["verdict"]["label"] == "NOT_SUPPORTED" and not benign["claims"]


def test_an_unscoped_agent_query_does_not_add_benign_ssh_events(two_hosts, fake_llm):
    fake_llm({"intake": lambda s, u: {}, "investigator": [UNSCOPED_LOGINS, UNSCOPED_COUNTS, {"action": "stop", "reason": "done"}],
              "skeptic": lambda s, u: {"alternatives": []}, "responder": lambda s, u: {}})
    r = asyncio.run(run_hunt(TWO["hypotheses"]["attack"], "pytest-twohost-agent-attack"))
    llm.set_override(None)
    assert r["verdict"]["label"] == "SUPPORTED" and cited(r) == ATTACK, sorted(cited(r) - ATTACK)
    assert not any("BENIGN-SSH" in c["text"] or "198.51.100.20" in c["text"] for c in r["claims"])
    s1, s2 = r["agent"]["steps"][:2]
    assert s1["claims"] and s1["out_of_scope"] == {"hits": 1, "hosts": ["BENIGN-SSH"]}
    assert s2["claims"] == [] and s2["out_of_scope"] == {"aggregation": "not limited to the hypothesis's hosts"}
