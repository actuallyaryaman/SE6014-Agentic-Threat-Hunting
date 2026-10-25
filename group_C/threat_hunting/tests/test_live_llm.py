"""Live LLM hunts on the c2test indices (opt-in: HUNT_LIVE_LLM=1 and an LLM configured in .env). The agent may take a
different path in every run, so only what code guarantees is asserted: playbook verdicts, a clean self-check, leads only
from agent steps, every agent query recorded, and no injected log text in any prompt."""
import asyncio, json, os

import pytest
import yaml

from threat_hunting import config, llm
from threat_hunting.run import run_hunt

GT_FILE = config.SCENARIO_DIR / "ground_truth.yml"
GT = yaml.safe_load(GT_FILE.read_text()) if GT_FILE.exists() else {}
pytestmark = [pytest.mark.es, pytest.mark.llm,
              pytest.mark.skipif(os.environ.get("HUNT_LIVE_LLM") != "1" or not config.ES_API_KEY or not GT,
                                 reason="opt-in: HUNT_LIVE_LLM=1 with the c2test artifacts and an LLM configured")]
NEW = GT.get("new_sources", {})
CASES = {"primary": ("main", {"SUPPORTED"}), "ssh": ("main", {"SUPPORTED"}), "vpn": ("new", {"SUPPORTED"}),
         "dns_tunnel": ("new", {"INCONCLUSIVE", "INSUFFICIENT_DATA"})}      # dns: leads if the agent finds the tunnel


@pytest.mark.parametrize("case", sorted(CASES))
def test_live_hunt(case, monkeypatch):
    monkeypatch.delenv("HUNT_FORCE_RULES", raising=False)
    if llm.get_llm() is None:
        pytest.skip("no LLM configured")
    index, expected = CASES[case]
    if index == "new":
        monkeypatch.setenv("HUNT_INDEX", NEW["index"])
        monkeypatch.setattr(config, "HUNT_INDEX", NEW["index"])
    h = (NEW["hypotheses"] if index == "new" else GT["hypotheses"])[case]
    r = asyncio.run(run_hunt(h, f"live-{case}"))
    assert r["verdict"]["label"] in expected, r["verdict"]
    assert not r["self_check"]["failed"] and r["agent"]["enabled"] and r["agent"]["steps"]
    ran = {s["step_id"] for s in r["agent"]["steps"] if s["status"] in ("ran", "error")}
    assert {q["step_id"] for q in r["queries"] if q["phase"] == "agent"} == ran
    assert all(s.get("reason") for s in r["agent"]["steps"] if s["status"] == "rejected")
    assert all(c["step_id"].startswith("AG-") for c in r["claims"] if c["origin"] == "llm")
    assert r["manifest"]["llm"]["calls"] <= r["manifest"]["llm"]["max_calls"]
    prompts = (config.RUNS_DIR / r["run_id"] / "llm.jsonl").read_text()
    assert "ignore all previous instructions" not in prompts.lower()
