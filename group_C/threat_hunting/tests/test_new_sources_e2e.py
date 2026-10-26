"""New-source mode end to end on security-events-c2test-new (python -m dev.setup_test_es first): a VPN log that joins the auth
playbooks through its ECS fields, and a DNS log no playbook covers, hunted in draft mode, promoted, then hunted as vetted."""
import asyncio

import pytest
import yaml

from threat_hunting import config, llm, promote
from threat_hunting.run import run_hunt

GT_FILE = config.SCENARIO_DIR / "ground_truth.yml"
NEW = (yaml.safe_load(GT_FILE.read_text()) if GT_FILE.exists() else {}).get("new_sources", {})
pytestmark = [pytest.mark.es, pytest.mark.skipif(not config.ES_API_KEY or not NEW, reason="c2test artifacts missing: run python -m dev.setup_test_es")]

TUNNEL = {"thought": "Tunnelling shows as one domain with very many distinct names", "action": "aggregate", "technique": "T1071.004",
          "purpose": "Registered domains queried with many distinct names (DNS tunnelling)",
          "params": {"filters": [{"field": "event.dataset", "op": "eq", "value": "dns.query"},       # scoped to the named host
                                 {"field": "host.name", "op": "eq", "value": "WS-03"}], "agg": "terms",
                     "field": "dns.question.registered_domain", "distinct_field": "dns.question.name", "size": 10},
          "claim": {"template": "{bucket_key} was queried with {distinct} distinct names in {count} lookups", "bucket_min_distinct": 50}}


@pytest.fixture
def new_index(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNT_INDEX", NEW["index"])
    monkeypatch.setattr(config, "HUNT_INDEX", NEW["index"])
    monkeypatch.setattr(config, "PLAYBOOK_DIR", tmp_path / "playbooks")
    return tmp_path


def classify(system, user):
    return {"kind": "auth", "reason": "logins"} if "vpn.auth" in user else {"kind": "auth", "reason": "wrong on purpose"}


def test_vpn_log_joins_the_auth_playbooks_by_its_ecs_fields(new_index):
    r = asyncio.run(run_hunt(NEW["hypotheses"]["vpn"], "pytest-new-vpn"))
    assert r["verdict"]["label"] == "SUPPORTED", r["verdict"]
    src = {u["dataset"]: u for u in r["coverage"]["unknown_sources"]}
    assert src["vpn.auth"]["matched_kind"] == "auth" and src["vpn.auth"]["proposed_by"] == "rules"
    assert src["dns.query"]["matched_kind"] is None
    by_step = {c["step_id"]: c for c in r["claims"]}
    assert by_step["T1110-a@vpn.auth"]["facts"] == {"bucket_key": "198.51.100.23", "count": "40"}
    assert by_step["T1078-b-198.51.100.23@vpn.auth"]["facts"]["user.name"] == "jdoe"
    assert all(c["origin"] == "playbook" for c in r["claims"])


def test_a_wrong_classifier_proposal_is_overruled_by_code(new_index, fake_llm):
    fake_llm({"intake": lambda s, u: {}, "classifier": classify, "investigator": [{"action": "stop", "reason": "nothing to add"}],
              "skeptic": lambda s, u: {"alternatives": []}, "responder": lambda s, u: {}})
    r = asyncio.run(run_hunt(NEW["hypotheses"]["vpn"], "pytest-new-classifier"))
    src = {u["dataset"]: u for u in r["coverage"]["unknown_sources"]}
    assert src["vpn.auth"]["matched_kind"] == "auth" and src["vpn.auth"]["proposed_by"] == "llm"
    assert src["dns.query"]["proposed_kind"] == "auth" and src["dns.query"]["matched_kind"] is None
    assert "do not include 'authentication'" in src["dns.query"]["not_matched_because"]


def test_dns_tunnelling_goes_from_lead_to_promoted_playbook_to_vetted_verdict(new_index, fake_llm):
    fake_llm({"intake": lambda s, u: {}, "classifier": classify, "investigator": [TUNNEL, {"action": "stop", "reason": "found it"}],
              "skeptic": lambda s, u: {"alternatives": []}, "responder": lambda s, u: {}})
    h = NEW["hypotheses"]["dns_tunnel"]
    draft = asyncio.run(run_hunt(h, "pytest-new-dns-draft"))
    llm.set_override(None)
    assert draft["agent"]["draft_mode"] and draft["verdict"]["label"] == "INCONCLUSIVE"
    lead = next(c for c in draft["claims"] if c["origin"] == "llm")
    assert lead["facts"]["bucket_key"] == "exfil-tunnel.net" and draft["verdict"]["leads"] == [lead["claim_id"]]
    assert any("cannot decide the verdict without a vetted playbook" in x for x in draft["verdict"]["reasons"])
    cand = config.ROOT / draft["candidates"][0]["file"]
    pb = yaml.safe_load(cand.read_text())
    assert pb["status"] == "candidate" and pb["datasets"] == ["dns.query"] and pb["steps"][0]["expect"] == ["exfil-tunnel.net"]

    attack = (pb["provenance"]["window"]["from"], pb["provenance"]["window"]["to"])
    refused = asyncio.run(promote.promote(cand, attack, "pytest", ["tunnel"]))            # the attack window is not benign
    assert not refused["ok"] and refused["file"] is None and not config.PLAYBOOK_DIR.exists()
    bw = NEW["benign_window"]
    done = asyncio.run(promote.promote(cand, (bw["from"], bw["to"]), "pytest", ["tunnel"]))
    assert done["ok"] and done["validation"]["attack"][0]["reproduced"] and done["validation"]["benign"][0]["claims"] == 0

    vetted = asyncio.run(run_hunt(h, "pytest-new-dns-vetted"))                             # rules only: the promoted playbook decides
    assert vetted["verdict"]["label"] == "SUPPORTED" and vetted["verdict"]["confidence"] == "medium", vetted["verdict"]
    c = next(c for c in vetted["claims"] if c["technique"] == "T1071.004")
    assert c["origin"] == "playbook" and c["step_id"] == "T1071.004-dns.query-a" and c["facts"]["bucket_key"] == "exfil-tunnel.net"
