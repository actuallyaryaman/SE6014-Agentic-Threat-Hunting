"""Every playbook step must compile against the fields B1's pipelines (plus the C2 Windows extension) produce."""
import pytest
import yaml
from threat_hunting import config, playbooks
from threat_hunting.query import build_query

T0, T1 = "2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z"
KW = "keyword"
KNOWN = {f: KW for f in (
    "event.dataset", "event.code", "event.action", "event.outcome", "host.name", "user.name", "process.name", "process.executable",
    "process.command_line", "process.parent.name", "winlog.event_data.TargetImage", "winlog.event_data.GrantedAccess", "file.name",
    "file.path", "url.path", "url.original", "url.query", "http.request.method")}
KNOWN.update({"source.ip": "ip", "destination.ip": "ip", "destination.port": "long", "http.response.status_code": "long", "@timestamp": "date"})


@pytest.mark.parametrize("technique", sorted(playbooks.SOURCES))
def test_steps_compile_and_are_scoped(technique):
    steps = playbooks.steps_for(technique, T0, T1, {"hosts": ["WS-01"]})
    assert steps
    for s in steps:
        p = s.params
        assert p["index"] == config.HUNT_INDEX and p["time_from"] == T0 and p["time_to"] == T1
        assert any(f["field"] == "event.dataset" for f in p["filters"]), s.step_id
        build_query(p["time_from"], p["time_to"], p.get("filters"), p.get("must_not"), p.get("any_of"), known=KNOWN)
        for k in ("field", "distinct_field"):
            if p.get(k):
                assert p[k] in KNOWN, (s.step_id, p[k])


def test_tables_are_consistent():
    assert set(playbooks.REQUIRED_FIELDS) == set(playbooks.SOURCES)
    for t, per in playbooks.REQUIRED_FIELDS.items():
        assert set(per) <= set(playbooks.SOURCES[t]) <= set(playbooks.DATASETS), t


def test_dataset_aliases():
    assert playbooks.log_type_of("firewall") == playbooks.log_type_of("firewall.log") == "firewall"
    assert playbooks.log_type_of("Microsoft-Windows-Sysmon/Operational") == "sysmon"
    assert playbooks.log_type_of("aws.s3") is None


def test_promoted_yaml_playbooks_load_and_unload(tmp_path, monkeypatch):
    from threat_hunting import config
    monkeypatch.setattr(config, "PLAYBOOK_DIR", tmp_path)
    pb = {"technique": "T1071.004", "name": "DNS", "status": "approved", "kind": "dns.query", "datasets": ["dns.query"],
          "required_fields": ["dns.question.name"], "keywords": ["tunnel"],
          "steps": [{"id": "T1071.004-a", "tool": "aggregate", "purpose": "p", "claim_template": "{bucket_key}",
                     "analysis": {"bucket_min_distinct": 50}, "params": {"agg": "terms", "field": "dns.question.registered_domain"}}]}
    (tmp_path / "dns.yml").write_text(yaml.safe_dump(pb))
    (tmp_path / "draft.yml").write_text(yaml.safe_dump({**pb, "technique": "T1572", "status": "candidate"}))
    assert set(playbooks.refresh()) == {"T1071.004"}                        # candidates are never used
    (tmp_path / "dns-exfil.yml").write_text(yaml.safe_dump({**pb, "technique": "T1048"}))   # a new source for a built-in technique
    assert set(playbooks.refresh()) == {"T1071.004", "T1048"} and playbooks.SOURCES["T1048"] == ["firewall", "dns.query"]
    ids = [s.step_id for s in playbooks.steps_for("T1048", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", {})]
    assert ids == ["T1048-a", "T1071.004-a"]                               # built-in first, then the promoted steps
    (tmp_path / "dns-exfil.yml").unlink()
    assert playbooks.SOURCES["T1071.004"] == ["dns.query"] and playbooks.log_type_of("dns.query") == "dns.query"
    step = playbooks.steps_for("T1071.004", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", {})[0]
    assert step.params["filters"][0] == {"field": "event.dataset", "op": "in", "value": ["dns.query"]} and step.must_have
    (tmp_path / "dns.yml").unlink()
    assert playbooks.refresh() == {} and "T1071.004" not in playbooks.SOURCES and playbooks.log_type_of("dns.query") is None
    assert playbooks.SOURCES["T1048"] == ["firewall"]


def test_matched_datasets_widen_ds_but_not_the_ssh_specific_filter():
    playbooks.set_matches({"auth": ["vpn.auth"]})
    try:
        assert "vpn.auth" in playbooks.ds("auth")["value"] and "vpn.auth" not in playbooks.native("auth")["value"]
        ids = [s.step_id for s in playbooks.steps_for("T1110", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", {})]
        assert ids == ["T1110-a", "T1110-a@vpn.auth"]
    finally:
        playbooks.set_matches({})


def test_candidates_drop_the_hunt_host_from_queries_and_claim_text(tmp_path, monkeypatch):
    """Live DNS run: the template said "WS-03 issued {count} queries" while the host filter was removed, so vetted claims
    failed the self-check. The host's name goes too."""
    from threat_hunting import config, promote
    from threat_hunting.hunter import HuntState
    from threat_hunting.models import Claim, HuntPlan, PlanStep
    monkeypatch.setattr(config, "ROOT", tmp_path)
    step = PlanStep(step_id="AG-01", technique="T1048", tool="aggregate", purpose="queries per type", role="context",
                    claim_template="WS-03 issued {count} DNS queries of type {bucket_key}", analysis={"bucket_min_count": 1},
                    params={"index": "i", "time_from": "a", "time_to": "b", "agg": "terms", "field": "dns.question.type",
                            "filters": [{"field": "event.dataset", "op": "eq", "value": "dns.query"},
                                        {"field": "host.name", "op": "eq", "value": "WS-03"}]})
    plan = HuntPlan(hypothesis="WS-03 tunnelled data out over DNS", techniques=["T1048"], required_techniques=["T1048"], required_sources=[],
                    time_range={"from": "a", "to": "b"}, steps=[], success_criteria=[], refutation_criteria=[], entities={"hosts": ["WS-03"]})
    st = HuntState(plan)
    st.dynamic_steps = [step]
    st.claims = [Claim(claim_id="C-001", text="t", technique="T1048", evidence_ids=["E"], step_id="AG-01", kind="aggregate",
                       status="self_checked", origin="llm", facts={"bucket_key": "TXT", "count": "120"})]
    out = promote.write_candidates(tmp_path / "runs" / "r1", "r1", plan, st, {"model": "fake"})
    pb = yaml.safe_load((tmp_path / out[0]["file"]).read_text())
    assert pb["steps"][0]["params"]["filters"] == [] and pb["steps"][0]["claim_template"] == "a host issued {count} DNS queries of type {bucket_key}"
