"""The C2 self-check catches claims that are not backed by the results the agent holds."""
from threat_hunting import selfcheck
from threat_hunting.hunter import HuntState, extract_claims
from threat_hunting.models import Evidence, HuntPlan, PlanStep

TR = {"from": "2026-10-01T08:00:00Z", "to": "2026-10-01T18:00:00Z"}
HITS = [{"index": "security-events-c2test", "event_id": f"id{i}", "fields": {"@timestamp": f"2026-10-01T14:00:0{i}.000Z",
         "source.ip": "203.0.113.99", "user.name": "admin", "host.name": "WS-02"}} for i in range(3)]
AGG = [{"key": "203.0.113.99", "count": 30}, {"key": "203.0.113.7", "count": 3}]


def _state():
    s_search = PlanStep(step_id="S", technique="T1078", tool="search", params={"filters": []}, purpose="x",
                        claim_template="Source {source.ip} logged in as {user.name} on {host.name}", analysis={"group_by": ["source.ip", "user.name", "host.name"]})
    s_agg = PlanStep(step_id="A", technique="T1110", tool="aggregate", params={"filters": []}, purpose="x",
                     claim_template="Source {bucket_key} produced {count} failed SSH logins", analysis={"bucket_min_count": 20})
    plan = HuntPlan(hypothesis="h", techniques=["T1110", "T1078"], required_techniques=["T1110", "T1078"], required_sources=["auth"],
                    time_range=TR, steps=[s_search, s_agg], success_criteria=[], refutation_criteria=[])
    st = HuntState(plan)
    st.raw = {"S": {"hits": HITS, "total": 3}, "A": {"result": AGG, "total": 33}}
    st.evidence = [Evidence(evidence_id="E-S", call_id="c1", step_id="S", event_ids=[f'{h["index"]}/{h["event_id"]}' for h in HITS]),
                   Evidence(evidence_id="E-A", call_id="c2", step_id="A")]
    extract_claims(st, s_search, st.raw["S"])
    extract_claims(st, s_agg, st.raw["A"])
    return st


def test_claims_derived_from_results_pass():
    st = _state()
    r = selfcheck.check(st)
    assert r["claims"] == 2 and r["self_checked"] == 2 and not r["failed"]


def test_fabricated_ip_in_text_fails():
    st = _state()
    st.claims[0].text += " and from 198.51.100.200"
    selfcheck.check(st)
    assert st.claims[0].status == "unsupported" and "198.51.100.200" in st.claims[0].verifier_notes


def test_event_ids_must_come_from_cited_results():
    st = _state()
    st.claims[0].event_ids.append("security-events-c2test/invented")
    selfcheck.check(st)
    assert st.claims[0].status == "unsupported"


def test_aggregate_numbers_must_match_the_bucket():
    st = _state()
    st.claims[1].facts["count"] = "300"
    selfcheck.check(st)
    assert st.claims[1].status == "unsupported" and "count=300" in st.claims[1].verifier_notes


def test_a_value_from_other_evidence_in_facts_fails():
    """PR #24 / C3 finding: the T1078 claim quoted the T1110 failure count, which is not in its cited success events."""
    st = _state()
    st.claims[0].facts["failed_logins"] = "30"
    st.claims[0].text += " (30 failures from this source in the window)"
    selfcheck.check(st)
    assert st.claims[0].status == "unsupported"
    assert "failed_logins" in st.claims[0].verifier_notes and "['30']" in st.claims[0].verifier_notes


def test_facts_do_not_validate_their_own_text():
    """A value present only in the claim's facts is not evidence (same rule C3 applies)."""
    st = _state()
    st.claims[1].facts["host.name"] = "WS-9999"
    st.claims[1].text += " on WS-9999 at port 4444"
    selfcheck.check(st)
    assert st.claims[1].status == "unsupported" and "4444" in st.claims[1].verifier_notes


def test_missing_evidence_fails():
    st = _state()
    st.claims[1].evidence_ids = ["E-nope"]
    selfcheck.check(st)
    assert st.claims[1].status == "unsupported"


def test_ip_and_port_are_not_read_as_a_time():
    """Live agent claim "demo from 198.51.100.20:43000": "20:43" was stripped as a time, leaving a stray "000"."""
    assert selfcheck.lint_text("demo from 198.51.100.20:43000", '{"source.ip": "198.51.100.20", "source.port": 43000}') == []
    assert selfcheck.lint_text("demo from 198.51.100.21:43000", '{"source.ip": "198.51.100.20", "source.port": 43000}') == ["198.51.100.21"]
    assert selfcheck.lint_text("at 14:03 from WS-02", '{"host.name": "ws-02"}') == []   # a clock time is still not a number to check
