"""Host scope of investigator findings (PR #29): with DEMO-SSH named in the hypothesis, an unscoped follow-up query must not
turn BENIGN-SSH events into claims. Uses PR #29's seeded data: 30 failed logins and 1 success from 203.0.113.99 on DEMO-SSH,
3 failed logins and 1 success from 198.51.100.20 on BENIGN-SSH. Scripted LLM, in-memory MCP; no Elasticsearch."""
import asyncio

from threat_hunting import agent, llm, verdict
from threat_hunting.hunter import HuntState
from threat_hunting.models import HuntPlan

INDEX = "security-events-c2test-twohost"
EVENTS = ([{"id": f"demo-f{i}", "host.name": "DEMO-SSH", "source.ip": "203.0.113.99", "event.outcome": "failure",
            "@timestamp": f"2026-10-25T00:10:{i:02d}Z"} for i in range(30)]
          + [{"id": "demo-s", "host.name": "DEMO-SSH", "source.ip": "203.0.113.99", "event.outcome": "success", "@timestamp": "2026-10-25T00:11:00Z"}]
          + [{"id": f"benign-f{i}", "host.name": "BENIGN-SSH", "source.ip": "198.51.100.20", "event.outcome": "failure",
              "@timestamp": f"2026-10-25T00:10:{i:02d}Z"} for i in range(3)]
          + [{"id": "benign-s", "host.name": "BENIGN-SSH", "source.ip": "198.51.100.20", "event.outcome": "success", "@timestamp": "2026-10-25T00:11:00Z"}])
for e in EVENTS:
    e.update({"user.name": "demo", "event.action": "ssh_login", "event.dataset": "linux.auth"})
DEMO_IDS = {f"{INDEX}/{e['id']}" for e in EVENTS if e["host.name"] == "DEMO-SSH"}
TYPES = {f: "keyword" for f in ("event.dataset", "host.name", "user.name", "event.action", "event.outcome")} | {"@timestamp": "date", "source.ip": "ip"}


class TwoHostMcp:
    """Evaluates eq/in filters over the 35 events and answers search, count and terms aggregations."""
    def __init__(self):
        self.calls = 0

    async def call(self, tool, **a):
        self.calls += 1
        rows = [e for e in EVENTS if all(e.get(f["field"]) in (f["value"] if isinstance(f["value"], list) else [f["value"]])
                                         for f in a.get("filters", []) if f.get("op", "eq") in ("eq", "in"))]
        out = {"call_id": f"c{self.calls}", "total": len(rows)}
        if tool == "search":
            out["hits"] = [{"index": INDEX, "event_id": e["id"], "fields": {k: e[k] for k in a.get("fields", []) if k in e}} for e in rows]
        elif tool == "aggregate":
            keys = sorted({e[a["field"]] for e in rows})
            out["result"] = [{"key": k, "count": sum(1 for e in rows if e[a["field"]] == k)} for k in keys]
        return out


def plan(host="DEMO-SSH"):
    return HuntPlan(hypothesis=f"An external IP brute-forced SSH on {host} and then logged in successfully on 2026-10-25.",
                    techniques=["T1110", "T1078"], required_techniques=["T1110", "T1078"], required_sources=["auth"],
                    time_range={"from": "2026-10-25T00:00:00Z", "to": "2026-10-25T01:00:00Z"}, steps=[], success_criteria=[],
                    refutation_criteria=[], entities={"hosts": [host] if host else [], "technique_names": {}})


SUCCESS = {"field": "event.outcome", "op": "eq", "value": "success"}
FAILURE = {"field": "event.outcome", "op": "eq", "value": "failure"}
UNSCOPED_LOGINS = {"thought": "who logged in after the failures?", "action": "search", "technique": "T1078", "purpose": "successful logins",
                   "params": {"filters": [SUCCESS], "fields": ["@timestamp", "source.ip"]},
                   "claim": {"template": "Source {source.ip} logged in as {user.name}", "group_by": ["source.ip"]}}
UNSCOPED_COUNTS = {"action": "aggregate", "technique": "T1110", "purpose": "failures per source",
                   "params": {"filters": [FAILURE], "agg": "terms", "field": "source.ip"},
                   "claim": {"template": "Source {bucket_key} failed {count} times", "bucket_min_count": 1}}
PER_HOST = {"action": "aggregate", "technique": "T1110", "purpose": "failures per host",
            "params": {"filters": [FAILURE], "agg": "terms", "field": "host.name"},
            "claim": {"template": "{bucket_key} had {count} failed logins", "bucket_min_count": 1}}


def hunt(fake_llm, script, host="DEMO-SSH"):
    fake = fake_llm({"investigator": script + [{"action": "stop", "reason": "done"}]})
    p = plan(host)
    st = HuntState(p)
    llm.start_trace(None)
    out = asyncio.run(agent.investigate(TwoHostMcp(), p, st, {"index_types": TYPES, "datasets": [], "llm_notes": []}, {"findings": []}))
    return p, st, out, fake


def test_unrelated_benign_ssh_events_never_become_claims_of_a_demo_ssh_hunt(fake_llm):
    p, st, out, fake = hunt(fake_llm, [UNSCOPED_LOGINS, UNSCOPED_COUNTS, PER_HOST])
    cited = {e for c in st.claims for e in c.event_ids}
    assert cited and cited <= DEMO_IDS                                   # PR #29's gate: no event outside the attack
    text = " ".join(c.text + str(c.facts) for c in st.claims)
    assert "BENIGN-SSH" not in text and "198.51.100.20" not in text
    login = next(c for c in st.claims if c.step_id == "AG-01")
    assert login.facts == {"source.ip": "203.0.113.99", "user.name": "demo", "host.name": "DEMO-SSH"}   # host and user grouped on
    s1, s2, s3 = out["steps"][:3]
    assert s1["out_of_scope"] == {"hits": 1, "hosts": ["BENIGN-SSH"]}     # kept as context in the agent record
    assert s2["claims"] == [] and "not limited to the hypothesis's hosts" in fake.prompts["investigator"][2][1]
    assert [c.facts["bucket_key"] for c in st.claims if c.step_id == "AG-03"] == ["DEMO-SSH"] and s3["out_of_scope"]["hosts"] == ["BENIGN-SSH"]


def test_a_host_filtered_query_keeps_its_findings(fake_llm):
    scoped = {**UNSCOPED_COUNTS, "params": {**UNSCOPED_COUNTS["params"],
                                            "filters": [FAILURE, {"field": "host.name", "op": "eq", "value": "DEMO-SSH"}]}}
    p, st, out, _ = hunt(fake_llm, [scoped])
    assert [(c.facts["bucket_key"], c.facts["count"]) for c in st.claims] == [("203.0.113.99", "30")] and "out_of_scope" not in out["steps"][0]


def test_the_benign_host_hunt_only_sees_benign_ssh_events(fake_llm):
    """The same unscoped query in the BENIGN-SSH hunt: its finding cites the BENIGN-SSH login only. It is still a lead, so the
    verdict cannot be NOT_SUPPORTED (leads block a refutation, as in C3)."""
    p, st, out, _ = hunt(fake_llm, [UNSCOPED_LOGINS], host="BENIGN-SSH")
    assert {e for c in st.claims for e in c.event_ids} == {f"{INDEX}/benign-s"}
    for c in st.claims:
        c.status = "self_checked"
    notes = {"data_sources": {"auth": 35}, "coverage": {"auth": {"n_buckets": 1, "empty_buckets": [], "coverage_ratio": 1.0, "total": 35}},
             "gaps": [], "missing_fields": {}, "entity_missing": []}
    assert verdict.decide(p, st, notes)["verdict"] == "INCONCLUSIVE"


def test_without_named_hosts_every_placeholder_is_still_grouped_on(fake_llm):
    p, st, out, _ = hunt(fake_llm, [UNSCOPED_LOGINS], host=None)
    assert sorted(c.facts["source.ip"] for c in st.claims) == ["198.51.100.20", "203.0.113.99"]
    assert all(set(c.facts) == {"source.ip", "user.name"} for c in st.claims)   # the text's user is a fact of every cited event
