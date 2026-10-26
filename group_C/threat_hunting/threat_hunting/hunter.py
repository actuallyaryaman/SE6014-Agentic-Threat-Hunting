"""Hunter + Analyst: execute plan steps via MCP, record evidence, derive claims, pivot (bounded).
Ported from the prototype's src/hunt/hunter.py. The lateral-movement pivot uses Sysmon EID 3 (the team's firewall log has no
ports); the T1078 follow-up (successful login after a brute force) is new."""
from __future__ import annotations
import re
from datetime import datetime, timedelta
from collections import defaultdict
from .models import Claim, Evidence, HuntPlan, PlanStep
from .playbooks import BASE, EID, IDX, INTERNAL_DST, ds

MAX_PIVOT_HOSTS = 5
PIVOT_WINDOW_H = 2


class HuntState:
    def __init__(self, plan: HuntPlan, max_calls: int = 80, complete_results: bool = True):
        self.plan, self.max_calls, self.complete_results = plan, max_calls, complete_results
        self.step_results: dict[str, dict] = {}
        self.raw: dict[str, dict] = {}            # full tool result per step (the self-check reads it)
        self.call_steps: dict[str, str] = {}      # call_id -> step_id, for every call a step made (incl. re-queries)
        self.evidence: list[Evidence] = []
        self.claims: list[Claim] = []
        self.dynamic_steps: list[PlanStep] = []
        self.notes: list[str] = []
        self.calls = 0

    def next_claim_id(self) -> str:
        return f"C-{len(self.claims) + 1:03d}"


def fill(template: str, ctx: dict) -> str:
    return re.sub(r"\{([\w.@]+)\}", lambda m: str(ctx.get(m.group(1), "?")), template)


def _val(v):
    return str(int(v)) if isinstance(v, float) and v == int(v) else str(v)


async def run_step(mcp, st: HuntState, step: PlanStep, dynamic=False) -> dict | None:
    if st.calls >= st.max_calls:
        st.notes.append(f"budget exhausted before step {step.step_id}")
        st.step_results[step.step_id] = {"status": "skipped_budget"}
        if dynamic:                                 # so the verdict sees the skipped step as incomplete coverage
            st.dynamic_steps.append(step)
        return None
    st.calls += 1
    res = await mcp.call(step.tool, **step.params)
    st.call_steps[res.get("call_id")] = step.step_id
    # completeness control: a truncated sample is never accepted silently; re-ask for every hit (within the tool cap)
    if st.complete_results and step.tool == "search" and not step.analysis.get("sample_ok") and "hits" in res \
            and res["total"] > len(res["hits"]) and res["total"] <= 200:
        st.notes.append(f"step {step.step_id}: result was truncated ({len(res['hits'])}/{res['total']}); re-queried with size={res['total']}")
        step.params["size"] = res["total"]
        st.calls += 1
        res = await mcp.call(step.tool, **step.params)
        st.call_steps[res.get("call_id")] = step.step_id
    if dynamic:
        st.dynamic_steps.append(step)
    info = {"call_id": res.get("call_id"), "status": "error" if "error" in res else "ok", "total": res.get("total", 0), "tool": step.tool}
    if "error" in res:
        info["error"] = res["error"]
        st.step_results[step.step_id] = info
        return None
    st.raw[step.step_id] = res
    ev = Evidence(evidence_id=f"E-{step.step_id}", call_id=res["call_id"], step_id=step.step_id, index=step.params.get("index", ""),
                  total_hits=res.get("total", 0))
    if step.tool == "search":
        ev.event_ids = [f'{h["index"]}/{h["event_id"]}' for h in res["hits"]]
        ev.excerpt = [h["fields"] for h in res["hits"][:3]]
        info["complete"] = res["total"] <= len(res["hits"])
        if not info["complete"] and not step.analysis.get("sample_ok"):
            st.notes.append(f"step {step.step_id}: {res['total']} hits but only {len(res['hits'])} returned (size cap); claims cover the returned sample")
    else:
        ev.excerpt = [res.get("result")] if not isinstance(res.get("result"), list) else res["result"][:5]
    st.evidence.append(ev)
    st.step_results[step.step_id] = info
    return res


def _context_only(st: HuntState, technique: str) -> bool:
    return technique not in st.plan.required_techniques


def extract_claims(st: HuntState, step: PlanStep, res: dict):
    a = step.analysis
    ctx_only = _context_only(st, step.technique)
    if step.tool == "search" and step.claim_template and res.get("hits"):
        gb = a.get("group_by", [])
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for h in res["hits"]:
            groups[tuple(_val(h["fields"].get(f, "")) for f in gb)].append(h)
        for key in sorted(groups):
            hits = groups[key]
            if len(hits) < a.get("min_count", 1):
                continue
            ctx = {**hits[0]["fields"], "n": len(hits)}
            facts = {f: _val(hits[0]["fields"].get(f, "")) for f in gb}     # only fields of the cited events
            st.claims.append(Claim(
                claim_id=st.next_claim_id(), text=fill(step.claim_template, ctx), technique=step.technique, evidence_ids=[f"E-{step.step_id}"],
                facts=facts, step_id=step.step_id, kind="events", context_only=ctx_only,
                event_ids=[f'{h["index"]}/{h["event_id"]}' for h in hits], first_seen=min(h["fields"].get("@timestamp", "") for h in hits)))
    elif step.tool == "aggregate" and step.claim_template and isinstance(res.get("result"), list):
        thresholds = ("bucket_min_count", "bucket_min_sum", "bucket_min_distinct")
        for b in res["result"]:
            ok = b["count"] >= a.get("bucket_min_count", 0) and b.get("sum", 0) >= a.get("bucket_min_sum", 0) \
                 and b.get("distinct", 0) >= a.get("bucket_min_distinct", 0) and any(t in a for t in thresholds)
            if not ok:
                continue
            ctx = {"bucket_key": b["key"], "count": b["count"], "sum": _val(b.get("sum", "")), "distinct": b.get("distinct", "")}
            facts = {"bucket_key": str(b["key"]), "count": str(b["count"])}
            for k in ("sum", "distinct"):
                if k in b:
                    facts[k] = _val(b[k])
            st.claims.append(Claim(claim_id=st.next_claim_id(), text=fill(step.claim_template, ctx), technique=step.technique,
                                   evidence_ids=[f"E-{step.step_id}"], facts=facts, step_id=step.step_id, kind="aggregate", context_only=ctx_only,
                                   replay={"tool": "aggregate", "params": step.params, "bucket_key": str(b["key"]), "count": b["count"],
                                           "sum": b.get("sum"), "distinct": b.get("distinct")}))


async def enrich_iocs(mcp, st: HuntState, step: PlanStep):
    if not step.analysis.get("ioc_enrich"):
        return
    for c in [c for c in st.claims if c.step_id == step.step_id and c.kind == "aggregate"]:
        key = c.facts["bucket_key"]
        r = await mcp.call("check_ioc", value=key)
        st.calls += 1
        st.call_steps[r.get("call_id")] = step.step_id + "-ioc"
        if r.get("total"):
            ev = Evidence(evidence_id=f"E-{step.step_id}-ioc-{key}", call_id=r["call_id"], step_id=step.step_id + "-ioc", total_hits=r["total"],
                          excerpt=r["matches"])
            st.evidence.append(ev)
            st.claims.append(Claim(claim_id=st.next_claim_id(), text=f"Destination {key} matches a threat-intel entry ({r['matches'][0]['note']})",
                                   technique=step.technique, evidence_ids=[ev.evidence_id], facts={"ioc": key}, step_id=step.step_id + "-ioc",
                                   kind="ioc", context_only=c.context_only, replay={"tool": "check_ioc", "value": key}))


async def drilldown(mcp, st: HuntState, step: PlanStep):
    """Aggregate claims get concrete event ids: search the events behind each qualifying bucket."""
    dd = step.analysis.get("drilldown")
    if not dd:
        return
    for c in [c for c in st.claims if c.step_id == step.step_id and c.kind == "aggregate"]:
        key = c.facts["bucket_key"]
        sid = f"{step.step_id}-dd-{key}"
        sub = PlanStep(step_id=sid, technique=step.technique, tool="search", role="context", purpose=f"Events behind aggregate bucket {key}",
                       params={**{k: v for k, v in step.params.items() if k in ("index", "time_from", "time_to", "filters", "must_not")},
                               "size": 100, "fields": ["@timestamp", dd],
                               "filters": step.params.get("filters", []) + [{"field": dd, "op": "eq", "value": key}]})
        r = await run_step(mcp, st, sub, dynamic=True)
        if r and r.get("hits"):
            c.event_ids = [f'{h["index"]}/{h["event_id"]}' for h in r["hits"]]
            c.first_seen = min(h["fields"]["@timestamp"] for h in r["hits"])
            c.evidence_ids.append(f"E-{sid}")
            c.replay["event_field"] = dd


async def network_pivot(mcp, st: HuntState):
    """Lateral-movement pivot (T1021.002-b): from seed hosts, Sysmon EID 3 connections on lateral ports to internal
    destinations that host never used in the baseline period before the seed time."""
    plan = st.plan
    tf, tt = plan.time_range["from"], plan.time_range["to"]
    ports = BASE["lateral_ports"]
    missing = set(plan.entities.get("entity_missing", []))
    hosts = [h for h in plan.entities.get("hosts", []) if h not in missing]
    for c in st.claims:
        if c.technique in ("T1003.001", "T1059.001") and "host.name" in c.facts and c.facts["host.name"] not in hosts:
            hosts.append(c.facts["host.name"])
    lateral = [ds("sysmon"), EID(3), {"field": "destination.port", "op": "in", "value": ports}]
    seeds: list[dict] = []
    for h in sorted(set(hosts))[:MAX_PIVOT_HOSTS]:
        times = [c.first_seen for c in st.claims if c.facts.get("host.name") == h and c.technique in ("T1003.001", "T1059.001") and c.first_seen]
        seeds.append({"host": h, "t_start": min(times) if times else tf})
    if not seeds and not plan.entities.get("hosts"):
        step = PlanStep(step_id="T1021.002-fanout", technique="T1021.002", tool="aggregate", role="context",
                        purpose="No seed host: rank hosts by lateral-port connections to internal destinations",
                        params={"index": IDX, "time_from": tf, "time_to": tt, "agg": "terms", "field": "host.name", "size": 5,
                                "filters": lateral, "any_of": INTERNAL_DST})
        r = await run_step(mcp, st, step, dynamic=True)
        for b in (r or {}).get("result", []):
            seeds.append({"host": b["key"], "t_start": tf})
    for s in seeds:
        t_start, h = s["t_start"], s["host"]
        t_end = min(datetime.fromisoformat(t_start.replace("Z", "+00:00")) + timedelta(hours=PIVOT_WINDOW_H),
                    datetime.fromisoformat(tt.replace("Z", "+00:00")))
        t_end_s = t_end.strftime("%Y-%m-%dT%H:%M:%SZ")
        common = lateral + [{"field": "host.name", "op": "eq", "value": h}]
        base_step = PlanStep(step_id=f"T1021.002-base-{h}", technique="T1021.002", tool="aggregate", role="benign_check",
                             purpose=f"Baseline: internal destinations {h} already reached on lateral ports before {t_start}",
                             params={"index": IDX, "time_from": tf, "time_to": t_start, "agg": "terms", "field": "destination.ip", "size": 50,
                                     "filters": common, "any_of": INTERNAL_DST})
        known: set[str] = set()
        if t_start > tf:
            rb = await run_step(mcp, st, base_step, dynamic=True)
            known = {b["key"] for b in (rb or {}).get("result", [])}
        else:
            st.notes.append(f"no baseline period before the seed time for {h}; every destination counts as new")
        win_step = PlanStep(step_id=f"T1021.002-b-{h}", technique="T1021.002", tool="search", role="indicator", must_have=True,
                            purpose=f"Lateral-port connections from {h} to internal hosts between {t_start} and {t_end_s}",
                            params={"index": IDX, "time_from": t_start, "time_to": t_end_s, "size": 100, "filters": common, "any_of": INTERNAL_DST,
                                    "fields": ["@timestamp", "host.name", "process.name", "destination.ip", "destination.port"]})
        rw = await run_step(mcp, st, win_step, dynamic=True)
        if not rw:
            continue
        by_dst: dict[str, list[dict]] = defaultdict(list)
        for hit in rw["hits"]:
            by_dst[hit["fields"]["destination.ip"]].append(hit)
        for dst in sorted(by_dst):
            if dst in known:
                st.notes.append(f"{h} -> {dst} on lateral ports is part of the baseline; not reported as new")
                continue
            hits = by_dst[dst]
            plist = sorted({int(x["fields"]["destination.port"]) for x in hits})
            st.claims.append(Claim(
                claim_id=st.next_claim_id(), technique="T1021.002", step_id=win_step.step_id, kind="events",
                text=f"{h} connected to {dst} on lateral-movement ports {','.join(map(str, plist))} "
                     f"for the first time after {t_start} ({len(hits)} connections, not in baseline)",
                evidence_ids=[f"E-{win_step.step_id}"],
                facts={"host.name": h, "destination.ip": dst, "destination.port": [str(p) for p in plist], "n_connections": str(len(hits))},
                event_ids=[f'{x["index"]}/{x["event_id"]}' for x in hits], first_seen=min(x["fields"]["@timestamp"] for x in hits),
                context_only=_context_only(st, "T1021.002")))


async def bruteforce_success(mcp, st: HuntState):
    """T1078 after T1110: a successful SSH login from a source that first produced a burst of failed logins."""
    plan = st.plan
    tf, tt = plan.time_range["from"], plan.time_range["to"]
    thr = BASE["bruteforce_min_failures"]
    host = [{"field": "host.name", "op": "in", "value": plan.entities["hosts"]}] if plan.entities.get("hosts") else []
    cands: list[str] = []
    for sid in ("T1110-a", "T1078-a"):
        res = st.raw.get(sid) or {}
        for b in res.get("result", []) if isinstance(res.get("result"), list) else []:
            if b["count"] >= thr and b["key"] not in cands:
                cands.append(b["key"])
    for ip in sorted(cands)[:MAX_PIVOT_HOSTS]:
        base = [ds("auth"), {"field": "event.action", "op": "eq", "value": "ssh_login"}, {"field": "source.ip", "op": "eq", "value": ip}] + host
        first = PlanStep(step_id=f"T1078-first-{ip}", technique="T1078", tool="search", role="context", purpose=f"First failed SSH login from {ip}",
                         analysis={"sample_ok": True},
                         params={"index": IDX, "time_from": tf, "time_to": tt, "size": 1, "fields": ["@timestamp"],
                                 "filters": base + [{"field": "event.outcome", "op": "eq", "value": "failure"}]})
        r = await run_step(mcp, st, first, dynamic=True)
        if not r or not r.get("hits"):
            continue
        t_first = r["hits"][0]["fields"]["@timestamp"]
        succ = PlanStep(step_id=f"T1078-b-{ip}", technique="T1078", tool="search", role="indicator", must_have=True,
                        purpose=f"Successful SSH logins from {ip} after its first failed login ({t_first})",
                        params={"index": IDX, "time_from": t_first, "time_to": tt, "size": 100,
                                "fields": ["@timestamp", "source.ip", "user.name", "host.name"],
                                "filters": base + [{"field": "event.outcome", "op": "eq", "value": "success"}]},
                        # the failure count lives in the T1110 claim, which cites the aggregate; this claim cites only the
                        # success events, and "after" is guaranteed by the query window starting at the first failure
                        claim_template="Source {source.ip} logged in successfully as {user.name} on {host.name} after its failed SSH logins began",
                        analysis={"group_by": ["source.ip", "user.name", "host.name"]})
        rs = await run_step(mcp, st, succ, dynamic=True)
        if rs:
            extract_claims(st, succ, rs)


async def execute(mcp, plan: HuntPlan, max_calls: int = 120, complete_results: bool = True) -> HuntState:
    st = HuntState(plan, max_calls, complete_results)
    for step in plan.steps:
        res = await run_step(mcp, st, step)
        if res is not None:
            extract_claims(st, step, res)
            await drilldown(mcp, st, step)
            await enrich_iocs(mcp, st, step)
    if "T1021.002" in plan.techniques:
        await network_pivot(mcp, st)
    if "T1078" in plan.techniques:
        await bruteforce_success(mcp, st)
    return st
