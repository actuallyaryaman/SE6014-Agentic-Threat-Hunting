"""Simulated C2 playbook hunter: produces C3 hunt bundles from the synthetic sample.

    python -m tests.group_C.c3.fixture_builder     # rewrites tests/group_C/c3/fixtures/*.json

Scenarios:
  confirmed       LSASS dump on WS-01, then lateral movement to FS-01 (3 indicators each)
  missing_host    same hypothesis for HR-LAPTOP-99, which has no telemetry
  data_gap        a day without any data (coverage gap)
  refuted         exfiltration over HTTPS: every source covered, nothing found
Bad claims are planted in "confirmed" so the verifier has something to catch.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from group_C.threat_hunting.evidence.contracts import Claim, Evidence, HuntBundle, HuntNotes, HuntPlan, PlanStep

from .fake_tools import FakeHuntTools
from .mini_es import MiniES

FIXTURE_DIR = Path(__file__).with_name("fixtures")
SYSMON, WINSEC, FW = "logs-sysmon-sysmon-endpoints", "logs-windows-security-dc", "logs-firewall-fw-edge"
WEB, AUTH = "logs-web-web-prod", "logs-auth-linux-ssh"
NAMES = {"T1003.001": "OS Credential Dumping: LSASS Memory", "T1021.002": "Remote Services: SMB/Windows Admin Shares",
         "T1078": "Valid Accounts", "T1048": "Exfiltration Over Alternative Protocol"}
LSASS_ALLOW = [r"C:\Program Files\Windows Defender\MsMpEng.exe", r"C:\Windows\System32\svchost.exe"]


class Hunter:
    """Minimal stand-in for the C2 hunter: runs plan steps through the tools and writes claims from templates."""

    def __init__(self, run_id: str, es: Optional[MiniES] = None) -> None:
        self.es = es or MiniES()
        self.tools = FakeHuntTools(self.es, run_id=run_id)
        self.run_id = run_id
        self.evidence: list[Evidence] = []
        self.claims: list[Claim] = []
        self.step_results: dict[str, dict] = {}

    def _claim_id(self) -> str:
        return f"C-{len(self.claims) + 1:03d}"


    def run_step(self, step: PlanStep, text: str = "", facts_fields: tuple[str, ...] = (), context_only: bool = False) -> dict:
        res = getattr(self.tools, step.tool)(**step.params)
        self.step_results[step.step_id] = {"status": "ok" if "error" not in res else "error", "total": res.get("total")}
        ev = Evidence(evidence_id=f"E-{step.step_id}", call_id=res["call_id"], step_id=step.step_id,
                      index=step.params.get("index", ""), total_hits=res.get("total") or 0,
                      event_ids=[f'{h["index"]}/{h["event_id"]}' for h in res.get("hits", [])],
                      excerpt=res.get("result", [])[:10] if isinstance(res.get("result"), list) else [])
        self.evidence.append(ev)
        hits = res.get("hits", [])
        if step.tool == "search" and hits and text:
            first = hits[0]["fields"]
            facts = {f: str(first.get(f)) for f in facts_fields}
            refs = [f'{h["index"]}/{h["event_id"]}' for h in hits]
            self.claims.append(Claim(claim_id=self._claim_id(), text=text.format(**{k.replace(".", "_"): v for k, v in first.items()}),
                                     technique=step.technique, evidence_ids=[ev.evidence_id], facts=facts, step_id=step.step_id,
                                     kind="events", event_ids=refs, first_seen=min(h["fields"]["@timestamp"] for h in hits),
                                     context_only=context_only))
        return res


def _window(day: str) -> dict:
    return {"from": f"{day}T08:00:00Z", "to": f"{day}T18:00:00Z"}


def _plan(hypothesis: str, host: str, tr: dict) -> HuntPlan:
    f, t = tr["from"], tr["to"]
    steps = [
        PlanStep(step_id="T1003.001-a", technique="T1003.001", tool="aggregate", role="benign_check",
                 purpose="who opens lsass.exe (baseline check)",
                 params=dict(index=SYSMON, time_from=f, time_to=t, agg="terms", field="process.executable",
                             filters=[{"field": "event.code", "op": "eq", "value": 10},
                                      {"field": "winlog.event_data.TargetImage", "op": "wildcard", "value": "*lsass.exe"}])),
        PlanStep(step_id="T1003.001-b", technique="T1003.001", tool="search", need="Sysmon event 10 (process access)",
                 purpose="non-baseline process opens lsass.exe",
                 params=dict(index=SYSMON, time_from=f, time_to=t,
                             filters=[{"field": "event.code", "op": "eq", "value": 10}, {"field": "host.name", "op": "eq", "value": host},
                                      {"field": "winlog.event_data.TargetImage", "op": "wildcard", "value": "*lsass.exe"}],
                             must_not=[{"field": "process.executable", "op": "in", "value": LSASS_ALLOW}])),
        PlanStep(step_id="T1003.001-c", technique="T1003.001", tool="search", need="Sysmon event 1 (process creation)",
                 purpose="command line of a known LSASS-dump technique",
                 params=dict(index=SYSMON, time_from=f, time_to=t,
                             filters=[{"field": "host.name", "op": "eq", "value": host},
                                      {"field": "process.command_line", "op": "wildcard", "value": "*comsvcs.dll*MiniDump*"}])),
        PlanStep(step_id="T1003.001-d", technique="T1003.001", tool="search", need="Sysmon event 11 (file create)",
                 purpose="memory dump file written",
                 params=dict(index=SYSMON, time_from=f, time_to=t,
                             filters=[{"field": "event.code", "op": "eq", "value": 11}, {"field": "host.name", "op": "eq", "value": host},
                                      {"field": "file.path", "op": "wildcard", "value": "*lsass.dmp"}])),
        PlanStep(step_id="T1021.002-a", technique="T1021.002", tool="search", need="Sysmon event 1 on servers",
                 purpose="remote service binary started by services.exe",
                 params=dict(index=SYSMON, time_from=f, time_to=t,
                             filters=[{"field": "process.name", "op": "eq", "value": "PSEXESVC.exe"},
                                      {"field": "process.parent.name", "op": "eq", "value": "services.exe"}])),
        PlanStep(step_id="T1021.002-b", technique="T1021.002", tool="aggregate", need="firewall connection logs",
                 purpose="new connections from the host on lateral-movement ports", analysis={"bucket_min_count": 3},
                 params=dict(index=FW, time_from=f, time_to=t, agg="terms", field="destination.ip",
                             filters=[{"field": "source.ip", "op": "eq", "value": "10.0.1.15"},
                                      {"field": "destination.port", "op": "in", "value": [135, 445, 5985]}],
                             must_not=[{"field": "destination.ip", "op": "eq", "value": "10.0.2.20"}])),
        PlanStep(step_id="T1021.002-c", technique="T1021.002", tool="search", need="Windows Security 5145",
                 purpose="admin share accessed from the host",
                 params=dict(index=WINSEC, time_from=f, time_to=t,
                             filters=[{"field": "event.code", "op": "eq", "value": 5145},
                                      {"field": "winlog.event_data.ShareName", "op": "wildcard", "value": "*ADMIN$"},
                                      {"field": "source.ip", "op": "eq", "value": "10.0.1.15"}])),
        PlanStep(step_id="T1078-a", technique="T1078", tool="search",
                 purpose="network logons from the host",
                 params=dict(index=WINSEC, time_from=f, time_to=t,
                             filters=[{"field": "event.code", "op": "eq", "value": 4624}, {"field": "source.ip", "op": "eq", "value": "10.0.1.15"}])),
    ]
    return HuntPlan(
        hypothesis=hypothesis, techniques=["T1003.001", "T1021.002", "T1078"],
        required_techniques=["T1003.001", "T1021.002"], context_techniques=["T1078"],
        entities={"hosts": [host], "technique_names": NAMES,
                  "requirement_groups": [{"label": "T1003.001", "kind": "technique", "techniques": ["T1003.001"]},
                                         {"label": "T1021.002", "kind": "technique", "techniques": ["T1021.002"]}]},
        required_sources=[SYSMON, FW, WINSEC], time_range=tr, steps=steps,
        success_criteria=["T1003.001 (OS Credential Dumping: LSASS Memory): at least 2 independent verified indicator(s)",
                          "T1021.002 (Remote Services: SMB/Windows Admin Shares): at least 2 independent verified indicator(s)"],
        refutation_criteria=["T1003.001: all required sources covered for the full window AND zero verified indicators",
                             "T1021.002: all required sources covered for the full window AND zero verified indicators"],
        planner="rules")


def _coverage(h: Hunter, indices: list[str], tr: dict) -> tuple[dict, dict, list]:
    r = h.tools.coverage_check(indices=indices, time_from=tr["from"], time_to=tr["to"], bucket_minutes=60)
    cov = {idx: {**c, "bucket_minutes": 60} for idx, c in r["coverage"].items()}
    gaps, gap_list = {}, []
    for idx, c in cov.items():
        n, empty = len(c["buckets"]), len(c["empty_buckets"])
        if n and empty == n:               # synthetic data is sparse: only a source with no events at all is a gap
            gaps[idx] = f"{empty}/{n} hourly buckets have no events"
            gap_list.append(f"{idx}: {gaps[idx]}")
    return cov, gaps, gap_list


def _bundle(h: Hunter, plan: HuntPlan, notes: HuntNotes) -> HuntBundle:
    return HuntBundle(run_id=h.run_id, plan=plan, evidence=h.evidence, claims=h.claims, audit=h.tools.audit,
                      step_results=h.step_results, notes=notes,
                      baselines=[f"LSASS access allowlist: {LSASS_ALLOW}", "10.0.1.15 -> 10.0.2.20 on 445 is daily file-share traffic"],
                      meta={"run_id": h.run_id, "planner": "rules", "backend": "rules (simulated hunter)",
                            "controls": {"canonical_order": True, "coverage_enforcement": True}, "fixture": "c3-sample"})


def _run_lsass_hunt(run_id: str, host: str, day: str) -> tuple[Hunter, HuntPlan]:
    h = Hunter(run_id)
    tr = _window(day)
    plan = _plan(f"An attacker on {host} dumped credentials from LSASS and then moved laterally to other hosts on {day}.", host, tr)
    s = {x.step_id: x for x in plan.steps}
    h.run_step(s["T1003.001-a"])
    h.run_step(s["T1003.001-b"], "A non-baseline process ({process_executable}) opened lsass.exe on {host_name} with access mask "
                                 "{winlog_event_data_GrantedAccess}",
               ("host.name", "process.executable", "winlog.event_data.GrantedAccess"))
    h.run_step(s["T1003.001-c"], "A process command line on {host_name} matches LSASS-dump tooling: {process_command_line}",
               ("host.name", "process.command_line"))
    h.run_step(s["T1003.001-d"], "A memory dump file {file_path} was created on {host_name} by {process_executable}",
               ("host.name", "file.path"))
    h.run_step(s["T1021.002-a"], "Remote-service binary {process_name} ran on {host_name} (parent {process_parent_name})",
               ("host.name", "process.name", "process.parent.name"))
    agg = h.run_step(s["T1021.002-b"])
    for b in agg.get("result", []):
        if b["count"] >= 3:
            drill = h.tools.search(index=FW, time_from=tr["from"], time_to=tr["to"],
                                   filters=[{"field": "source.ip", "op": "eq", "value": "10.0.1.15"},
                                            {"field": "destination.ip", "op": "eq", "value": b["key"]}])
            refs = [f'{x["index"]}/{x["event_id"]}' for x in drill["hits"]]
            h.claims.append(Claim(claim_id=h._claim_id(), technique="T1021.002", step_id="T1021.002-b", kind="aggregate",
                                  text=f"10.0.1.15 connected to {b['key']} on lateral-movement ports {b['count']} times "
                                       "(not in baseline)",
                                  evidence_ids=["E-T1021.002-b"], facts={"source.ip": "10.0.1.15", "destination.ip": b["key"]},
                                  event_ids=refs, first_seen=drill["hits"][0]["fields"]["@timestamp"] if drill["hits"] else "",
                                  replay={"tool": "aggregate", "params": s["T1021.002-b"].params, "bucket_key": str(b["key"]),
                                          "count": b["count"], "sum": b.get("sum"), "distinct": b.get("distinct"),
                                          "event_field": "destination.ip"}))
    h.run_step(s["T1021.002-c"], "Admin share {winlog_event_data_ShareName} on {host_name} was accessed from {source_ip} "
                                 "by {user_name} (file {winlog_event_data_RelativeTargetName})",
               ("host.name", "source.ip", "user.name"))
    h.run_step(s["T1078-a"], "Network logon (type {winlog_event_data_LogonType}) as {user_name} on {host_name} from {source_ip}",
               ("user.name", "source.ip"), context_only=True)
    return h, plan


def build_confirmed() -> HuntBundle:
    h, plan = _run_lsass_hunt("hunt-lsass-001", "WS-01", "2026-10-15")
    cov, gaps, gap_list = _coverage(h, plan.required_sources, plan.time_range)
    real = next(c for c in h.claims if c.step_id == "T1003.001-b")
    # --- planted bad claims -------------------------------------------------
    h.claims.append(Claim(claim_id=h._claim_id(), technique="T1003.001", step_id="LLM-1", kind="events", origin="llm",
                          text="mimikatz.exe also read LSASS memory on WS-01", evidence_ids=["E-LLM-1"],
                          event_ids=["logs-sysmon-sysmon-endpoints/sm-9999"]))
    h.claims.append(Claim(claim_id=h._claim_id(), technique="T1003.001", step_id="T1003.001-b", kind="events",
                          text="A non-baseline process opened lsass.exe on WS-02", evidence_ids=real.evidence_ids,
                          event_ids=real.event_ids, facts={"host.name": "WS-02"}))
    h.claims.append(Claim(claim_id=h._claim_id(), technique="T1021.002", step_id="T1021.002-c", kind="events",
                          text="WS-01 opened 47 admin-share sessions on FS-01", evidence_ids=["E-T1021.002-c"],
                          event_ids=[c for c in h.claims if c.step_id == "T1021.002-c"][0].event_ids, facts={"host.name": "FS-01"}))
    notes = HuntNotes(coverage=cov, coverage_gaps=gaps, gaps=gap_list, dated=True,
                      data_sources={idx: c["total"] for idx, c in cov.items()},
                      min_support={"T1003.001": 2, "T1021.002": 2})
    return _bundle(h, plan, notes)


def build_missing_host() -> HuntBundle:
    h, plan = _run_lsass_hunt("hunt-missing-002", "HR-LAPTOP-99", "2026-10-15")
    cov, gaps, gap_list = _coverage(h, plan.required_sources, plan.time_range)
    notes = HuntNotes(entity_missing=["HR-LAPTOP-99"], coverage=cov, coverage_gaps=gaps, gaps=gap_list,
                      data_sources={idx: c["total"] for idx, c in cov.items()}, min_support={"T1003.001": 2, "T1021.002": 2})
    return _bundle(h, plan, notes)


def build_data_gap() -> HuntBundle:
    h, plan = _run_lsass_hunt("hunt-gap-003", "WS-01", "2026-10-16")
    cov, gaps, gap_list = _coverage(h, plan.required_sources, plan.time_range)
    notes = HuntNotes(coverage=cov, coverage_gaps=gaps, gaps=gap_list,
                      data_sources={idx: c["total"] for idx, c in cov.items()}, min_support={"T1003.001": 2, "T1021.002": 2})
    return _bundle(h, plan, notes)


def build_refuted() -> HuntBundle:
    h = Hunter("hunt-exfil-004")
    tr = _window("2026-10-15")
    step = PlanStep(step_id="T1048-a", technique="T1048", tool="aggregate", need="firewall connection logs",
                    purpose="large outbound transfers to external addresses",
                    params=dict(index=FW, time_from=tr["from"], time_to=tr["to"], agg="terms", field="destination.ip",
                                filters=[{"field": "source.ip", "op": "eq", "value": "10.0.1.15"},
                                         {"field": "destination.port", "op": "in", "value": [21, 22, 53]}]))
    plan = HuntPlan(hypothesis="WS-01 exfiltrated data over FTP, SSH or DNS on 2026-10-15.", techniques=["T1048"],
                    required_techniques=["T1048"], entities={"hosts": ["WS-01"], "technique_names": NAMES},
                    required_sources=[FW], time_range=tr, steps=[step],
                    success_criteria=["T1048: at least 1 independent verified indicator"],
                    refutation_criteria=["T1048: all required sources covered for the full window AND zero verified indicators"])
    h.run_step(step)
    cov, gaps, gap_list = _coverage(h, [FW], tr)
    notes = HuntNotes(coverage=cov, coverage_gaps=gaps, gaps=gap_list, data_sources={FW: cov[FW]["total"]})
    return _bundle(h, plan, notes)


BUILDERS = {"confirmed": build_confirmed, "missing_host": build_missing_host, "data_gap": build_data_gap, "refuted": build_refuted}


def write_fixtures() -> list[Path]:
    FIXTURE_DIR.mkdir(exist_ok=True)
    out = []
    for name, fn in BUILDERS.items():
        p = FIXTURE_DIR / f"hunt_bundle_{name}.json"
        p.write_text(fn().model_dump_json(indent=1) + "\n", encoding="utf-8")
        out.append(p)
    return out


if __name__ == "__main__":
    for p in write_fixtures():
        print(f"Wrote {p}")
