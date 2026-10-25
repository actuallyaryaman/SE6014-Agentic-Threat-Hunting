"""Planner agent: hypothesis text -> structured HuntPlan. Rules always work; an LLM may pick techniques from the catalogue.
Ported from the prototype's src/hunt/planner.py; sources are grouped by event.dataset and coverage goes through analytics.gap_check."""
from __future__ import annotations
import json, re
from datetime import datetime, timedelta, timezone
from . import config, playbooks
from .llm import get_llm
from .models import HuntPlan

HOST_RX = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b")
IP_RX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
DATE_RX = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
SIZE_RX = re.compile(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB)\b", re.I)
CONTEXT = ["T1059.001", "T1071", "T1190"]
CHAIN = {"T1003.001", "T1021.002", "T1059.001"}
ORDER = ["T1003.001", "T1059.001", "T1190", "T1071", "T1021.002", "T1048", "T1110", "T1078", "T1046"]
MIN_SUPPORT = {"T1003.001": 2, "T1021.002": 2}
GAP_THRESHOLD = 0.05     # DESIGN.md 5.4: full coverage needs >= 95% non-empty hourly buckets


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def select_techniques(hypothesis: str, kb: dict) -> tuple[list[str], str, list[str]]:
    h = hypothesis.lower()
    rules = [tid for tid, v in kb.items() if tid in playbooks.SOURCES and any(k in h for k in v["keywords"])]
    llm = get_llm("planner")
    if llm:
        try:
            cat = {tid: {"name": v["name"], "summary": v["summary"]} for tid, v in kb.items() if tid in playbooks.SOURCES}
            r = llm.complete_json("You are a threat-hunt planner. Choose which techniques from the catalogue must be tested to "
                                  "confirm or refute the hypothesis. Return {\"techniques\": [ids]} using only ids from the catalogue.",
                                  json.dumps({"hypothesis": hypothesis, "catalogue": cat}))
            sel = [t for t in r.get("techniques", []) if t in cat]
            if sel:
                # Guardrail found in live testing: an over-eager LLM added T1071 as *required* to an exfiltration hypothesis,
                # which turned a clean Refuted into Inconclusive. Techniques the hypothesis text itself names stay required;
                # the LLM may widen coverage only as context, and only decides on its own when the text matches nothing.
                if rules:
                    return [t for t in ORDER if t in rules], "llm", [t for t in sel if t not in rules]
                return sel, "llm", []
        except Exception:
            pass
    return rules, "rules", []


async def missing_fields(mcp, log_type: str, fields: list[str], tf: str, tt: str, cache: dict) -> list[str]:
    """A field counts as present when at least one event of this dataset in the window has it."""
    for f in fields:
        if (log_type, f) not in cache:
            r = await mcp.call("count", index=config.HUNT_INDEX, time_from=tf, time_to=tt,
                               filters=[playbooks.ds(log_type), {"field": f, "op": "exists"}])
            cache[(log_type, f)] = "error" not in r and r.get("total", 0) > 0
    return [f for f in fields if not cache[(log_type, f)]]


async def plan_hunt(mcp, hypothesis: str) -> tuple[HuntPlan, dict]:
    notes: dict = {"gaps": [], "entity_missing": [], "missing_fields": {}}
    dd = await mcp.call("describe_data", index_pattern=config.HUNT_INDEX)
    sources = [s for s in dd.get("sources", []) if playbooks.log_type_of(s["dataset"])]
    if not sources:
        raise RuntimeError(f"no known datasets in {config.HUNT_INDEX}: {dd.get('error') or [s['dataset'] for s in dd.get('sources', [])]}")
    notes["index_fields"] = sorted(f.rsplit(":", 1)[0] for f in dd.get("fields", []))
    by_type: dict[str, list[dict]] = {}
    for s in sources:
        by_type.setdefault(playbooks.log_type_of(s["dataset"]), []).append(s)
    first = min(s["first_event"] for s in sources); last = max(s["last_event"] for s in sources)
    t0 = datetime.fromisoformat(first.replace("Z", "+00:00")).replace(minute=0, second=0, microsecond=0)
    t1 = datetime.fromisoformat(last.replace("Z", "+00:00")).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    m = DATE_RX.search(hypothesis)
    if m:
        day = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        lo, hi = max(t0, day), min(t1, day + timedelta(days=1))
        # a requested day with no data stays as requested so that the coverage check exposes the gap
        t0, t1 = (lo, hi) if lo < hi else (day, day + timedelta(days=1))
    tf, tt = iso(t0), iso(t1)

    kb = json.loads((config.KNOWLEDGE_DIR / "attack_subset.json").read_text())
    required, by, llm_extra = select_techniques(hypothesis, kb)
    required = [t for t in ORDER if t in required]
    context = [t for t in CONTEXT if t not in required] if set(required) & CHAIN else []
    context += [t for t in ORDER if t in llm_extra and t not in required and t not in context]
    notes["llm_extra_context"] = llm_extra
    meta = {}
    for tid in required + context:
        r = await mcp.call("lookup_attack", query=tid)
        meta[tid] = r.get("techniques", {}).get(tid, {}).get("name", tid)

    hosts = sorted(set(HOST_RX.findall(hypothesis)))
    ips = sorted(set(IP_RX.findall(hypothesis)))
    for h in hosts:
        c = await mcp.call("count", index=config.HUNT_INDEX, time_from=tf, time_to=tt, filters=[{"field": "host.name", "op": "eq", "value": h}])
        if c.get("total", 0) == 0:
            notes["entity_missing"].append(h)
    sm = SIZE_RX.search(hypothesis)
    scope: dict = {"hosts": hosts}
    if sm:
        scope["exfil_bytes"] = int(float(sm.group(1)) * {"kb": 1024, "mb": 1024**2, "gb": 1024**3}[sm.group(2).lower()])

    need = sorted({s for t in required + context for s in playbooks.SOURCES[t]})
    for s in need:
        if s not in by_type:
            notes["gaps"].append(f"required log type '{s}' is not ingested")
    notes["coverage"] = {}
    for s in [s for s in need if s in by_type]:
        h = await mcp.call("aggregate", index=config.HUNT_INDEX, time_from=tf, time_to=tt, agg="date_histogram", interval="60m",
                           filters=[playbooks.ds(s)])
        g = await mcp.call("gap_check", buckets=h.get("result", []))
        notes["coverage"][s] = {"total": h.get("total", 0), "n_buckets": g.get("n_buckets", 0),
                                "empty_buckets": g.get("empty_buckets", []), "coverage_ratio": g.get("coverage_ratio", 0.0)}
        if g.get("n_buckets") and 1 - g["coverage_ratio"] > GAP_THRESHOLD:
            notes["gaps"].append(f"{s}: {len(g['empty_buckets'])}/{g['n_buckets']} hourly buckets have no events")
    present: dict = {}
    for t in required + context:
        for s, fields in playbooks.REQUIRED_FIELDS.get(t, {}).items():
            if s in by_type and notes["coverage"].get(s, {}).get("total"):      # an empty window is reported as such, not as missing fields
                miss = await missing_fields(mcp, s, fields, tf, tt, present)
                if miss:
                    notes["missing_fields"][f"{t}/{s}"] = miss

    steps = []
    for tid in required + context:
        steps += playbooks.steps_for(tid, tf, tt, dict(scope))
    plan = HuntPlan(
        hypothesis=hypothesis, techniques=required + context, required_techniques=required, context_techniques=context,
        entities={"hosts": hosts, "ips": ips, "technique_names": meta, **({"exfil_bytes": scope["exfil_bytes"]} if "exfil_bytes" in scope else {})},
        required_sources=need, time_range={"from": tf, "to": tt}, window_minutes=60, steps=steps,
        success_criteria=[f"{t} ({meta[t]}): at least {MIN_SUPPORT.get(t, 1)} independent self-checked indicator(s)" for t in required],
        refutation_criteria=[f"{t}: all required sources and fields covered for the full window AND zero indicators" for t in required],
        planner=by)
    notes["data_sources"] = {k: sum(x["docs"] for x in v) for k, v in by_type.items()}
    return plan, notes
