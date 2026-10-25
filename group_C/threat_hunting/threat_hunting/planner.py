"""Planner agent: hypothesis text -> structured HuntPlan. Rules always work; the intake LLM may add techniques, entities and a
time window, and code keeps only what it can check. Ported from the prototype's src/hunt/planner.py; sources are grouped by
event.dataset and coverage goes through analytics.gap_check."""
from __future__ import annotations
import json, re
from datetime import datetime, timedelta, timezone
from . import config, playbooks
from .llm import ask_json
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


INTAKE_SYSTEM = (
    "You are the intake analyst of a threat-hunting agent that hunts over stored security logs. Turn the analyst's hypothesis "
    "into a structured hunt request.\n"
    "- techniques: ids from the catalogue that must be tested to confirm or refute the hypothesis (catalogue ids only).\n"
    "- hosts, ips, users: entities the hypothesis names, copied exactly as written. Never invent or normalise them.\n"
    "- window: {\"from\": ..., \"to\": ...} in ISO 8601 UTC (e.g. 2026-10-01T10:00:00Z), only if the hypothesis states a time or a "
    "relative time; resolve relative times against `now`, the newest event in the data. Otherwise null.\n"
    "- assumptions: short notes on anything you had to interpret.\n"
    'Return {"techniques": [], "hosts": [], "ips": [], "users": [], "window": null, "assumptions": []}.')


def _parse(ts) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def intake(hypothesis: str, kb: dict, now: str, notes: dict) -> dict:
    """Hypothesis -> techniques, entities and time window. The regex and keyword rules always run; the intake LLM may add what
    they miss. Code keeps an LLM entity only if the hypothesis text contains it, and a technique only if it is in the catalogue."""
    h = hypothesis.lower()
    rules = [tid for tid, v in kb.items() if tid in playbooks.SOURCES and any(k in h for k in v["keywords"])]
    out = {"rules": rules, "required": rules, "context": [], "planner": "rules", "hosts": sorted(set(HOST_RX.findall(hypothesis))),
           "ips": sorted(set(IP_RX.findall(hypothesis))), "users": [], "window": None, "assumptions": [], "dropped": []}
    cat = {tid: {"name": v["name"], "summary": v["summary"]} for tid, v in kb.items() if tid in playbooks.SOURCES}
    r = await ask_json("intake", INTAKE_SYSTEM, json.dumps({"hypothesis": hypothesis, "now": now, "catalogue": cat}), notes["llm_notes"])
    if r is None:
        return out
    techniques = [str(t) for t in r.get("techniques") or []]
    sel = [t for t in techniques if t in cat]
    out["dropped"] += [f"technique {t!r} (not in the catalogue)" for t in techniques if t not in cat]
    if sel:
        # Guardrail found in live testing: an over-eager LLM added T1071 as *required* to an exfiltration hypothesis,
        # which turned a clean Refuted into Inconclusive. Techniques the hypothesis text itself names stay required;
        # the LLM may widen coverage only as context, and only decides on its own when the text matches nothing.
        out["planner"] = "llm"
        if rules:
            out["context"] = [t for t in sel if t not in rules]
        else:
            out["required"] = sel
    for key, rx in (("hosts", None), ("ips", IP_RX), ("users", None)):
        for v in (str(x).strip() for x in r.get(key) or []):
            if not v or v in out[key]:
                continue
            if v.lower() in h and (rx is None or rx.fullmatch(v)):
                out[key].append(v)
            else:
                out["dropped"].append(f"{key[:-1]} {v!r} (not in the hypothesis text)")
    w = r.get("window")
    if isinstance(w, dict):
        a, b = _parse(w.get("from")), _parse(w.get("to"))
        if a and b and a < b:
            out["window"] = (a, b)
        else:
            out["dropped"].append(f"window {w} (not an ISO 8601 range)")
    out["assumptions"] = [str(x)[:200] for x in r.get("assumptions") or []][:5]
    return out


def hunt_window(hypothesis: str, sources: list[dict], llm_window) -> tuple[str, str, dict]:
    """DESIGN.md 5.2: the hunt window, from the spans of the datasets the techniques need (not the whole index).
    Basis, in order: a time the LLM read from the hypothesis (inside its date, if one is written), the date written in the
    hypothesis, else the last DEFAULT_LOOKBACK_H hours before the newest needed event. Never longer than MAX_WINDOW_DAYS."""
    first = min(s["first_event"] for s in sources); last = max(s["last_event"] for s in sources)
    d0 = _parse(first).replace(minute=0, second=0, microsecond=0)
    d1 = _parse(last).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    m = DATE_RX.search(hypothesis)
    day = None
    if m:
        start = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        day = (start, start + timedelta(days=1))
    if llm_window and (day is None or (day[0] <= llm_window[0] and llm_window[1] <= day[1])):
        req, basis = llm_window, "time stated in the hypothesis (read by the intake LLM)"
    elif day:
        req, basis = day, "date written in the hypothesis"
    else:
        req = (max(d0, d1 - timedelta(hours=config.DEFAULT_LOOKBACK_H)), d1)
        basis = f"no time in the hypothesis: the {config.DEFAULT_LOOKBACK_H} h before the newest event of the needed datasets"
    if req[1] - req[0] > timedelta(days=config.MAX_WINDOW_DAYS):
        req = (req[1] - timedelta(days=config.MAX_WINDOW_DAYS), req[1])
        basis += f"; cut to the last {config.MAX_WINDOW_DAYS} days"
    lo, hi = max(d0, req[0]), min(d1, req[1])
    # a requested window with no data stays as requested so that the coverage check exposes the gap
    eff = (lo, hi) if lo < hi else req
    return iso(eff[0]), iso(eff[1]), {"requested": {"from": iso(req[0]), "to": iso(req[1])},
                                       "effective": {"from": iso(eff[0]), "to": iso(eff[1])}, "basis": basis}


async def missing_fields(mcp, log_type: str, fields: list[str], tf: str, tt: str, cache: dict) -> list[str]:
    """A field counts as present when at least one event of this dataset in the window has it."""
    for f in fields:
        if (log_type, f) not in cache:
            r = await mcp.call("count", index=config.HUNT_INDEX, time_from=tf, time_to=tt,
                               filters=[playbooks.ds(log_type), {"field": f, "op": "exists"}])
            cache[(log_type, f)] = "error" not in r and r.get("total", 0) > 0
    return [f for f in fields if not cache[(log_type, f)]]


async def plan_hunt(mcp, hypothesis: str) -> tuple[HuntPlan, dict]:
    notes: dict = {"gaps": [], "entity_missing": [], "missing_fields": {}, "llm_notes": []}
    dd = await mcp.call("describe_data", index_pattern=config.HUNT_INDEX)
    sources = [s for s in dd.get("sources", []) if playbooks.log_type_of(s["dataset"])]
    if not sources:
        raise RuntimeError(f"no known datasets in {config.HUNT_INDEX}: {dd.get('error') or [s['dataset'] for s in dd.get('sources', [])]}")
    notes["index_fields"] = sorted(f.rsplit(":", 1)[0] for f in dd.get("fields", []))
    by_type: dict[str, list[dict]] = {}
    for s in sources:
        by_type.setdefault(playbooks.log_type_of(s["dataset"]), []).append(s)

    kb = json.loads((config.KNOWLEDGE_DIR / "attack_subset.json").read_text())
    it = await intake(hypothesis, kb, max(s["last_event"] for s in sources), notes)
    required, by, llm_extra = [t for t in ORDER if t in it["required"]], it["planner"], it["context"]
    context = [t for t in CONTEXT if t not in required] if set(required) & CHAIN else []
    context += [t for t in ORDER if t in llm_extra and t not in required and t not in context]
    notes["llm_extra_context"] = llm_extra
    meta = {}
    for tid in required + context:
        r = await mcp.call("lookup_attack", query=tid)
        meta[tid] = r.get("techniques", {}).get(tid, {}).get("name", tid)

    need = sorted({s for t in required + context for s in playbooks.SOURCES[t]})
    tf, tt, window = hunt_window(hypothesis, [s for k in need for s in by_type.get(k, [])] or sources, it["window"])
    notes["intake"] = {"source": by, "window": window, "assumptions": it["assumptions"], "dropped": it["dropped"],
                       "users": it["users"]}
    hosts, ips = it["hosts"], it["ips"]
    for h in hosts:
        c = await mcp.call("count", index=config.HUNT_INDEX, time_from=tf, time_to=tt, filters=[{"field": "host.name", "op": "eq", "value": h}])
        if c.get("total", 0) == 0:
            notes["entity_missing"].append(h)
    sm = SIZE_RX.search(hypothesis)
    scope: dict = {"hosts": hosts}
    if sm:
        scope["exfil_bytes"] = int(float(sm.group(1)) * {"kb": 1024, "mb": 1024**2, "gb": 1024**3}[sm.group(2).lower()])

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
        entities={"hosts": hosts, "ips": ips, "users": it["users"], "technique_names": meta,
                  # C3 reads these: a technique only the LLM chose is a lead group, never proof (C3 evidence/verdict.py)
                  "requirement_groups": [{"label": t, "kind": "technique" if t in it["rules"] or by == "rules" else "llm", "techniques": [t]}
                                         for t in required],
                  **({"exfil_bytes": scope["exfil_bytes"]} if "exfil_bytes" in scope else {})},
        required_sources=need, time_range={"from": tf, "to": tt}, window_minutes=60, steps=steps,
        success_criteria=[f"{t} ({meta[t]}): at least {MIN_SUPPORT.get(t, 1)} independent self-checked indicator(s)" for t in required],
        refutation_criteria=[f"{t}: all required sources and fields covered for the full window AND zero indicators" for t in required],
        planner=by)
    notes["data_sources"] = {k: sum(x["docs"] for x in v) for k, v in by_type.items()}
    return plan, notes
