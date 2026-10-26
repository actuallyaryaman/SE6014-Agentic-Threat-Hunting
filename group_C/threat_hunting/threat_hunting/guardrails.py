"""Guardrail on log content (DESIGN.md threat T1). In this agent log text never reaches the LLM: the planner sends only the
hypothesis and the ATT&CK catalogue, claims are filled from templates and verdicts come from rules. Injection-like text in the
logs is still suspicious in its own right, so every hunt sweeps its window for it, reports matches as findings and forces review."""
from __future__ import annotations
from . import config
from .models import HuntPlan
from .playbooks import BASE

SWEEP_FIELDS = ["user_agent.original", "url.original", "process.command_line", "user.name", "message"]
STEP_ID = "guard-injection"


async def injection_sweep(mcp, plan: HuntPlan, index_fields: set[str]) -> dict:
    """One search over the hunt window for the markers in baselines.yml, in the free-text fields the index actually has."""
    markers = BASE["injection_markers"]
    fields = [f for f in SWEEP_FIELDS if f in index_fields]
    out: dict = {"step_id": STEP_ID, "checked_fields": fields, "markers": markers, "call_id": None, "total": 0, "findings": []}
    if not fields:
        return out
    r = await mcp.call("search", index=config.HUNT_INDEX, time_from=plan.time_range["from"], time_to=plan.time_range["to"], size=50,
                       any_of=[{"field": f, "op": "contains", "value": m} for f in fields for m in markers],
                       fields=["@timestamp", "event.dataset", "host.name", "source.ip", *fields])
    out.update(call_id=r.get("call_id"), total=r.get("total", 0))
    if "error" in r:
        out["error"] = r["error"]
        return out
    for h in r["hits"]:
        f = h["fields"]
        hit = [k for k in fields if isinstance(f.get(k), str) and any(m.lower() in f[k].lower() for m in markers)]
        out["findings"].append({"event_id": f'{h["index"]}/{h["event_id"]}', "@timestamp": f.get("@timestamp"), "dataset": f.get("event.dataset"),
                                "source.ip": f.get("source.ip"), "host.name": f.get("host.name"), "fields": hit,
                                "excerpt": {k: f[k][:120] for k in hit}})
    return out
