"""python -m threat_hunting.run "<hypothesis>" [--run-id ID] [--max-calls N] [--control NAME=off ...]

Writes runs/<run_id>/{plan.json,result.json,trace.jsonl}. Report rendering is C3's; this prints a one-line summary.
Ported from the prototype's src/hunt/run.py (the verifier and reporter stay with C3)."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, platform, time
from pathlib import Path
from . import config, planner, hunter, selfcheck, verdict
from .llm import get_llm
from .mcp_client import McpHunt

DEFAULT_CONTROLS = {"canonical_order": True, "coverage_enforcement": True, "complete_results": True, "canonical_params": True}


def _hash_files(paths) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(Path(p).read_bytes())
    return h.hexdigest()[:16]


async def run_hunt(hypothesis: str, run_id: str | None = None, max_calls: int = 120, perturb_seed: int | None = None,
                   controls: dict | None = None) -> dict:
    controls = {**DEFAULT_CONTROLS, **(controls or {})}
    run_id = run_id or time.strftime("hunt-%Y%m%d-%H%M%S")
    run_dir = config.RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "trace.jsonl").unlink(missing_ok=True)
    (config.AUDIT_DIR / f"{run_id}.jsonl").unlink(missing_ok=True)
    t0 = time.time()
    async with McpHunt(run_id) as mcp:
        plan, notes = await planner.plan_hunt(mcp, hypothesis)
        plan.entities["entity_missing"] = notes["entity_missing"]
        canonical = list(plan.steps)
        if perturb_seed is not None:                               # experiment-only variance injection
            from .perturb import perturb_plan
            plan = perturb_plan(plan, perturb_seed)
            plan.entities["entity_missing"] = notes["entity_missing"]
        if controls["coverage_enforcement"]:                       # every planned step must run: re-add omitted ones
            have = {s.step_id for s in plan.steps}
            plan.steps += [s for s in canonical if s.step_id not in have]
        if controls["canonical_params"]:                           # the planner selects playbooks; it may not alter their queries
            canon = {s.step_id: s for s in canonical}
            plan.steps = [canon[s.step_id].model_copy(deep=True) for s in plan.steps]
        if controls["canonical_order"]:
            order = {s.step_id: i for i, s in enumerate(canonical)}
            plan.steps.sort(key=lambda s: order[s.step_id])
        (run_dir / "plan.json").write_text(plan.model_dump_json(indent=1))
        st = await hunter.execute(mcp, plan, max_calls, controls["complete_results"])
        tool_calls = mcp.calls
    check = selfcheck.check(st)
    d = verdict.decide(plan, st, notes)
    llm = get_llm("planner")
    src_files = list((config.ROOT / "threat_hunting").glob("*.py")) + list(config.KNOWLEDGE_DIR.glob("*"))
    meta = {"run_id": run_id, "backend": f"llm:{llm.describe()}" if llm else "rules (no usable LLM configured)", "planner": plan.planner,
            "code_hash": _hash_files(src_files), "tool_calls": tool_calls, "seconds": round(time.time() - t0, 1),
            "python": platform.python_version(), "temperature": os.environ.get("LLM_TEMPERATURE") or "provider default",
            "controls": controls, "perturb_seed": perturb_seed, "index": config.HUNT_INDEX,
            "mcp_servers": {"es": config.ES_MCP_CMD, "analytics": config.ANALYTICS_MCP_CMD}}
    limitations = ["Findings depend on the playbooks used; techniques without a playbook are not tested.",
                   "Baselines are synthetic allowlists and must be tuned per environment.",
                   "NOT_SUPPORTED means no evidence within the covered sources, fields and window, not proof of absence.",
                   "Claims passed C2's structural self-check only; independent re-verification against Elasticsearch is C3's."] + \
                  [f"data gap: {g}" for g in notes["gaps"]] + \
                  [f"missing fields: {k}: {v}" for k, v in notes["missing_fields"].items()]
    result = {"schema_version": "0.1", "run_id": run_id, "hypothesis": hypothesis, "time_range": plan.time_range,
              "verdict": {"label": d["verdict"], "confidence": d["confidence"], "requires_analyst_review": d["requires_analyst_review"],
                          "reasons": d["reasons"]},
              "techniques": d["rows"], "claims": [c.model_dump() for c in st.claims], "evidence": [e.model_dump() for e in st.evidence],
              "step_results": st.step_results, "self_check": check,
              "coverage": {k: notes.get(k) for k in ("data_sources", "coverage", "gaps", "missing_fields", "entity_missing")},
              "limitations": limitations, "notes": st.notes, "manifest": meta}
    (run_dir / "result.json").write_text(json.dumps(result, indent=1, default=str))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hypothesis"); ap.add_argument("--run-id"); ap.add_argument("--max-calls", type=int, default=120)
    ap.add_argument("--control", action="append", default=[], metavar="NAME=off", help=f"switch a control off: {sorted(DEFAULT_CONTROLS)}")
    a = ap.parse_args()
    ctl = {}
    for c in a.control:
        k, _, v = c.partition("=")
        if k not in DEFAULT_CONTROLS:
            ap.error(f"unknown control {k!r}")
        ctl[k] = v.lower() not in ("off", "false", "0")
    r = asyncio.run(run_hunt(a.hypothesis, a.run_id, a.max_calls, controls=ctl))
    v = r["verdict"]
    print(f"run {r['run_id']}: {v['label']} ({v['confidence']}); claims={len(r['claims'])} "
          f"self_checked={r['self_check']['self_checked']}; tool calls={r['manifest']['tool_calls']}")
    print(f"result: runs/{r['run_id']}/result.json")
