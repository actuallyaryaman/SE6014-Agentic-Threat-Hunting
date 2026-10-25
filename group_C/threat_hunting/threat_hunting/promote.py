"""Candidate playbooks from LLM leads, and their promotion into vetted playbooks (DESIGN.md 5.5).

After a hunt, the investigator steps whose findings passed the self-check, for techniques no built-in playbook covers, are
written to runs/<id>/candidates/<technique>.yml. An analyst promotes one with

  python -m threat_hunting.promote runs/<id>/candidates/<technique>.yml --benign-from ISO --benign-to ISO \\
      --approved-by NAME --keywords "dns tunnel,tunnelled"

Promotion replays the steps over MCP: over the original hunt window they must find the same events or buckets again, and
over the benign window they must find nothing. Only then is the playbook written to knowledge/playbooks/ (HUNT_PLAYBOOK_DIR),
where later hunts select it by its keywords and run it as a vetted playbook (its findings have origin "playbook")."""
from __future__ import annotations
import argparse, asyncio, json, re, sys, time
from pathlib import Path
import yaml
from . import config, hunter, playbooks
from .mcp_client import McpHunt
from .models import ACCEPTED, HuntPlan


def _fields(steps: list[dict]) -> list[str]:
    out = set()
    for s in steps:
        p = s["params"]
        out |= {f["field"] for k in ("filters", "any_of", "must_not") for f in p.get(k, [])}
        out |= {p[k] for k in ("field", "sum_field", "distinct_field") if p.get(k)} | set(s["analysis"].get("group_by", []))
    return sorted(out - {"@timestamp"})


def _scope(step) -> set[str]:
    return {v for f in step.params.get("filters", []) if f.get("field") == "event.dataset"
            for v in (f["value"] if isinstance(f["value"], list) else [f["value"]])}


def _infer_scope(step, sources: list[dict]) -> set[str]:
    """A step without an event.dataset filter: the datasets no playbook covers whose fields include every field it uses."""
    p = step.params
    used = {f["field"] for k in ("filters", "any_of", "must_not") for f in p.get(k, [])} | {p[k] for k in ("field", "distinct_field", "sum_field") if p.get(k)}
    return {u["dataset"] for u in sources if not u.get("matched_kind") and used - {"@timestamp"} <= set(u.get("fields", []))}


def write_candidates(run_dir: Path, run_id: str, plan: HuntPlan, st: hunter.HuntState, agent_out: dict,
                     unknown_sources: list[dict] | None = None) -> list[dict]:
    """One candidate playbook per technique, from the agent steps whose findings passed the self-check and that hunted data
    no built-in playbook of that technique covers. Returns what result.json["candidates"] lists."""
    steps = {s.step_id: s for s in st.dynamic_steps if s.step_id.startswith("AG-")}
    # a step that names no dataset is scoped to the uncovered datasets that have its fields (result.json keeps the query as run)
    scope = {sid: _scope(s) or _infer_scope(s, unknown_sources or []) for sid, s in steps.items()}
    by_tech: dict[str, dict[str, list]] = {}
    for c in st.claims:
        if c.origin == "llm" and c.status in ACCEPTED and c.step_id in steps and scope[c.step_id] \
                and not scope[c.step_id] <= playbooks.builtin_datasets(c.technique):
            by_tech.setdefault(c.technique, {}).setdefault(c.step_id, []).append(c)
    kb = json.loads((config.KNOWLEDGE_DIR / "attack_subset.json").read_text())
    out = []
    for tech, found in sorted(by_tech.items()):
        datasets, pb_steps = set(), []
        for i, (sid, claims) in enumerate(sorted(found.items())):
            s = steps[sid]
            p = {k: v for k, v in s.params.items() if k not in ("index", "time_from", "time_to")}
            datasets |= scope[sid]
            # the playbook adds its own dataset filter; a host named in the hypothesis is scope, not logic
            p["filters"] = [f for f in p.get("filters", []) if f.get("field") != "event.dataset"
                            and not (f.get("field") == "host.name" and f.get("value") in plan.entities.get("hosts", []))]
            expect = sorted({e for c in claims for e in c.event_ids}) if s.tool == "search" else sorted({c.facts["bucket_key"] for c in claims})
            pb_steps.append({"id": "", "from_step": sid, "tool": s.tool, "purpose": s.purpose, "params": p,
                             "claim_template": s.claim_template, "analysis": s.analysis, "expect": expect})
        if not datasets:
            out.append({"technique": tech, "file": None, "skipped": "the agent steps do not name an event.dataset"})
            continue
        for i, st_ in enumerate(pb_steps):              # ids carry the data source, so they never collide with built-in step ids
            st_["id"] = f"{tech}-{sorted(datasets)[0]}-{chr(97 + i)}"
        pb = {"technique": tech, "name": kb.get(tech, {}).get("name", f"{tech} (not in the local ATT&CK catalogue)"), "status": "candidate",
              "kind": sorted(datasets)[0], "datasets": sorted(datasets), "required_fields": _fields(pb_steps),
              "keywords": [], "steps": pb_steps,
              "provenance": {"run_id": run_id, "hypothesis": plan.hypothesis, "window": plan.time_range,
                             "created_by": f"investigator LLM ({agent_out.get('model')})", "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
        f = run_dir / "candidates" / f"{tech}.yml"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(yaml.safe_dump(pb, sort_keys=False, allow_unicode=True))
        out.append({"technique": tech, "file": str(f.relative_to(config.ROOT)), "steps": [s["from_step"] for s in pb_steps]})
    return out


async def replay(mcp, pb: dict, tf: str, tt: str) -> list[dict]:
    """Run a playbook's steps over a window and report the events (search) or buckets (aggregate) its claims cite."""
    t = pb["technique"]
    plan = HuntPlan(hypothesis=f"promotion replay of {t}", techniques=[t], required_techniques=[t], required_sources=[pb["kind"]],
                    time_range={"from": tf, "to": tt}, steps=[], success_criteria=[], refutation_criteria=[])
    st = hunter.HuntState(plan)
    out = []
    for step in playbooks.steps_from_yaml(pb, tf, tt):
        before = len(st.claims)
        res = await hunter.run_step(mcp, st, step)
        if res is not None:
            hunter.extract_claims(st, step, res)
        new = st.claims[before:]
        keys = sorted({e for c in new for e in c.event_ids}) if step.tool == "search" else sorted({c.facts["bucket_key"] for c in new})
        out.append({"step": step.step_id, "claims": len(new), "keys": keys,
                    **({"error": st.step_results.get(step.step_id, {}).get("error", "failed")} if res is None else {})})
    return out


async def promote(path: Path, benign: tuple[str, str], approved_by: str, keywords: list[str], name: str | None = None) -> dict:
    pb = yaml.safe_load(path.read_text())
    if pb.get("status") != "candidate":
        raise SystemExit(f"{path} is not a candidate playbook (status {pb.get('status')!r})")
    if not keywords:
        raise SystemExit("--keywords is required: later hunts select the playbook by them")
    win = pb["provenance"]["window"]
    slug = re.sub(r"[^a-z0-9]+", "-", f"{pb['technique']}-{pb['kind']}".lower()).strip("-")
    async with McpHunt(f"promote-{slug}-{time.strftime('%Y%m%d-%H%M%S')}") as mcp:
        attack = await replay(mcp, pb, win["from"], win["to"])
        quiet = await replay(mcp, pb, *benign)
    expect = {s["id"]: set(s["expect"]) for s in pb["steps"]}
    checks = {"attack_window": win, "benign_window": {"from": benign[0], "to": benign[1]},
              "attack": [{**r, "keys": r["keys"][:20], "reproduced": expect[r["step"]] <= set(r["keys"])} for r in attack],
              "benign": [{k: r[k] for k in ("step", "claims", "keys") if k in r} for r in quiet]}
    ok = all(r["reproduced"] and "error" not in r for r in checks["attack"]) and all(r["claims"] == 0 for r in quiet)
    out = {"ok": ok, "validation": checks, "file": None}
    if ok:
        pb.update(status="approved", keywords=keywords, approved_by=approved_by, validation=checks,
                  approved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **({"name": name} if name else {}))
        config.PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
        f = config.PLAYBOOK_DIR / f"{slug}.yml"
        f.write_text(yaml.safe_dump(pb, sort_keys=False, allow_unicode=True))
        out["file"] = str(f)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Promote a candidate playbook after replaying it over an attack and a benign window.")
    ap.add_argument("candidate", type=Path)
    ap.add_argument("--benign-from", required=True); ap.add_argument("--benign-to", required=True)
    ap.add_argument("--approved-by", required=True)
    ap.add_argument("--keywords", required=True, help="comma-separated words that select this playbook from a hypothesis")
    ap.add_argument("--name")
    a = ap.parse_args()
    r = asyncio.run(promote(a.candidate, (a.benign_from, a.benign_to), a.approved_by,
                            [k.strip().lower() for k in a.keywords.split(",") if k.strip()], a.name))
    print(json.dumps(r, indent=1))
    sys.exit(0 if r["ok"] else 1)
