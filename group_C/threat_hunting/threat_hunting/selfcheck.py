"""C2 self-check (DESIGN.md 3.1): structural checks on every claim before hand-off. It uses only results the agent already
holds; independent re-verification against Elasticsearch is C3's job. The text lint is ported from the prototype's verifier."""
from __future__ import annotations
import json, re
from .hunter import HuntState

IP_RX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TS_RX = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?|\b\d{1,2}:\d{2}(?::\d{2})?Z?")
INT_RX = re.compile(r"(?<![\w.])\d{2,}(?![\w.])")


def lint_text(text: str, haystack: str) -> list[str]:
    """Every IP and number quoted in a claim must be traceable to its facts, cited events or the query itself."""
    t = TS_RX.sub(" ", text)
    bad = [ip for ip in IP_RX.findall(t) if ip.lower() not in haystack]
    bad += [n for n in INT_RX.findall(IP_RX.sub(" ", t)) if n not in haystack]
    return bad


def _steps(st: HuntState) -> dict:
    return {s.step_id: s for s in st.plan.steps + st.dynamic_steps}


def check(st: HuntState) -> dict:
    ev = {e.evidence_id: e for e in st.evidence}
    steps = _steps(st)
    failed = []
    for c in st.claims:
        problems = []
        cited = [ev[e] for e in c.evidence_ids if e in ev]
        if not c.evidence_ids or len(cited) != len(c.evidence_ids):
            problems.append(f"cites missing evidence {[e for e in c.evidence_ids if e not in ev] or 'none'}")
        hits = [h for e in cited for h in st.raw.get(e.step_id, {}).get("hits", [])]
        if c.kind == "events":
            known_ids = {i for e in cited for i in e.event_ids}
            if not c.event_ids:
                problems.append("no event ids")
            elif not set(c.event_ids) <= known_ids:
                problems.append("event ids not in the cited results")
            for k, v in c.facts.items():
                vals = {str(h["fields"][k]) for h in hits if k in h["fields"]}
                if vals and not {str(x) for x in (v if isinstance(v, list) else [v])} <= vals:
                    problems.append(f"fact {k}={v} not in cited events")
        elif c.kind == "aggregate":
            res = st.raw.get(c.step_id, {}).get("result", [])
            b = next((b for b in res if str(b["key"]) == c.facts.get("bucket_key")), None) if isinstance(res, list) else None
            if b is None:
                problems.append("bucket not in the cited aggregation")
            else:
                for k in ("count", "sum", "distinct"):
                    if k in c.facts and str(c.facts[k]) != (str(int(b[k])) if isinstance(b.get(k), float) and b[k] == int(b[k]) else str(b.get(k))):
                        problems.append(f"{k}={c.facts[k]} differs from the aggregation ({b.get(k)})")
        elif not cited or not cited[0].total_hits:
            problems.append("threat-intel match not in the cited result")
        params = json.dumps(steps[c.step_id].params, default=str) if c.step_id in steps else ""
        hay = "\n".join([*(str(v) for v in c.facts.values()), *(str(v) for h in hits for v in h["fields"].values()), params]).lower()
        bad = lint_text(c.text, hay)
        if bad:
            problems.append(f"text quotes values not found in its evidence: {bad}")
        c.status = "unsupported" if problems else "self_checked"
        c.verifier_notes = "; ".join(problems)
        if problems:
            failed.append({"claim_id": c.claim_id, "problems": problems})
    return {"claims": len(st.claims), "self_checked": sum(c.status == "self_checked" for c in st.claims), "failed": failed}
