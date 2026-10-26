"""C2 self-check (DESIGN.md 3.1): structural checks on every claim before hand-off, using only results the agent already holds.
Same rules as C3 (INTERFACES.md 4.2): every fact is a field value of every cited event (n_connections is the one derived fact),
and IPs and numbers in the text must come from the cited events, bucket or query, never from the claim's own facts.
Independent re-verification against Elasticsearch is C3's job. The text lint is ported from the prototype's verifier."""
from __future__ import annotations
import json, re
from .hunter import HuntState

IP_RX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# a clock time, but not the "20:43" inside "198.51.100.20:43000" (an IP and a port; seen in a live agent claim)
TS_RX = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?|(?<![\d.])\b\d{1,2}:\d{2}(?::\d{2})?Z?(?!\d)")
INT_RX = re.compile(r"(?<![\w.])\d{2,}(?![\w.])")


def lint_text(text: str, haystack: str) -> list[str]:
    """Every IP and number quoted in a claim must be found in the haystack (its cited events, bucket or query)."""
    t = TS_RX.sub(" ", text)
    bad = [ip for ip in IP_RX.findall(t) if ip.lower() not in haystack]
    bad += [n for n in INT_RX.findall(IP_RX.sub(" ", t)) if n not in haystack]
    return bad


# facts that are not event fields, with the only way they may be checked (same rule as C3)
DERIVED = {"n_connections": lambda c: str(len(c.event_ids))}


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
        own = [h for h in hits if f'{h["index"]}/{h["event_id"]}' in set(c.event_ids)]     # the events this claim cites
        quotable: list[str] = []          # what the claim text may quote: cited events, the bucket, threat-intel matches
        if c.kind == "events":
            known_ids = {i for e in cited for i in e.event_ids}
            if not c.event_ids:
                problems.append("no event ids")
            elif not set(c.event_ids) <= known_ids:
                problems.append("event ids not in the cited results")
            for k, v in c.facts.items():
                if k in DERIVED:
                    if str(v) != DERIVED[k](c):
                        problems.append(f"fact {k}={v} does not match the cited events ({DERIVED[k](c)})")
                elif isinstance(v, list):
                    if not {str(x) for x in v} <= {str(h["fields"].get(k, "")) for h in own}:
                        problems.append(f"fact {k}={v} is not in the cited events")
                elif not own or any(str(h["fields"].get(k, "")).lower() != str(v).lower() for h in own):
                    problems.append(f"fact {k}={v!r} is not a field value of every cited event")
        elif c.kind == "aggregate":
            res = st.raw.get(c.step_id, {}).get("result", [])
            b = next((b for b in res if str(b["key"]) == c.facts.get("bucket_key")), None) if isinstance(res, list) else None
            if b is None:
                problems.append("bucket not in the cited aggregation")
            else:
                quotable.append(json.dumps(b, default=str))
                for k in ("count", "sum", "distinct"):
                    if k in c.facts and str(c.facts[k]) != (str(int(b[k])) if isinstance(b.get(k), float) and b[k] == int(b[k]) else str(b.get(k))):
                        problems.append(f"{k}={c.facts[k]} differs from the aggregation ({b.get(k)})")
        elif not cited or not cited[0].total_hits:
            problems.append("threat-intel match not in the cited result")
        else:
            quotable += [json.dumps(e.excerpt, default=str) for e in cited]
        params = json.dumps(steps[c.step_id].params, default=str) if c.step_id in steps else ""
        # the claim's own facts are not evidence: a value quoted in the text must come from what the claim cites
        hay = "\n".join([*quotable, *(str(v) for h in own for v in h["fields"].values()), params]).lower()
        bad = lint_text(c.text, hay)
        if bad:
            problems.append(f"text quotes values not found in its evidence: {bad}")
        c.status = "unsupported" if problems else "self_checked"
        c.verifier_notes = "; ".join(problems)
        if problems:
            failed.append({"claim_id": c.claim_id, "problems": problems})
    return {"claims": len(st.claims), "self_checked": sum(c.status == "self_checked" for c in st.claims), "failed": failed}
