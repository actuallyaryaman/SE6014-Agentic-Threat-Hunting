"""Executive summary, built from the verified data.

An LLM may rephrase it. The rephrased text is thrown away if it contains an IP,
number or hash that is not in the findings.
"""

from __future__ import annotations

from typing import Callable, Optional

from .contracts import Claim
from .verdict import Decision
from .verifier import lint_text

Rephraser = Callable[[str, dict], str]


def deterministic_summary(hypothesis: str, decision: Decision, findings: list[Claim]) -> str:
    """Write the summary from rules only, with no LLM involved."""
    v = decision.verdict
    if v == "Confirmed":
        techs = sorted({f"{r.technique} ({r.name})" for r in decision.rows if r.supported and r.required})
        first = min((c.first_seen for c in findings if c.first_seen), default="")
        text = (f"The hunt confirmed the hypothesis with {decision.confidence} confidence: {len(findings)} verified "
                f"finding(s) support {', '.join(techs)}.")
        if first:
            text += f" The earliest supporting event is at {first}."
        return text + " An analyst should review the findings before acting."
    if v == "Refuted":
        return ("No verified indicator was found for any part of the hypothesis within the covered sources and time "
                "window. That means there was no evidence in that scope. It does not prove the activity did not happen.")
    lead = decision.reasons[0] if decision.reasons else "the evidence was not sufficient"
    return f"The hunt could not confirm or refute the hypothesis: {lead}"


def summary_text(hypothesis: str, decision: Decision, findings: list[Claim],
                 rephrase: Optional[Rephraser] = None) -> tuple[str, str]:
    """Return (summary, source), where source is 'rules' or 'llm'."""
    base = deterministic_summary(hypothesis, decision, findings)
    if rephrase is None:
        return base, "rules"
    facts = {"hypothesis": hypothesis, "verdict": decision.verdict, "confidence": decision.confidence,
             "findings": [c.text for c in findings], "reasons": decision.reasons}
    try:
        candidate = rephrase(base, facts)
    except Exception:
        return base, "rules"
    haystack = "\n".join([base, hypothesis] + [c.text for c in findings] + decision.reasons).lower()
    for c in findings:
        haystack += "\n" + "\n".join(str(v) for v in c.facts.values()).lower()
    if not candidate or lint_text(candidate, haystack):
        return base, "rules"
    return candidate.strip(), "llm"
