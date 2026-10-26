"""Find text in log events that tries to give instructions to an AI (prompt injection).

C3 treats every cited event as data. A match changes nothing in the analysis. It adds a flag to the report and sends the hunt to an analyst.
"""

from __future__ import annotations

import re
from typing import Optional

_PATTERNS = [
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|messages)",
    r"disregard (all |any )?(the )?(previous|prior|above) ",
    r"\byou are now\b",
    r"\bsystem prompt\b",
    r"\bnew instructions?\b",
    r"\b(assistant|system)\s*:",
    r"\bact as\b",
    r"(mark|report|classify|treat)\s+(this|the)?\s*(host|event|log|activity|ip)?\s*as\s+(safe|benign|clean|false positive)",
    r"\bdo not (report|flag|alert|mention)\b",
    r"\bverdict\s*[:=]\s*(benign|safe|not_supported|clean)",
    r"</?(tool|function|instructions?|prompt)>",
]
_RX = re.compile("|".join(f"(?:{p})" for p in _PATTERNS), re.IGNORECASE)


def scan_for_injection(text: Optional[str]) -> list[str]:
    """Return the instruction-like fragments in ``text``, or an empty list."""
    if not text:
        return []
    return [m.group(0) for m in _RX.finditer(text)]
