"""Small B1 recogniser stub used only by the adapter tests."""

from __future__ import annotations

from collections.abc import Sequence


def recognise(lines: Sequence[str]) -> dict:
    return {
        "matched": True,
        "format_id": "test.fake",
        "dataset": "test.fake",
        "confidence": 0.9,
        "evidence": {"lines": len(lines)},
    }


not_callable = 42
