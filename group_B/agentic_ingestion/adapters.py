"""Execution boundary for Batch 6; Batch 5 implements no transports."""

from collections.abc import Iterable
from typing import Protocol

from .models import IngestionPlan


class IngestionAdapter(Protocol):
    """An executor must enforce dry-run and require a separate verification step.

    A transport receipt cannot establish that events were indexed or parsed.
    Records are raw envelopes with message and B3 metadata, except where a
    future agreed stream contract explicitly requires normalization.
    """

    def handoff(self, plan: IngestionPlan, records: Iterable[dict]) -> dict: ...
