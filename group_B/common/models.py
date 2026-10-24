"""Core models shared by B2 and B3."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RecogniseResult(BaseModel):
    """Result returned by B1's ``recognise(lines)`` interface.

    B1 may return this model or a plain mapping with the same keys. A matched
    result identifies the format and dataset. ``pipeline_id`` is optional
    because the shared repository README assigns pipeline selection to B3; B1
    may supply it when it already owns the validated pipeline mapping.

    An unmatched result is the explicit signal for B3 to ask B2 to resolve or
    generate a schema. It must not carry match metadata.

    Extra keys from B1's native return value are ignored so the boundary stays
    tolerant while B1 finishes its implementation; the adapter does not use
    them.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    matched: bool
    format_id: str | None = None
    dataset: str | None = None
    pipeline_id: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reason_code: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "format_id",
        "dataset",
        "pipeline_id",
        "reason_code",
        mode="before",
    )
    @classmethod
    def _clean_optional_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("must be a string or null")
        cleaned = value.strip()
        return cleaned or None

    @field_validator("confidence", mode="before")
    @classmethod
    def _validate_confidence_number(cls, value: Any) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("confidence must be a number between 0 and 1")
        return float(value)

    @model_validator(mode="after")
    def _validate_state(self) -> "RecogniseResult":
        match_fields = {
            "format_id": self.format_id,
            "dataset": self.dataset,
            "pipeline_id": self.pipeline_id,
        }

        if self.matched:
            missing = [
                name
                for name in ("format_id", "dataset")
                if not match_fields[name]
            ]
            if missing:
                raise ValueError(
                    "matched recognition requires: " + ", ".join(missing)
                )
            if self.reason_code is not None:
                raise ValueError(
                    "matched recognition must not set reason_code"
                )
            if self.confidence is not None and self.confidence <= 0.0:
                raise ValueError(
                    "matched confidence must be greater than 0 when supplied"
                )
            return self

        supplied = [name for name, value in match_fields.items() if value]
        if supplied:
            raise ValueError(
                "unmatched recognition must not include: "
                + ", ".join(supplied)
            )
        if self.confidence not in (None, 0.0):
            raise ValueError(
                "unmatched confidence must be 0 or omitted"
            )
        return self

    @classmethod
    def unknown(
        cls,
        reason: str = "no known schema matched",
        /,
        *,
        reason_code: str = "no_match",
        **evidence: Any,
    ) -> "RecogniseResult":
        """Build the explicit no-match result used to route records to B2.

        ``reason_code`` lets B3 distinguish a genuine format miss from a
        configuration failure such as B1 not being wired in yet.
        """

        return cls(
            matched=False,
            confidence=0.0,
            reason_code=reason_code,
            evidence={"reason": reason, **evidence},
        )
