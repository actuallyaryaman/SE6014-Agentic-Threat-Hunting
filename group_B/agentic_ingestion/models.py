"""Inputs and planning results for source onboarding."""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from group_B.common.models import RecogniseResult
from group_B.schema_generation.generate import SchemaResolution
from group_B.schema_generation.signature import SourceSignature

SourceKind = Literal["file", "http", "stream"]
IngestMode = Literal["auto", "pull", "push", "stream", "direct_es"]


class SourceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SourceKind
    location: str = Field(min_length=1, max_length=4096)
    format_hint: Literal["auto", "json", "csv", "kv", "line"] = "auto"
    dataset_hint: str | None = Field(default=None, min_length=1, max_length=128)
    host_name: str | None = Field(default=None, min_length=1, max_length=255)
    timezone: str | None = None
    ingest_mode: IngestMode = "auto"
    dry_run: bool = Field(default=True, strict=True)

    @field_validator("location", "dataset_hint", "host_name")
    @classmethod
    def clean_text(cls, value):
        if value is None:
            return None
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError("must be non-empty text without control characters")
        return value.strip()

    @field_validator("timezone")
    @classmethod
    def check_timezone(cls, value):
        if value is not None:
            try:
                ZoneInfo(value)
            except (ZoneInfoNotFoundError, ValueError) as error:
                raise ValueError("timezone must name an IANA timezone") from error
        return value


class InspectionPolicy(BaseModel):
    """Explicit source permissions; an empty allowlist grants no access."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_roots: tuple[Path, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    max_samples: int = Field(default=50, ge=1, le=200)
    max_line_bytes: int = Field(default=65536, ge=1, le=65536)
    max_bytes: int = Field(default=1048576, ge=1, le=1048576)
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    max_redirects: int = Field(default=3, ge=0, le=5)

    @field_validator("timeout_seconds")
    @classmethod
    def finite_timeout(cls, value):
        if not math.isfinite(value):
            raise ValueError("timeout must be finite")
        return value

    @classmethod
    def from_env(cls) -> "InspectionPolicy":
        return cls(
            allowed_roots=tuple(
                Path(p) for p in os.environ.get("B3_ALLOWED_ROOTS", "").split(os.pathsep) if p
            ),
            allowed_hosts=tuple(
                h.strip() for h in os.environ.get("B3_ALLOWED_HOSTS", "").split(",") if h.strip()
            ),
        )


class TimestampCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    format: str
    requires_timezone: bool = False
    requires_year: bool = False


class SourceInspection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SourceKind
    source_id: str
    signature: SourceSignature
    sample_count: int
    sample_limit_reached: bool
    timestamp: TimestampCandidate | None = None
    # Samples remain available to B1/B2, but never enter JSON plan output.
    samples: tuple[str, ...] = Field(exclude=True, repr=False)


class IngestionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["planned", "blocked"]
    inspection: SourceInspection
    schema_resolution: SchemaResolution | None = Field(default=None, exclude=True, repr=False)
    recognition: RecogniseResult
    ingest_mode: IngestMode
    dataset: str | None = None
    pipeline_id: str | None = None
    schema_reused: bool = False
    registration_required: bool = False
    validation_mode: Literal["offline", "es_simulate"] | None = None
    dry_run: bool
    verification_required: Literal[True] = True
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @field_serializer("recognition")
    def recognition_summary(self, value):
        # B1 evidence is opaque and may contain source excerpts.
        return value.model_dump(mode="json", exclude={"evidence"})
