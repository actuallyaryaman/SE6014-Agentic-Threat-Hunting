"""Read-only B1/B2 orchestration and deterministic transport planning."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Protocol

from group_B.common.recognizer import NullRecognizer, Recognizer
from group_B.schema_generation.generate import CandidateProvider, resolve_or_generate
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.validate import validate_pipeline

from .inspect import inspect_source
from .models import IngestionPlan, InspectionPolicy, SourceInspection, SourceSpec


class RouteAdvisor(Protocol):
    """Optional advice can select only a permitted transport mode."""

    def propose(self, summary: dict, allowed_modes: tuple[str, ...]) -> str: ...


def plan_source(
    source: SourceSpec,
    policy: InspectionPolicy,
    *,
    recognizer: Recognizer | None = None,
    registry: SchemaRegistry | None = None,
    known_pipelines: Mapping[str, str] | None = None,
    schema_provider: CandidateProvider | None = None,
    route_advisor: RouteAdvisor | None = None,
    stream_samples: Iterable[str] | None = None,
) -> IngestionPlan:
    inspection = inspect_source(source, policy, stream_samples=stream_samples)
    return plan_inspection(
        source, inspection, recognizer=recognizer, registry=registry,
        known_pipelines=known_pipelines, schema_provider=schema_provider,
        route_advisor=route_advisor,
    )


def plan_inspection(
    source: SourceSpec,
    inspection: SourceInspection,
    *,
    recognizer: Recognizer | None = None,
    registry: SchemaRegistry | None = None,
    known_pipelines: Mapping[str, str] | None = None,
    schema_provider: CandidateProvider | None = None,
    route_advisor: RouteAdvisor | None = None,
) -> IngestionPlan:
    if source.kind != inspection.kind:
        raise ValueError("source kind does not match the inspection")
    reasons = []
    warnings = ["Indexing and Elasticsearch verification have not been performed."]
    allowed = (("stream",) if source.kind == "stream" else
               ("pull", "push", "stream") if source.ingest_mode == "stream" else ("pull", "push"))
    default = {"file": "pull", "http": "push", "stream": "stream"}[source.kind]
    mode = default if source.ingest_mode == "auto" else source.ingest_mode
    if mode not in allowed and mode != "direct_es":
        reasons.append("Requested transport is incompatible with the source kind.")
    if mode == "direct_es":
        warnings.append("Direct Elasticsearch transport is an explicit local fallback only.")
    if source.kind == "stream":
        reasons.append("Continuous UDP capture is unsupported; use a bounded file or HTTP snapshot with stream mode.")
    if route_advisor is not None and source.ingest_mode == "auto":
        try:
            proposed = route_advisor.propose({
                "kind": source.kind, "sample_count": inspection.sample_count,
                "format": inspection.signature.kind.value,
            }, allowed)
            if proposed not in allowed:
                raise ValueError("advisor proposed a disallowed mode")
            mode = proposed
        except Exception:
            warnings.append("Route advice failed validation; the deterministic route was retained.")

    timestamp = inspection.timestamp
    if timestamp is None:
        reasons.append("No consistent timestamp candidate was found.")
    else:
        if timestamp.requires_timezone and source.timezone is None:
            reasons.append("Source timestamps require an explicit timezone.")
        if timestamp.requires_year and source.log_year is None:
            reasons.append("Source timestamps omit the year; an explicit year policy is required.")

    recognition = (recognizer or NullRecognizer()).recognise(inspection.samples)
    dataset = None
    pipeline_id = None
    reused = False
    registration_required = False
    validation_mode = None
    resolution = None
    if recognition.matched:
        dataset = recognition.dataset
        # B1's output is evidence, not approval. Only an operator-supplied
        # known-format mapping may authorize the selected pipeline.
        approved = (known_pipelines or {}).get(recognition.format_id)
        if (approved and re.fullmatch(r"[A-Za-z0-9._-]{1,255}", approved)
                and (recognition.pipeline_id is None or approved == recognition.pipeline_id)):
            pipeline_id = approved
        else:
            reasons.append("The recognized format has no matching approved pipeline mapping.")
        if source.dataset_hint and source.dataset_hint != dataset:
            reasons.append("Dataset hint conflicts with the recognized dataset.")
    elif recognition.reason_code != "no_match":
        reasons.append("B1 recognition is not configured or did not return an explicit no-match.")
    else:
        read_registry = SchemaRegistry(
            registry.root if registry is not None else None, read_only=True,
        )
        resolution = resolve_or_generate(
            inspection.samples, source.dataset_hint, registry=read_registry,
            provider=schema_provider,
            timezone=source.timezone,
        )
        reused = resolution.reused
        if resolution.entry is not None:
            entry = resolution.entry
            dataset = entry.schema_spec.dataset
            pipeline_id = entry.pipeline_id
            report = validate_pipeline(entry.schema_spec, entry.pipeline, inspection.samples)
            validation_mode = report.mode
            if not report.accepted:
                reasons.append("Registered pipeline failed validation against the current samples.")
            if (timestamp is not None and timestamp.requires_timezone
                    and source.timezone != entry.schema_spec.timestamp.timezone):
                reasons.append("Registered schema timezone conflicts with the source timezone.")
            if source.dataset_hint and source.dataset_hint != dataset:
                reasons.append("Dataset hint conflicts with the registered schema.")
        elif resolution.generation is not None and resolution.generation.accepted:
            generated = resolution.generation
            dataset = generated.schema_spec.dataset
            pipeline_id = generated.schema_spec.pipeline_id
            validation_mode = generated.validation.mode
            registration_required = True
            warnings.append("The generated schema still needs registry registration and ES pipeline installation.")
        else:
            reasons.append("B2 could not produce an accepted schema for the samples.")
    if validation_mode == "offline":
        warnings.append("Pipeline validation is offline; live Elasticsearch validation is pending.")
    if pipeline_id is not None:
        warnings.append("The selected pipeline must exist in Elasticsearch before execution.")
    return IngestionPlan(
        status="blocked" if reasons else "planned", inspection=inspection,
        recognition=recognition, ingest_mode=mode, dataset=dataset,
        pipeline_id=pipeline_id, schema_reused=reused,
        registration_required=registration_required, validation_mode=validation_mode,
        schema_resolution=resolution,
        dry_run=source.dry_run, reasons=tuple(reasons), warnings=tuple(warnings),
    )
