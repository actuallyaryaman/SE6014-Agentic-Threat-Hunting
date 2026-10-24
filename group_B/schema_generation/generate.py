"""Agentic generation of a ``SchemaSpec`` from unknown source samples.

Batch 3 fills the middle of the B2 lifecycle: when Batch 1 detection finds no
registered schema, this module proposes candidate ``SchemaSpec`` objects,
compiles and validates each one through the Batch 2 pipeline layer, and uses
the resulting validation feedback to score candidates. Generation is offline
and deterministic by default; an optional candidate provider (for example a
local LLM call) can be injected for sources that the heuristic generator
cannot describe. No network access happens inside this module.

Every generated record must satisfy ``group_B/CONTRACTS.md``:

* a structural signature is built from the raw samples;
* at least one candidate is compiled and validated against a bounded sample;
* the first candidate whose ``ValidationReport`` is accepted wins;
* provenance records whether the winning candidate came from the heuristic
  generator or from an injected provider.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from group_B.common.errors import SchemaGenerationError
from group_B.schema_generation.compile_es import (
    MAX_SAMPLE_LINE_LENGTH,
    PipelineCompileError,
    compile_pipeline,
)
from group_B.schema_generation.models import (
    CsvParser,
    FieldSpec,
    FieldType,
    JsonParser,
    KvParser,
    Provenance,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import RegistryEntry, SchemaRegistry
from group_B.schema_generation.signature import (
    SourceSignature,
    build_signature,
)
from group_B.schema_generation.validate import (
    MAX_VALIDATION_SAMPLES,
    sample_hashes,
    validate_pipeline,
)

MAX_CANDIDATES = 8

_SCHEMA_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_TIMESTAMP_HINT_RE = re.compile(
    r"(?:^|[_\-.])(?:timestamp|time|date)(?:[_\-.]|$)"
)
_IP_VALUE_RE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}"
    r"|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){0,7})$",
    re.IGNORECASE,
)

_MESSAGE_KEYS = frozenset(
    {"message", "msg", "event_message", "log_message", "log_message_text"}
)

# Deterministic keyword targets, ordered so the first match wins. The targets
# stay within the ECS portion of the shared field list; unknown keys are
# deliberately ignored so a generated schema cannot fabricate arbitrary new
# fields from one sample source.
_KEY_TARGETS: tuple[tuple[str, str], ...] = (
    ("src_ip", "source.ip"),
    ("source_ip", "source.ip"),
    ("sourceip", "source.ip"),
    ("src_addr", "source.ip"),
    ("source_addr", "source.ip"),
    ("ipaddr", "source.ip"),
    ("ip_address", "source.ip"),
    ("src_port", "source.port"),
    ("source_port", "source.port"),
    ("user", "user.name"),
    ("user_name", "user.name"),
    ("username", "user.name"),
    ("usrname", "user.name"),
    ("acct", "user.name"),
    ("account", "user.name"),
    ("host", "host.name"),
    ("hostname", "host.name"),
    ("host_name", "host.name"),
    ("node", "host.name"),
    ("command", "process.command_line"),
    ("command_line", "process.command_line"),
    ("cmd", "process.command_line"),
    ("cmdline", "process.command_line"),
    ("process_name", "process.name"),
    ("proc_name", "process.name"),
    ("exe", "process.executable"),
    ("executable", "process.executable"),
    ("action", "event.action"),
    ("event_action", "event.action"),
    ("event_type", "event.type"),
    ("event", "event.action"),
    ("event_id", "event.id"),
)


class CandidateProvider(Protocol):
    """Offline, deterministic candidate supplier for unknown formats.

    A provider returns ``SchemaSpec``-shaped dictionaries (the same mapping
    shape accepted by ``SchemaSpec.model_validate``). Providers must never
    perform network calls; the generator treats them as pure functions of the
    supplied samples.
    """

    def propose(
        self,
        *,
        samples: Sequence[str],
        dataset_hint: str | None,
        signature: SourceSignature,
    ) -> Sequence[Mapping[str, Any]]:
        """Return zero or more candidate schema dictionaries."""


class GenerationAttempt(BaseModel):
    """One candidate that the generator compiled and validated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    origin: str = Field(pattern=r"^(heuristic|provider)$")
    candidate: dict[str, Any]
    schema_spec: SchemaSpec | None = None
    pipeline: dict[str, Any] | None = None
    validation: ValidationReport | None = None
    accepted: bool = False
    errors: list[str] = Field(default_factory=list)


class GenerationResult(BaseModel):
    """Outcome of bounded candidate generation against one source sample."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature: SourceSignature
    accepted: bool = False
    schema_spec: SchemaSpec | None = None
    pipeline: dict[str, Any] | None = None
    validation: ValidationReport | None = None
    provenance: Provenance | None = None
    attempts: list[GenerationAttempt] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class SchemaResolution(BaseModel):
    """Result of ``resolve_or_generate``: reuse a known schema or generate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature: SourceSignature
    reused: bool
    entry: RegistryEntry | None = None
    generation: GenerationResult | None = None

    @property
    def pipeline_id(self) -> str | None:
        if self.entry is not None:
            return self.entry.pipeline_id
        if self.generation is None or self.generation.schema_spec is None:
            return None
        return self.generation.schema_spec.pipeline_id


class SchemaGenerator:
    """Propose, compile, and validate candidate schemas for one source."""

    def __init__(
        self,
        provider: CandidateProvider | None = None,
        *,
        max_candidates: int = MAX_CANDIDATES,
        registry: SchemaRegistry | None = None,
        timezone: str | None = None,
    ) -> None:
        if not isinstance(max_candidates, int) or isinstance(max_candidates, bool):
            raise SchemaGenerationError(
                "max_candidates must be an integer between 1 and 8"
            )
        if max_candidates < 1 or max_candidates > MAX_CANDIDATES:
            raise SchemaGenerationError(
                "max_candidates must be an integer between 1 and 8"
            )
        self._provider = provider
        self._max_candidates = max_candidates
        self._registry = registry
        self._timezone = timezone

    def generate(
        self,
        samples: Sequence[str],
        dataset_hint: str | None = None,
    ) -> GenerationResult:
        """Build a validated schema for ``samples``, or reject them."""

        lines = _prepare_samples(samples)
        signature = build_signature(samples)
        dataset = _normalize_dataset(dataset_hint or _guess_dataset(signature))

        candidates = _heuristic_candidates(lines, dataset)
        attempts: list[GenerationAttempt] = []
        provider_error: str | None = None
        for index, candidate in enumerate(candidates):
            if len(attempts) >= self._max_candidates:
                break
            attempts.append(
                self._evaluate_candidate(
                    candidate,
                    origin="heuristic",
                    samples=lines,
                )
            )
            if attempts[-1].accepted:
                return self._result(signature, attempts, lines)

        # The heuristic generator only knows JSON, CSV and KV. Anything else
        # needs an injected provider.
        if self._provider is not None:
            try:
                prompt_hash, provider_candidates = self._provider_candidates(
                    samples,
                    dataset,
                    signature,
                )
            except SchemaGenerationError as error:
                prompt_hash = None
                provider_candidates = []
                provider_error = str(error)
            else:
                provider_error = None
            for candidate in provider_candidates[: self._max_candidates]:
                attempts.append(
                    self._evaluate_candidate(
                        candidate,
                        origin="provider",
                        samples=lines,
                    )
                )
                if attempts[-1].accepted:
                    return self._result(
                        signature,
                        attempts,
                        lines,
                        provenance={
                            "generator": "llm",
                            "model": _provider_model_name(self._provider),
                            "prompt_hash": prompt_hash,
                            "sample_hashes": sample_hashes(samples),
                        },
                    )

        errors: list[str] = []
        for attempt in attempts:
            errors.extend(attempt.errors)
        if provider_error is not None:
            errors.append(provider_error)
        if not attempts:
            errors.append(
                "no candidate schema was produced for the sample format"
            )
        return GenerationResult(
            signature=signature,
            accepted=False,
            attempts=attempts,
            errors=errors,
        )

    def _evaluate_candidate(
        self,
        candidate: Mapping[str, Any],
        *,
        origin: str,
        samples: list[str],
    ) -> GenerationAttempt:
        try:
            spec = SchemaSpec.model_validate(candidate)
        except Exception as error:  # noqa: BLE001 - candidate is untrusted
            return GenerationAttempt(
                origin=origin,
                candidate=dict(candidate),
                schema_spec=None,
                errors=[
                    f"candidate {origin} is not a valid "
                    f"SchemaSpec: {error}"
                ],
            )

        if self._timezone is not None:
            spec = spec.model_copy(update={
                "timestamp": spec.timestamp.model_copy(update={"timezone": self._timezone}),
            })
        if self._registry is not None:
            existing = self._registry.find_by_signature(build_signature(samples))
            version = (
                existing.schema_spec.version
                if existing is not None
                and existing.schema_spec.schema_id == spec.schema_id
                else self._registry.next_version(spec.schema_id)
            )
            spec = spec.model_copy(update={"version": version})

        try:
            pipeline = compile_pipeline(spec, samples=samples)
        except PipelineCompileError as error:
            return GenerationAttempt(
                origin=origin,
                candidate=dict(candidate),
                schema_spec=spec,
                errors=[f"compile failed: {error}"],
            )
        except SchemaGenerationError as error:
            return GenerationAttempt(
                origin=origin,
                candidate=dict(candidate),
                schema_spec=spec,
                errors=[f"compile failed: {error}"],
            )

        validation = validate_pipeline(spec, pipeline, samples)
        return GenerationAttempt(
            origin=origin,
            candidate=dict(candidate),
            schema_spec=spec,
            pipeline=pipeline,
            validation=validation,
            accepted=validation.accepted,
            errors=list(validation.errors),
        )

    @staticmethod
    def _result(
        signature: SourceSignature,
        attempts: list[GenerationAttempt],
        samples: list[str],
        provenance: dict[str, Any] | None = None,
    ) -> GenerationResult:
        winning = next(
            attempt for attempt in attempts if attempt.accepted
        )
        if winning.validation is None or winning.schema_spec is None:
            raise SchemaGenerationError(
                "accepted attempt is missing validation or schema"
            )
        if provenance is None:
            provenance = {
                "generator": "heuristic",
                "sample_hashes": sample_hashes(samples),
            }
        return GenerationResult(
            signature=signature,
            accepted=True,
            schema_spec=winning.schema_spec,
            pipeline=winning.pipeline,
            validation=winning.validation,
            provenance=Provenance.model_validate(provenance),
            attempts=attempts,
            errors=[],
        )

    def _provider_candidates(
        self,
        samples: list[str],
        dataset: str,
        signature: SourceSignature,
    ) -> tuple[str, list[Mapping[str, Any]]]:
        prompt_input = {
            "signature": signature.model_dump(mode="json"),
            "samples": sample_hashes(samples),
            "dataset": dataset,
        }
        canonical = json.dumps(
            prompt_input,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        prompt_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        prop = getattr(self._provider, "propose", None)
        if not callable(prop):
            raise SchemaGenerationError(
                "provider must implement CandidateProvider.propose"
            )
        try:
            proposed = prop(
                samples=samples,
                dataset_hint=dataset,
                signature=signature,
            )
        except Exception as error:  # noqa: BLE001 - provider is untrusted
            raise SchemaGenerationError(
                f"provider failed while proposing candidates: {error}"
            ) from error
        candidates: list[Mapping[str, Any]] = []
        for item in proposed:
            if isinstance(item, Mapping):
                candidates.append(dict(item))
        return prompt_hash, candidates


class SchemaResolver:
    """Combine signature lookup with generation for one onboarding attempt."""

    def __init__(
        self,
        registry: SchemaRegistry,
        *,
        provider: CandidateProvider | None = None,
        max_candidates: int = MAX_CANDIDATES,
        timezone: str | None = None,
    ) -> None:
        self._registry = registry
        self._generator = SchemaGenerator(
            provider=provider,
            max_candidates=max_candidates,
            registry=registry,
            timezone=timezone,
        )

    def resolve_or_generate(
        self,
        lines: Sequence[str],
        dataset_hint: str | None = None,
    ) -> SchemaResolution:
        signature = build_signature(lines)
        entry = self._registry.find_by_signature(signature)
        if entry is not None:
            return SchemaResolution(
                signature=signature,
                reused=True,
                entry=entry,
            )
        generation = self._generator.generate(lines, dataset_hint)
        return SchemaResolution(
            signature=signature,
            reused=False,
            generation=generation,
        )


def generate_schema(
    samples: Sequence[str],
    dataset_hint: str | None = None,
    *,
    provider: CandidateProvider | None = None,
    max_candidates: int = MAX_CANDIDATES,
    registry: SchemaRegistry | None = None,
    timezone: str | None = None,
) -> GenerationResult:
    """Convenience wrapper around :class:`SchemaGenerator.generate`."""

    return SchemaGenerator(
        provider=provider,
        max_candidates=max_candidates,
        registry=registry,
        timezone=timezone,
    ).generate(samples, dataset_hint)


def resolve_or_generate(
    lines: Sequence[str],
    dataset_hint: str | None = None,
    *,
    registry: SchemaRegistry | None = None,
    provider: CandidateProvider | None = None,
    max_candidates: int = MAX_CANDIDATES,
    timezone: str | None = None,
) -> SchemaResolution:
    """Contract-facing entry point used by B3 and the Batch 4 CLI."""

    if registry is None:
        raise SchemaGenerationError(
            "resolve_or_generate requires a SchemaRegistry"
        )
    return SchemaResolver(
        registry,
        provider=provider,
        max_candidates=max_candidates,
        timezone=timezone,
    ).resolve_or_generate(lines, dataset_hint)


def _prepare_samples(samples: Sequence[str]) -> list[str]:
    if isinstance(samples, (str, bytes)):
        raise SchemaGenerationError(
            "samples must be a sequence of strings, not one string"
        )
    lines: list[str] = []
    for index, line in enumerate(samples):
        if not isinstance(line, str):
            raise SchemaGenerationError(
                f"sample {index + 1} is not a string"
            )
        stripped = line.rstrip("\r\n")
        if not stripped.strip():
            continue
        if len(stripped) > MAX_SAMPLE_LINE_LENGTH:
            raise SchemaGenerationError(
                f"sample {index + 1} exceeds the "
                f"{MAX_SAMPLE_LINE_LENGTH}-character input bound"
            )
        lines.append(stripped)
    if not lines:
        raise SchemaGenerationError("no representative samples are available")
    return lines


def _normalize_dataset(value: str | None) -> str:
    if value is None or not value.strip():
        return "unknown.dataset"
    cleaned = value.strip().lower()
    if _SCHEMA_ID_RE.fullmatch(cleaned):
        return cleaned
    trimmed = re.sub(r"[^a-z0-9]+", "_", cleaned).strip("_")
    return trimmed or "unknown.dataset"


def _schema_id(dataset: str) -> str:
    prefix = "" if dataset.startswith("b2-") else "b2-"
    candidate = f"{prefix}{dataset}"
    if not _SCHEMA_ID_RE.fullmatch(candidate):
        candidate = re.sub(r"[^a-z0-9._-]+", "_", candidate)
        candidate = candidate[:64].strip("._-") or "b2-unknown"
    return candidate


def _guess_dataset(signature: SourceSignature) -> str | None:
    # Without an explicit hint the structural signature is the only evidence;
    # keep the deterministic placeholder so later attempts can refine it.
    return None


def _candidate(
    parser: Mapping[str, Any],
    timestamp: Mapping[str, Any],
    fields: Sequence[Mapping[str, Any]],
    dataset: str,
) -> dict[str, Any]:
    return {
        "schema_id": _schema_id(dataset),
        "version": 1,
        "dataset": dataset,
        "description": (
            f"Heuristically generated B2 schema for {dataset}"
        ),
        "parser": dict(parser),
        "timestamp": dict(timestamp),
        "fields": [dict(field) for field in fields],
    }


def _heuristic_candidates(
    lines: list[str],
    dataset: str,
) -> list[Mapping[str, Any]]:
    candidates: list[Mapping[str, Any]] = []

    json_paths = _json_field_hints(lines, dataset)
    candidates.extend(json_paths)

    csv_hints = _csv_field_hints(lines, dataset)
    candidates.extend(csv_hints)

    kv_hints = _kv_field_hints(lines, dataset)
    candidates.extend(kv_hints)
    return candidates


def _json_field_hints(
    lines: list[str],
    dataset: str,
) -> list[Mapping[str, Any]]:
    """Return bounded JSON candidates derived from the sample paths."""

    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            return []
        if isinstance(value, dict):
            records.append(value)
    if not records:
        return []

    keys: list[str] = []
    seen: set[str] = set()
    for record in records:
        for key in record:
            if key not in seen and _clean_source(key):
                keys.append(key)
                seen.add(key)
    if not keys:
        return []

    message_source = None
    for key in keys:
        if key.lower() in _MESSAGE_KEYS:
            message_source = key
            break
    timestamp_source, timestamp_formats = _pick_timestamp(
        keys,
        _json_value_of(records, keys),
    )
    if timestamp_source is None:
        return []

    fields: list[Mapping[str, Any]] = [
        {"target": "event.dataset", "constant": dataset},
        {"target": "event.original", "source": "$raw"},
    ]
    if message_source is not None:
        fields.append({"target": "message", "source": message_source})
    else:
        fields.append(
            {
                "target": "message",
                "constant": f"Generated record from {dataset}",
            }
        )

    for key in keys:
        if key in {timestamp_source, message_source}:
            continue
        mapped = _map_key(key)
        if mapped is None:
            continue
        values = [
            record[key]
            for record in records
            if key in record
        ]
        inferred = _infer_json_type(values)
        fields.append({"target": mapped, "source": key, "type": inferred})

    timestamp = {
        "source": timestamp_source,
        "formats": timestamp_formats[0],
    }
    parser = {"kind": "json"}
    return [
        _candidate(parser, timestamp, fields, dataset)
    ]


def _json_value_of(
    records: list[dict[str, Any]],
    keys: Sequence[str],
) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for key in keys:
        seen: list[str] = []
        for record in records:
            value = record.get(key)
            if value is None:
                continue
            seen.append(value if isinstance(value, str) else str(value))
        values[key] = seen
    return values


def _csv_field_hints(
    lines: list[str],
    dataset: str,
) -> list[Mapping[str, Any]]:
    if len(lines) < 2:
        return []
    for delimiter in (",", "\t", "|", ";"):
        header, rows = _csv_rows(lines, delimiter)
        if header is None:
            continue
        candidates = _layout_candidates(
            header,
            rows,
            parser={
                "kind": "csv",
                "delimiter": delimiter,
                "quotechar": '"',
                "has_header": True,
            },
            dataset=dataset,
        )
        if candidates:
            return candidates
    return []


def _kv_field_hints(
    lines: list[str],
    dataset: str,
) -> list[Mapping[str, Any]]:
    rows: list[dict[str, str]] = []
    keys: list[str] = []
    seen: set[str] = set()
    for line in lines:
        tokens = line.split()
        record: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                continue
            key, _, value = token.partition("=")
            cleaned = _clean_source(key)
            if not cleaned:
                continue
            if cleaned not in seen:
                seen.add(cleaned)
                keys.append(cleaned)
            record[cleaned] = value
        if record:
            rows.append(record)
    if len(rows) < 2 or not keys:
        return []
    return _layout_candidates(
        keys,
        rows,
        parser={"kind": "kv"},
        dataset=dataset,
    )


def _layout_candidates(
    keys: Sequence[str],
    rows: Sequence[Mapping[str, str]],
    parser: Mapping[str, Any],
    dataset: str,
) -> list[Mapping[str, Any]]:
    if not keys:
        return []
    message_source = None
    for key in keys:
        if key.lower() in _MESSAGE_KEYS:
            message_source = key
            break
    timestamp_source, timestamp_formats = _pick_timestamp(
        keys,
        _row_value_of(rows, keys),
    )
    if timestamp_source is None:
        return []
    candidates: list[Mapping[str, Any]] = []
    for formats in timestamp_formats:
        fields: list[Mapping[str, Any]] = [
            {"target": "event.dataset", "constant": dataset},
            {"target": "event.original", "source": "$raw"},
        ]
        if message_source is not None:
            fields.append({"target": "message", "source": message_source})
        else:
            fields.append(
                {
                    "target": "message",
                    "constant": f"Generated record from {dataset}",
                }
            )
        for key in keys:
            if key in {timestamp_source, message_source}:
                continue
            mapped = _map_key(key)
            if mapped is None:
                continue
            fields.append({"target": mapped, "source": key})
        candidates.append(
            _candidate(
                parser,
                {"source": timestamp_source, "formats": formats},
                fields,
                dataset,
            )
        )
    return candidates


def _row_value_of(
    rows: Sequence[Mapping[str, str]],
    keys: Sequence[str],
) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for key in keys:
        bucket: list[str] = []
        for row in rows:
            value = row.get(key)
            if value:
                bucket.append(value)
        values[key] = bucket
    return values


def _csv_rows(
    lines: list[str],
    delimiter: str,
) -> tuple[tuple[str, ...] | None, list[dict[str, str]]]:
    import csv as _csv

    try:
        parsed = list(_csv.reader(lines, delimiter=delimiter))
    except _csv.Error:
        return None, []
    if len(parsed) < 2:
        return None, []
    widths = {len(row) for row in parsed}
    if len(widths) != 1:
        return None, []
    width = widths.pop()
    if width < 2:
        return None, []
    header = tuple(
        _clean_source(cell) for cell in parsed[0]
    )
    if any(not cell for cell in header):
        return None, []
    if len(set(header)) != len(header):
        return None, []
    rows: list[dict[str, str]] = []
    for row in parsed[1:]:
        if len(row) != width:
            continue
        rows.append(dict(zip(header, row)))
    if not rows:
        return None, []
    return header, rows


def _pick_timestamp(
    keys: Sequence[str],
    values: Mapping[str, Sequence[str]],
) -> tuple[str | None, list[list[str]]]:
    for key in keys:
        if not _TIMESTAMP_HINT_RE.search(key.lower()):
            continue
        examples = values.get(key, [])
        if not examples:
            continue
        formats = _detect_timestamp_formats(examples)
        if not formats:
            continue
        return key, formats
    return None, []


_TIMESTAMP_FORMAT_PROFILES: tuple[tuple[str, ...], ...] = (
    ("ISO8601",),
    ("ISO8601", "yyyy-MM-dd HH:mm:ss"),
    ("ISO8601", "yyyy-MM-dd HH:mm:ss", "MMM d HH:mm:ss"),
)

_ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?$"
)


def _detect_timestamp_formats(examples: Sequence[str]) -> list[list[str]]:
    """Return at most a few candidate ES date format lists."""
    if not examples:
        return []
    iso_hits = sum(
        bool(_ISO8601_RE.match(value)) for value in examples
    )
    if iso_hits == len(examples):
        return [list(_TIMESTAMP_FORMAT_PROFILES[0])]
    return [list(formats) for formats in _TIMESTAMP_FORMAT_PROFILES[:3]]


def _map_key(key: str) -> str | None:
    normalized = _clean_source(key).lower()
    if not normalized:
        return None
    if normalized in _KEY_TARGETS:
        return dict(_KEY_TARGETS)[normalized].strip()
    for (
        (needle_one, needle_two),
        target,
    ) in _COMPOUND_KEY_TARGETS:
        if needle_one in normalized and needle_two in normalized:
            return target
    return None


# Compound heuristics follow the exact-target list. Same-key combinations map
# deterministically so the generator is reproducible on identical samples.
_COMPOUND_KEY_TARGETS: tuple[
    tuple[tuple[str, str], str], ...
] = (
    (("ip", "src"), "source.ip"),
    (("ip", "source"), "source.ip"),
    (("ip", "dst"), "destination.ip"),
    (("ip", "destination"), "destination.ip"),
    (("port", "src"), "source.port"),
    (("port", "source"), "source.port"),
    (("port", "dst"), "destination.port"),
    (("port", "destination"), "destination.port"),
    (("time", "start"), "@timestamp"),
    (("time", "end"), "@timestamp"),
)


def _infer_json_type(values: Sequence[Any]) -> str:
    present = [value for value in values if value is not None]
    if not present:
        return FieldType.STRING.value
    if all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in present
    ):
        return FieldType.INTEGER.value
    if all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in present
    ):
        return FieldType.FLOAT.value
    if all(
        isinstance(value, bool) for value in present
    ):
        return FieldType.BOOLEAN.value
    if all(
        isinstance(value, str) and _IP_VALUE_RE.match(value)
        for value in present
    ):
        return FieldType.IP.value
    if all(isinstance(value, str) for value in present):
        return FieldType.STRING.value
    return FieldType.STRING.value


def _clean_source(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip()
    return cleaned


def _provider_model_name(provider: Any) -> str | None:
    for attribute in ("model_name", "model", "name"):
        value = getattr(provider, attribute, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
