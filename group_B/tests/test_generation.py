"""Batch 3 tests for the agentic candidate generation loop."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from group_B.common.errors import SchemaGenerationError
from group_B.schema_generation import (
    CandidateProvider,
    GenerationResult,
    OpenRouterCandidateProvider,
    SchemaDetector,
    SchemaRegistry,
    SchemaResolver,
    generate_schema,
    resolve_or_generate,
)
from group_B.schema_generation.models import (
    FieldSpec,
    FieldType,
    Provenance,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)
from group_B.schema_generation.signature import SourceSignature


JSON_SAMPLES = [
    '{"timestamp": "2025-03-18T02:34:01.5620726Z", "src_ip": "10.0.0.4", "user": "alice", "message": "login ok"}',
    '{"timestamp": "2025-03-18T02:35:01.5620726Z", "src_ip": "10.0.0.5", "user": "bob", "message": "login ok"}',
    '{"timestamp": "2025-03-18T02:36:01.5620726Z", "src_ip": "10.0.0.6", "user": "carol", "message": "login ok"}',
    '{"timestamp": "2025-03-18T02:37:01.5620726Z", "src_ip": "10.0.0.7", "user": "dave", "message": "login ok"}',
    '{"timestamp": "2025-03-18T02:38:01.5620726Z", "src_ip": "10.0.0.8", "user": "erin", "message": "login ok"}',
]

CSV_SAMPLES = [
    "timestamp,src_ip,destination_ip,user,message",
    "2025-03-18T02:34:01Z,10.0.0.4,10.0.0.9,alice,login ok",
    "2025-03-18T02:35:01Z,10.0.0.5,10.0.0.9,bob,login failed",
    "2025-03-18T02:36:01Z,10.0.0.6,10.0.0.9,carol,login ok",
    "2025-03-18T02:37:01Z,10.0.0.7,10.0.0.9,dave,login ok",
    "2025-03-18T02:38:01Z,10.0.0.8,10.0.0.9,erin,login ok",
]

KV_SAMPLES = [
    "msg=login ok user=alice timestamp=2025-03-18T02:34:01Z src_ip=10.0.0.4",
    "msg=login failed user=bob timestamp=2025-03-18T02:35:01Z src_ip=10.0.0.5",
    "msg=login ok user=carol timestamp=2025-03-18T02:36:01Z src_ip=10.0.0.6",
    "msg=login ok user=dave timestamp=2025-03-18T02:37:01Z src_ip=10.0.0.7",
    "msg=login ok user=erin timestamp=2025-03-18T02:38:01Z src_ip=10.0.0.8",
]

SYSLINE_SAMPLES = [
    "2025-03-18T02:34:01Z alpha sshd: login ok by alice from 10.0.0.4",
    "2025-03-18T02:35:01Z bravo sshd: login ok by bob from 10.0.0.5",
    "2025-03-18T02:36:01Z charlie sshd: login ok by carol from 10.0.0.6",
    "2025-03-18T02:37:01Z delta sshd: login ok by dave from 10.0.0.7",
    "2025-03-18T02:38:01Z echo sshd: login ok by erin from 10.0.0.8",
]


class RecordingCandidateProvider:
    """Deterministic provider double that records its inputs."""

    def __init__(
        self,
        candidates: list[dict[str, Any]],
        model_name: str = "test-provider-model",
    ) -> None:
        self.candidates = candidates
        self.calls: list[dict[str, Any]] = []
        self.model = model_name

    def propose(
        self,
        *,
        samples: list[str],
        dataset_hint: str | None,
        signature: SourceSignature,
    ) -> list[dict[str, Any]]:
        self.calls.append(
            {
                "samples": list(samples),
                "dataset_hint": dataset_hint,
                "signature_hash": signature.hash,
            }
        )
        return self.candidates


@pytest.fixture
def recording_provider() -> RecordingCandidateProvider:
    return RecordingCandidateProvider(candidates=[])


def test_json_source_is_generated() -> None:
    result = generate_schema(JSON_SAMPLES, "test.json")
    assert result.accepted is True
    assert result.schema_spec is not None
    assert result.provenance is not None
    assert result.provenance.generator == "heuristic"
    assert result.validation is not None
    assert result.validation.parse_failure_count == 0


def test_csv_source_is_generated() -> None:
    result = generate_schema(CSV_SAMPLES, "test.csv")
    assert result.accepted is True
    assert result.schema_spec is not None
    assert result.provenance is not None
    assert result.provenance.generator == "heuristic"
    assert result.validation is not None
    assert result.validation.parse_failure_count == 0


def test_kv_source_is_generated() -> None:
    result = generate_schema(KV_SAMPLES, "test.kv")
    assert result.accepted is True
    assert result.schema_spec is not None
    assert result.provenance is not None
    assert result.provenance.generator == "heuristic"
    assert result.validation is not None
    assert result.validation.parse_failure_count == 0


def test_unknown_line_format_without_provider_is_rejected() -> None:
    result = generate_schema(SYSLINE_SAMPLES, "test.syslog")
    assert result.accepted is False
    assert result.errors
    assert any(
        "no candidate schema" in message for message in result.errors
    )


def test_provider_candidate_is_accepted_with_llm_provenance() -> None:
    provider = RecordingCandidateProvider(
        candidates=[
            {
                "schema_id": "sysline-v1",
                "version": 1,
                "dataset": "sysline",
                "description": "syslog regex candidates",
                "parser": {
                    "kind": "regex",
                    "pattern": (
                        r"(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) "
                        r"(?P<host>\S+) sshd: login ok by (?P<user>\S+) "
                        r"from (?P<input_ip>\d+\.\d+\.\d+\.\d+)"
                    ),
                },
                "timestamp": {"source": "time", "formats": ["ISO8601"]},
                "fields": [
                    {"target": "event.dataset", "constant": "sysline"},
                    {"target": "event.original", "source": "$raw"},
                    {"target": "message", "source": "$raw"},
                    {"target": "event.action", "source": "$raw"},
                    {"target": "user.name", "source": "user"},
                    {"target": "source.ip", "source": "input_ip"},
                ],
            }
        ]
    )
    result = generate_schema(SYSLINE_SAMPLES, "test.syslog", provider=provider)
    assert result.accepted
    assert result.provenance is not None
    assert result.provenance.generator == "llm"
    assert result.provenance.model == "test-provider-model"
    assert result.provenance.prompt_hash
    assert result.provenance.sample_hashes
    assert provider.calls


def test_provider_offline_openrouter_adapter_parses_json_array() -> None:
    def inference(system: str, user: str) -> str:
        return json.dumps(
            [
                {
                    "schema_id": "sysline-v1",
                    "version": 1,
                    "dataset": "sysline",
                    "description": "syslog regex",
                    "parser": {
                        "kind": "regex",
                        "pattern": r"(?P<message>login)",
                    },
                    "timestamp": {"source": "$raw"},
                    "fields": [
                        {"target": "event.dataset", "constant": "sysline"},
                        {"target": "event.original", "source": "$raw"},
                        {"target": "message", "source": "message"},
                    ],
                }
            ]
        )

    provider = OpenRouterCandidateProvider(
        inference=inference,
        model="openrouter/test",
    )
    proposed = provider.propose(
        samples=CSV_SAMPLES,
        dataset_hint="test.csv",
        signature=None,  # type: ignore[arg-type]
    )
    assert len(proposed) == 1
    assert proposed[0]["schema_id"] == "sysline-v1"


def test_provider_malformed_json_returns_no_candidates() -> None:
    provider = OpenRouterCandidateProvider(inference=lambda system, user: "not json")
    proposed = provider.propose(
        samples=CSV_SAMPLES,
        dataset_hint="test.csv",
        signature=None,  # type: ignore[arg-type]
    )
    assert proposed == []


def test_from_env_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(SchemaGenerationError):
        OpenRouterCandidateProvider.from_env()


def test_resolver_reuses_registered_schema(tmp_path: Path) -> None:
    resolver = SchemaResolver(SchemaRegistry(tmp_path))
    resolution = resolver.resolve_or_generate(CSV_SAMPLES, "test.csv")
    assert resolution.generation is not None
    assert resolution.generation.accepted

    generation = resolution.generation
    assert generation.provenance is not None
    assert generation.schema_spec is not None
    assert generation.validation is not None
    entry = SchemaRegistry(tmp_path).register(
        samples=CSV_SAMPLES,
        schema=generation.schema_spec,
        signature=resolution.signature,
        pipeline=generation.pipeline,
        validation=generation.validation,
        provenance=generation.provenance,
    )

    second = resolver.resolve_or_generate(CSV_SAMPLES, "test.csv")
    assert second.reused is True
    assert second.generation is None
    assert second.entry is not None
    assert second.entry.pipeline_id == entry.pipeline_id


def test_generated_schema_round_trips_through_registry_and_detector(
    tmp_path: Path,
) -> None:
    generation = generate_schema(JSON_SAMPLES, "test.json")
    assert generation.accepted

    registry = SchemaRegistry(tmp_path)
    assert generation.schema_spec is not None
    assert generation.pipeline is not None
    assert generation.validation is not None
    assert generation.provenance is not None
    entry = registry.register(
        samples=JSON_SAMPLES,
        schema=generation.schema_spec,
        signature=generation.signature,
        pipeline=generation.pipeline,
        validation=generation.validation,
        provenance=generation.provenance,
    )

    detector = SchemaDetector(registry)
    detection = detector.detect(JSON_SAMPLES)
    assert detection.known
    assert detection.entry is not None
    assert detection.entry.pipeline_id == entry.pipeline_id

    resolver = SchemaResolver(registry)
    resolution = resolver.resolve_or_generate(JSON_SAMPLES, "test.json")
    assert resolution.reused is True
    assert resolution.entry is not None
    assert resolution.entry.pipeline_id == entry.pipeline_id
