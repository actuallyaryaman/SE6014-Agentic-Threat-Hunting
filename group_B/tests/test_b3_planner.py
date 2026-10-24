"""Planning must preserve source permissions and never execute ingestion."""

import json
from pathlib import Path

import pytest

from group_B.agentic_ingestion import InspectionPolicy, SourceSpec, plan_source
from group_B.agentic_ingestion import cli
from group_B.agentic_ingestion.llm import OpenRouterRouteAdvisor
from group_B.common import FakeRecognizer, RecogniseResult
from group_B.common.errors import RegistryError
from group_B.schema_generation import SchemaRegistry, generate_schema


@pytest.fixture
def setup_source(tmp_path):
    path = tmp_path / "source.jsonl"
    lines = [json.dumps({"timestamp": "2026-10-24T12:00:00Z", "message": "private-record"})] * 5
    path.write_text("\n".join(lines))
    return SourceSpec(kind="file", location=str(path), dataset_hint="demo"), InspectionPolicy(allowed_roots=(tmp_path,)), lines


def unknown():
    return FakeRecognizer(RecogniseResult.unknown("unknown format"))


def test_unknown_file_produces_plan_without_registry_writes(tmp_path, setup_source):
    source, policy, _ = setup_source
    registry = SchemaRegistry(tmp_path / "registry")
    plan = plan_source(source, policy, recognizer=unknown(), registry=registry)
    assert plan.status == "planned"
    assert plan.ingest_mode == "pull"
    assert plan.registration_required and not plan.schema_reused
    assert plan.validation_mode == "offline"
    assert plan.schema_resolution.generation.schema_spec.pipeline_id == plan.pipeline_id
    assert plan.dry_run and plan.verification_required
    assert not registry.root.exists()
    assert "private-record" not in plan.model_dump_json()
    assert "schema_resolution" not in plan.model_dump()


def test_reuse_missing_index_does_not_rebuild_it(tmp_path, setup_source):
    source, policy, lines = setup_source
    registry = SchemaRegistry(tmp_path / "registry")
    result = generate_schema(lines, "demo")
    entry = registry.register(schema=result.schema_spec, signature=result.signature,
                              pipeline=result.pipeline, validation=result.validation,
                              provenance=result.provenance, samples=lines)
    registry.index_path.unlink()
    before = {p: p.read_bytes() for p in registry.root.rglob("*.json")}
    plan = plan_source(source, policy, recognizer=unknown(), registry=registry)
    assert plan.schema_reused and plan.pipeline_id == entry.pipeline_id
    assert plan.status == "planned"
    assert {p: p.read_bytes() for p in registry.root.rglob("*.json")} == before
    assert not registry.index_path.exists()
    with pytest.raises(RegistryError, match="read-only"):
        SchemaRegistry(registry.root, read_only=True).rebuild_index()


def test_not_configured_is_not_treated_as_a_format_miss(setup_source):
    source, policy, _ = setup_source
    plan = plan_source(source, policy)
    assert plan.status == "blocked"
    assert plan.pipeline_id is None
    assert any("not configured" in reason for reason in plan.reasons)


def test_known_pipeline_requires_approved_mapping(setup_source):
    source, policy, _ = setup_source
    source = source.model_copy(update={"dataset_hint": None})
    recognizer = FakeRecognizer(RecogniseResult(
        matched=True, format_id="known", dataset="known.data", pipeline_id="known-pipeline",
    ))
    assert plan_source(source, policy, recognizer=recognizer).status == "blocked"
    plan = plan_source(source, policy, recognizer=recognizer,
                       known_pipelines={"known": "known-pipeline"})
    assert plan.status == "planned"
    assert plan.dataset == "known.data"
    assert not plan.registration_required


def test_naive_timestamps_need_explicit_timezone(setup_source):
    source, policy, _ = setup_source
    path = Path(source.location)
    path.write_text(path.read_text().replace("00Z", "00"))
    blocked = plan_source(source, policy, recognizer=unknown())
    assert blocked.status == "blocked"
    assert any("timezone" in reason for reason in blocked.reasons)
    explicit = source.model_copy(update={"timezone": "Asia/Singapore"})
    assert plan_source(explicit, policy, recognizer=unknown()).status == "planned"


@pytest.mark.parametrize("reply,expected", [
    ('{"ingest_mode":"push"}', "push"),
    ('{"ingest_mode":"direct_es"}', "pull"),
    ('{"ingest_mode":"push","pipeline_id":"attacker"}', "pull"),
    ("not JSON", "pull"),
])
def test_optional_route_advice_is_constrained(setup_source, reply, expected):
    source, policy, _ = setup_source
    prompts = []
    def inference(system, user):
        prompts.append(user)
        return reply
    advisor = OpenRouterRouteAdvisor(inference=inference)
    plan = plan_source(source, policy, recognizer=unknown(), route_advisor=advisor)
    assert plan.ingest_mode == expected
    assert all("private-record" not in prompt and source.location not in prompt for prompt in prompts)
    assert plan.status == "planned"


def test_explicit_route_and_dry_run_are_not_overridden(setup_source):
    source, policy, _ = setup_source
    source = source.model_copy(update={"ingest_mode": "push", "dry_run": False})
    def forbidden(*args):
        pytest.fail("advisor must not override explicit mode")
    plan = plan_source(source, policy, recognizer=unknown(),
                       route_advisor=OpenRouterRouteAdvisor(inference=forbidden))
    assert plan.ingest_mode == "push"
    assert not plan.dry_run
    assert plan.verification_required


def test_cli_inspection_and_blocked_plan(tmp_path, setup_source, monkeypatch, capsys):
    source, _, _ = setup_source
    monkeypatch.setenv("B3_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("B1_RECOGNIZER", raising=False)
    assert cli.main(["inspect", source.location, "--kind", "file"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["sample_count"] == 5
    assert "samples" not in result
    assert cli.main(["plan", source.location, "--kind", "file"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    assert cli.main(["inspect", "/not/allowed", "--kind", "file"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["ok"] is False


def test_registered_pipeline_is_checked_against_current_values(tmp_path, setup_source):
    source, policy, lines = setup_source
    registry = SchemaRegistry(tmp_path / "registry")
    result = generate_schema(lines, "demo")
    registry.register(schema=result.schema_spec, signature=result.signature,
                      pipeline=result.pipeline, validation=result.validation,
                      provenance=result.provenance, samples=lines)
    # Same JSON key/type structure, but an unparseable event timestamp.
    Path(source.location).write_text("\n".join(line.replace("2026-10-24T12:00:00Z", "bad") for line in lines))
    plan = plan_source(source, policy, recognizer=unknown(), registry=registry)
    assert plan.schema_reused
    assert plan.status == "blocked"
    assert any("current samples" in reason for reason in plan.reasons)


def test_read_only_registry_refuses_registration(tmp_path, setup_source):
    _, _, lines = setup_source
    result = generate_schema(lines, "demo")
    with pytest.raises(RegistryError, match="read-only"):
        SchemaRegistry(tmp_path / "registry", read_only=True).register(
            schema=result.schema_spec, signature=result.signature,
            pipeline=result.pipeline, validation=result.validation,
            provenance=result.provenance, samples=lines,
        )
    assert not (tmp_path / "registry").exists()


def test_timezone_change_does_not_silently_reuse_old_policy(tmp_path, setup_source):
    source, policy, lines = setup_source
    lines = [line.replace("00Z", "00") for line in lines]
    Path(source.location).write_text("\n".join(lines))
    registry = SchemaRegistry(tmp_path / "registry")
    result = generate_schema(lines, "demo", timezone="UTC")
    assert result.accepted
    registry.register(schema=result.schema_spec, signature=result.signature,
                      pipeline=result.pipeline, validation=result.validation,
                      provenance=result.provenance, samples=lines)
    source = source.model_copy(update={"timezone": "Asia/Singapore"})
    plan = plan_source(source, policy, recognizer=unknown(), registry=registry)
    assert plan.status == "blocked"
    assert any("timezone conflicts" in reason for reason in plan.reasons)


def test_opaque_b1_evidence_does_not_leak_into_json(setup_source):
    source, policy, _ = setup_source
    recognizer = FakeRecognizer(RecogniseResult.unknown(
        "unknown format", raw_excerpt="private-record",
    ))
    plan = plan_source(source, policy, recognizer=recognizer)
    assert "private-record" not in plan.model_dump_json()
    assert plan.recognition.evidence["raw_excerpt"] == "private-record"
