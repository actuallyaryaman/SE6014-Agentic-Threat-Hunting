"""Regressions for B2 pipeline compatibility and lifecycle integrity."""

import json

import pytest

from group_B.common.errors import RegistryError
from group_B.schema_generation import cli
from group_B.schema_generation.compile_es import PipelineSafetyError
from group_B.schema_generation.generate import generate_schema
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.validate import (
    simulate_pipeline,
    validate_pipeline_safety,
)


def samples(extra=False):
    record = {"timestamp": "2026-10-24T12:00:00Z", "message": "ok"}
    if extra:
        record["host"] = "host1"
    return [json.dumps(record)] * 5


def test_csv_grok_uses_elasticsearch_patterns():
    result = generate_schema(
        ["timestamp,message", "2026-10-24T12:00:00Z,ok"], "demo"
    )
    assert result.accepted
    grok = next(p["grok"] for p in result.pipeline["processors"] if "grok" in p)
    assert isinstance(grok["patterns"], list)
    assert "pattern" not in grok


def test_grok_tries_patterns_in_order():
    pipeline = {"processors": [{"grok": {
        "field": "message", "patterns": ["^first$", "^%{WORD:matched}$"]
    }}]}
    assert simulate_pipeline(pipeline, {"message": "second"})["matched"] == "second"


def test_processor_options_use_elasticsearch_config_location():
    pipeline = {"processors": [
        {"rename": {"field": "missing", "target_field": "renamed", "ignore_failure": True}},
        {"set": {"field": "done", "value": True}},
    ]}
    assert simulate_pipeline(pipeline, {"message": "ok"})["done"] is True
    generated = generate_schema(samples(), "demo").pipeline
    assert generated["on_failure"][2]["set"]["ignore_failure"] is True


def test_safety_checks_nested_processor_failure_handlers():
    with pytest.raises(PipelineSafetyError, match="forbidden processor"):
        validate_pipeline_safety({"processors": [{"set": {
            "field": "message", "value": "ok",
            "on_failure": [{"script": {"source": "ctx.bad = true"}}],
        }}]})


def test_nested_processor_failure_handler_runs():
    pipeline = {"processors": [{"rename": {
        "field": "missing", "target_field": "renamed",
        "on_failure": [{"set": {"field": "handled", "value": True}}],
    }}]}
    assert simulate_pipeline(pipeline, {"message": "ok"})["handled"] is True


@pytest.mark.parametrize("config", [
    {"pattern": "^ok$"},
    {"patterns": []},
    {"patterns": ["^ok$", "(a+)+$"]},
    {"patterns": "^ok$"},
])
def test_grok_rejects_invalid_or_unsafe_pattern_lists(config):
    with pytest.raises(PipelineSafetyError):
        validate_pipeline_safety({"processors": [{"grok": {
            "field": "message", **config
        }}]})


def test_registry_rejects_pipeline_modified_after_validation(tmp_path):
    result = generate_schema(samples(), "demo")
    with pytest.raises(RegistryError, match="pipeline"):
        SchemaRegistry(tmp_path).register(
            schema=result.schema_spec, signature=result.signature,
            pipeline={"processors": [{"drop": {}}]},
            validation=result.validation, provenance=result.provenance,
            samples=samples(),
        )
    assert not (tmp_path / "schemas").exists()


def test_registry_rejects_changed_samples(tmp_path):
    result = generate_schema(samples(), "demo")
    with pytest.raises(RegistryError, match="signature"):
        SchemaRegistry(tmp_path).register(
            schema=result.schema_spec, signature=result.signature,
            pipeline=result.pipeline, validation=result.validation,
            provenance=result.provenance, samples=samples(extra=True),
        )
    assert not (tmp_path / "schemas").exists()


def test_cli_allocates_versions_and_reuses_both(tmp_path, capsys):
    registry = ["--registry", str(tmp_path / "registry")]
    for version, extra in ((1, False), (2, True)):
        path = tmp_path / f"samples{version}.jsonl"
        path.write_text("\n".join(samples(extra)))
        assert cli.main(registry + ["resolve", str(path), "--dataset", "demo", "--register"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["registered"]["version"] == version
        assert f"v{version}" in result["pipeline"]["description"]
    for version in (1, 2):
        assert cli.main(registry + ["resolve", str(tmp_path / f"samples{version}.jsonl")]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["reused"]
        assert result["registered"]["version"] == version


def test_emit_failure_has_no_success_output(tmp_path, capsys):
    path = tmp_path / "samples.jsonl"
    path.write_text("\n".join(samples()))
    assert cli.main(["generate", str(path), "--emit", str(tmp_path / "missing" / "bundle.json")]) != 0
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["ok"] is False


@pytest.mark.parametrize("mutation", ["pipeline", "signature", "schema", "validation", "provenance"])
def test_register_bundle_rejects_invalid_nested_content(tmp_path, capsys, mutation):
    path = tmp_path / "samples.jsonl"
    path.write_text("\n".join(samples()))
    bundle = tmp_path / "bundle.json"
    registry = ["--registry", str(tmp_path / "registry")]
    assert cli.main(registry + ["generate", str(path), "--emit", str(bundle)]) == 0
    capsys.readouterr()
    data = json.loads(bundle.read_text())
    if mutation == "pipeline":
        data["pipeline"] = {"processors": [{"drop": {}}]}
    elif mutation == "signature":
        data["signature"]["hash"] = "a" * 64
    elif mutation == "schema":
        data["schema_spec"]["fields"] = []
    elif mutation == "validation":
        data["validation"]["sample_count"] = 0
    else:
        data["provenance"]["generator"] = "invalid"
    bundle.write_text(json.dumps(data))
    assert cli.main(registry + ["register", str(bundle), str(path)]) != 0
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["ok"] is False
    assert not (tmp_path / "registry" / "schemas").exists()


def test_registration_stores_fresh_report_and_hashes(tmp_path):
    result = generate_schema(samples(), "demo")
    changed = [line.replace('"ok"', '"different"') for line in samples()]
    # Same structural signature, different values and available sample count.
    changed = changed[:2]
    entry = SchemaRegistry(tmp_path).register(
        schema=result.schema_spec, signature=result.signature,
        pipeline=result.pipeline, validation=result.validation,
        provenance=result.provenance, samples=changed,
    )
    assert entry.validation.sample_count == 2
    assert entry.signature.sample_count == 2
    assert entry.provenance.sample_hashes != result.provenance.sample_hashes


def test_registration_revalidates_same_shape_with_bad_timestamp(tmp_path):
    result = generate_schema(samples(), "demo")
    bad = [line.replace("2026-10-24T12:00:00Z", "invalid") for line in samples()]
    with pytest.raises(RegistryError, match="fresh sample validation"):
        SchemaRegistry(tmp_path).register(
            schema=result.schema_spec, signature=result.signature,
            pipeline=result.pipeline, validation=result.validation,
            provenance=result.provenance, samples=bad,
        )
    assert not (tmp_path / "schemas").exists()


def test_emit_allocates_version_before_bundle_registration(tmp_path, capsys):
    path = tmp_path / "samples.jsonl"
    registry = ["--registry", str(tmp_path / "registry")]
    path.write_text("\n".join(samples()))
    assert cli.main(registry + ["generate", str(path), "--dataset", "demo", "--register"]) == 0
    capsys.readouterr()
    path.write_text("\n".join(samples(extra=True)))
    bundle = tmp_path / "bundle.json"
    assert cli.main(registry + ["generate", str(path), "--dataset", "demo", "--emit", str(bundle)]) == 0
    capsys.readouterr()
    assert json.loads(bundle.read_text())["schema_spec"]["version"] == 2
    assert cli.main(registry + ["register", str(bundle), str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["registered"]["version"] == 2


def test_live_report_cannot_be_registered_without_fresh_live_validation(tmp_path):
    result = generate_schema(samples(), "demo")
    with pytest.raises(RegistryError, match="revalidate"):
        SchemaRegistry(tmp_path).register(
            schema=result.schema_spec, signature=result.signature,
            pipeline=result.pipeline,
            validation=result.validation.model_copy(update={"mode": "es_simulate"}),
            provenance=result.provenance, samples=samples(),
        )
    assert not (tmp_path / "schemas").exists()


def test_cli_model_errors_omit_input_values(tmp_path, capsys):
    path = tmp_path / "samples.jsonl"
    path.write_text("\n".join(samples()))
    bundle = tmp_path / "bundle.json"
    assert cli.main(["generate", str(path), "--emit", str(bundle)]) == 0
    capsys.readouterr()
    data = json.loads(bundle.read_text())
    data["schema_spec"]["version"] = "private-log-content"
    bundle.write_text(json.dumps(data))
    assert cli.main(["register", str(bundle), str(path)]) != 0
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["ok"] is False
    assert "private-log-content" not in output.err
