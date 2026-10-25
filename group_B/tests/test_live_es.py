"""Opt-in compatibility checks against an actual Elasticsearch endpoint."""

import os

import pytest

from group_B.schema_generation.compile_es import compile_pipeline
from group_B.schema_generation.generate import generate_schema, resolve_or_generate
from group_B.schema_generation.models import SchemaSpec
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.validate import validate_pipeline

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def live_es(request):
    if not request.config.option.markexpr or not os.environ.get("ES_URL"):
        pytest.skip("select -m integration and supply ES_URL for live checks")
    from elasticsearch import Elasticsearch

    options = {"request_timeout": 10, "max_retries": 0}
    api_key = os.environ.get("ES_WRITE_API_KEY") or os.environ.get("ES_API_KEY")
    if api_key:
        options["api_key"] = api_key
    if os.environ.get("ES_CA_CERT"):
        options["ca_certs"] = os.environ["ES_CA_CERT"]
    with Elasticsearch(os.environ["ES_URL"], **options) as client:
        yield client


@pytest.mark.parametrize(
    "kind", ["json", "csv", "kv", "auditd", "dissect", "grok", "regex"]
)
def test_compiled_pipeline_on_real_elasticsearch(
    kind, live_es, aws_schema, aws_lines, auditd_schema, auditd_lines,
):
    if kind == "auditd":
        schema, lines = auditd_schema, auditd_lines
    elif kind == "csv":
        schema, lines = aws_schema, aws_lines
    else:
        parser = {"kind": kind}
        if kind == "dissect":
            parser["pattern"] = "%{ts} %{msg}"
        elif kind == "grok":
            parser["pattern"] = "%{TIMESTAMP_ISO8601:ts} %{GREEDYDATA:msg}"
        elif kind == "regex":
            parser["pattern"] = r"^(?P<ts>\S+) (?P<msg>.*)$"
        schema = SchemaSpec.model_validate({
            "schema_id": f"live-{kind}", "dataset": "test.live",
            "parser": parser, "timestamp": {"source": "ts"},
            "fields": [
                {"target": "event.dataset", "constant": "test.live"},
                {"target": "event.original", "source": "$raw"},
                {"target": "message", "source": "msg"},
            ],
        })
        if kind == "json":
            line = '{"ts":"2026-10-24T12:00:00Z","msg":"hello"}'
        elif kind == "kv":
            line = "ts=2026-10-24T12:00:00Z msg=hello"
        else:
            line = "2026-10-24T12:00:00Z hello"
        lines = [line] * 5
    pipeline = compile_pipeline(schema, samples=lines)
    report = validate_pipeline(
        schema, pipeline, lines, mode="es_simulate", es_client=live_es,
    )
    assert report.accepted, report.errors
    assert report.mode == "es_simulate"
    assert report.parse_failure_count == 0

    # One good record plus a malformed record exercises real on_failure output.
    good_lines = lines[:2] if kind == "csv" else lines[:1]
    failure_lines = good_lines + ["not a valid record"]
    failure_report = validate_pipeline(
        schema, pipeline, failure_lines, mode="es_simulate", es_client=live_es,
    )
    assert failure_report.accepted, failure_report.errors
    assert failure_report.parse_failure_count == 1


@pytest.mark.parametrize("kind", ["json", "csv", "kv"])
def test_generated_schema_live_registration_and_reuse(kind, live_es, tmp_path):
    """Exercise real heuristic generation, live evidence, registration and reuse."""
    if kind == "json":
        lines = ['{"timestamp":"2026-10-24T12:00:00Z","message":"hello"}'] * 5
    elif kind == "csv":
        lines = ["timestamp,message"] + ["2026-10-24T12:00:00Z,hello"] * 5
    else:
        lines = ["timestamp=2026-10-24T12:00:00Z msg=hello"] * 5
    generated = generate_schema(lines, "test.generated")
    assert generated.accepted, generated.errors
    report = validate_pipeline(
        generated.schema_spec, generated.pipeline, lines,
        mode="es_simulate", es_client=live_es,
    )
    assert report.accepted, report.errors
    registry = SchemaRegistry(tmp_path / "registry")
    entry = registry.register(
        schema=generated.schema_spec, signature=generated.signature,
        pipeline=generated.pipeline, validation=report,
        provenance=generated.provenance, samples=lines, es_client=live_es,
    )
    assert entry.validation.mode == "es_simulate"
    assert entry.validation.accepted
    reused = resolve_or_generate(lines, registry=registry)
    assert reused.reused
    assert reused.entry.pipeline == generated.pipeline
    assert reused.pipeline_id == entry.pipeline_id


@pytest.mark.parametrize("kind", ["json", "csv", "json-with-parse-failure"])
def test_b3_execution_index_verify_and_replay(kind, live_es, tmp_path):
    """Install generated pipelines, index full snapshots and verify actual search hits."""
    import json
    from uuid import uuid4

    from group_B.agentic_ingestion import ExecutionConfig, InspectionPolicy, SourceSpec, onboard
    from group_B.common import FakeRecognizer, RecogniseResult

    prefix = "b3test-" + uuid4().hex[:12]
    path = tmp_path / "source.log"
    if kind == "csv":
        lines = ["timestamp,message"] + ["2026-10-24T12:00:00Z,hello"] * 121
    else:
        lines = [json.dumps({"timestamp": "2026-10-24T12:00:00Z", "message": "hello"})] * 121
        if kind == "json-with-parse-failure":
            lines[-1] = "not a valid JSON record"
    path.write_text("\n".join(lines))
    source = SourceSpec(kind="file", location=str(path), dataset_hint=prefix,
                        ingest_mode="direct_es", dry_run=False)
    policy = InspectionPolicy(allowed_roots=(tmp_path,))
    config = ExecutionConfig(index_prefix=prefix, search_pattern=prefix + "-*",
                             audit_path=tmp_path / "audit.jsonl", verify_attempts=2, verify_interval=0)
    options = dict(recognizer=FakeRecognizer(RecogniseResult.unknown("unknown")),
                   registry=SchemaRegistry(tmp_path / "registry"),
                   read_client=live_es, write_client=live_es)
    report = None
    try:
        report = onboard(source, policy, config, **options)
        assert report.status == "verified", report.model_dump()
        assert report.record_count == report.submitted_count == report.indexed_count == 121
        assert report.parse_failure_count == (1 if kind == "json-with-parse-failure" else 0)
        assert live_es.count(index=prefix + "-*")["count"] == 121
        repeated = onboard(source, policy, config, **options)
        assert repeated.status == "verified", repeated.model_dump()
        assert repeated.submitted_count == 0 and repeated.reused_count == 121
        assert live_es.count(index=prefix + "-*")["count"] == 121
        verified = onboard(source, policy, config, verify_only=True, **options)
        assert verified.status == "verified" and verified.submitted_count == 0
        audit = [json.loads(line) for line in config.audit_path.read_text().splitlines()]
        assert len(audit) == 6 and audit[-1]["status"] == "verified"
    finally:
        for index in live_es.indices.get(index=prefix + "-*", allow_no_indices=True):
            live_es.indices.delete(index=index)
        if report is not None and report.pipeline_id:
            live_es.ingest.delete_pipeline(id=report.pipeline_id)
