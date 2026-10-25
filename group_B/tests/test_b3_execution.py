"""Execution boundaries: no writes by default, transport receipts are not success."""

import copy
import json
import os
from types import SimpleNamespace

import httpx
import pytest

from group_B.agentic_ingestion import ExecutionConfig, InspectionPolicy, SourceSpec, onboard
from group_B.agentic_ingestion import cli, execution
from group_B.agentic_ingestion.execution import prepare_pipeline as prepare_pipeline_original
from group_B.agentic_ingestion.adapters import DirectESAdapter, FileDropAdapter, HttpPushAdapter, Receipt, TransportError
from group_B.agentic_ingestion.audit import AuditError, AuditLog
from group_B.common import FakeRecognizer, RecogniseResult
from group_B.schema_generation.registry import SchemaRegistry


class SearchStore:
    def __init__(self):
        self.documents = []
        self.unavailable = False
        self.searches = 0

    def search(self, **options):
        self.searches += 1
        if self.unavailable:
            raise ConnectionError("private connection detail")
        ids = options["query"]["bool"]["filter"][0]["bool"]["should"][0]["terms"]["event_id"]
        hits = [{"_id": "a2-fingerprint-" + str(i), "_source": d}
                for i, d in enumerate(self.documents) if d.get("event_id") in ids]
        return {"hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits[:options["size"]]}}


class IndexingAdapter:
    def __init__(self, store, *, acknowledge_only=False, failed=False):
        self.store, self.acknowledge_only, self.failed = store, acknowledge_only, failed
        self.calls = 0
        self.records = []

    def handoff(self, plan, records):
        self.calls += 1
        self.records.extend(copy.deepcopy(records))
        if not self.acknowledge_only:
            for record in records:
                document = copy.deepcopy(record)
                document["event"]["original"] = record["message"]
                document["event"]["dataset"] = plan.dataset
                document["@timestamp"] = "2026-10-24T12:00:00Z"
                self.store.documents.append(document)
        return Receipt(len(records), len(records), self.failed)


@pytest.fixture
def run(tmp_path, monkeypatch):
    path = tmp_path / "source.jsonl"
    path.write_text("\n".join(json.dumps({"timestamp": "2026-10-24T12:00:00Z", "message": "private record"}) for _ in range(80)))
    source = SourceSpec(kind="file", location=str(path), dataset_hint="test.execution", ingest_mode="direct_es", dry_run=False)
    policy = InspectionPolicy(allowed_roots=(tmp_path,))
    config = ExecutionConfig(audit_path=tmp_path / "audit.jsonl", verify_attempts=1, verify_interval=0)
    store = SearchStore()
    adapter = IndexingAdapter(store)
    prepared = []
    monkeypatch.setattr(execution, "prepare_pipeline", lambda *args: prepared.append(args))
    options = dict(recognizer=FakeRecognizer(RecogniseResult.unknown("unknown")),
                   registry=SchemaRegistry(tmp_path / "registry"), read_client=store,
                   write_client=object(), adapter=adapter)

    def invoke(**changes):
        return onboard(changes.pop("source", source), policy, changes.pop("config", config), **dict(options, **changes))
    return SimpleNamespace(call=invoke, source=source, path=path, config=config, store=store,
                           adapter=adapter, prepared=prepared, root=tmp_path)


def test_dry_run_has_no_output_or_clients(run):
    result = run.call(source=run.source.model_copy(update={"dry_run": True}))
    assert result.status == "dry_run" and result.record_count == 80
    assert not run.config.audit_path.exists() and not (run.root / "registry").exists()
    assert not run.prepared and not run.adapter.calls and not run.store.searches


def test_complete_snapshot_then_replay_and_verify_without_transport(run):
    first = run.call()
    assert first.status == "verified" and first.indexed_count == first.submitted_count == 80
    assert len({r["event_id"] for r in run.adapter.records}) == 80
    assert all(r["event"]["id"] == r["event_id"] for r in run.adapter.records)
    second = run.call()
    assert second.status == "verified" and second.reused_count == 80 and second.submitted_count == 0
    assert run.adapter.calls == 1 and len(run.store.documents) == 80
    verified = run.call(verify_only=True)
    assert verified.status == "verified" and run.adapter.calls == 1
    audit = run.config.audit_path.read_text()
    assert "private record" not in audit and str(run.path) not in audit
    assert len(audit.splitlines()) == 6


def test_http_acknowledgement_is_not_indexing_success(run):
    result = run.call(adapter=IndexingAdapter(run.store, acknowledge_only=True))
    assert result.status == "failed" and result.acknowledged_count == 80 and result.indexed_count == 0
    assert "VERIFICATION_FAILED" in result.error_codes


def test_read_outage_prevents_transport_and_pipeline_writes(run):
    run.store.unavailable = True
    result = run.call()
    assert result.status == "unverified" and result.error_codes == ("ES_VERIFICATION_UNAVAILABLE",)
    assert not run.prepared and not run.adapter.calls
    assert "private connection detail" not in result.model_dump_json()


def test_duplicate_ids_across_indices_fail_before_resubmission(run):
    assert run.call().status == "verified"
    run.store.documents.append(copy.deepcopy(run.store.documents[0]))
    result = run.call()
    assert result.status == "failed" and result.error_codes == ("EXISTING_DOCUMENT_CONFLICT",)
    assert run.adapter.calls == 1


@pytest.mark.parametrize("field,value", [("source", "wrong"), ("dataset", "wrong"),
                                         ("original", "changed"), ("time", "2026-10-24T12:00:00"),
                                         ("message", ""), ("failure", None)])
def test_required_document_evidence_is_checked(run, field, value):
    assert run.call().status == "verified"
    doc = run.store.documents[0]
    if field == "source":
        doc["labels"]["source_id"] = value
    elif field in {"dataset", "original"}:
        doc["event"][field] = value
    elif field == "time":
        doc["@timestamp"] = value
    elif field == "failure":
        doc["tags"] = ["_parse_failure"]
    else:
        doc[field] = value
    assert run.call().error_codes == ("EXISTING_DOCUMENT_CONFLICT",)


def test_parse_failures_with_contract_fields_are_counted(run):
    assert run.call().status == "verified"
    run.store.documents[0].update(tags=["_parse_failure"], error={"message": "bad record"})
    result = run.call(verify_only=True)
    assert result.status == "verified" and result.parse_failure_count == 1


def test_record_cap_rejects_source_instead_of_ingesting_sample(run):
    result = run.call(config=run.config.model_copy(update={"max_records": 60}))
    assert result.status == "failed" and not run.prepared and not run.adapter.calls


def test_csv_header_is_not_an_event(run):
    run.path.write_text("timestamp,message\n" + "2026-10-24T12:00:00Z,hello\n" * 6)
    result = run.call()
    assert result.status == "verified" and result.record_count == 6
    assert all(r["message"] != "timestamp,message" for r in run.adapter.records)


def test_audit_failure_before_and_after_submission(run):
    class BrokenAudit:
        def __init__(self, fail_at):
            self.calls, self.fail_at = 0, fail_at
        def write(self, event):
            self.calls += 1
            if self.calls == self.fail_at:
                raise AuditError("disk full")
    result = run.call(audit=BrokenAudit(1))
    assert result.error_codes == ("AUDIT_WRITE_FAILED",) and not run.adapter.calls
    result = run.call(audit=BrokenAudit(2))
    assert result.status == "failed" and result.indexed_count == 80
    assert result.error_codes == ("AUDIT_WRITE_FAILED",)


def test_verify_missing_does_not_install_or_submit(run):
    result = run.call(verify_only=True)
    assert result.status == "failed" and result.indexed_count == 0
    assert not run.prepared and not run.adapter.calls


def test_transport_failure_is_not_hidden_by_indexing(run):
    result = run.call(adapter=IndexingAdapter(run.store, failed=True))
    assert result.status == "failed" and result.indexed_count == 80
    assert result.error_codes == ("TRANSPORT_FAILED",)


def test_file_drop_atomic_publication_and_no_source_mutation(tmp_path):
    plan = SimpleNamespace(dry_run=False, status="planned", ingest_mode="pull")
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    records = [{"message": "raw", "event_id": "abc"}]
    receipt = FileDropAdapter(incoming).handoff(plan, records)
    assert receipt == Receipt(1, 1)
    paths = list(incoming.iterdir())
    assert len(paths) == 1 and paths[0].suffix == ".ndjson"
    assert json.loads(paths[0].read_text()) == records[0]
    assert paths[0].stat().st_mode & 0o777 == 0o600
    link = tmp_path / "link"
    link.symlink_to(incoming, target_is_directory=True)
    with pytest.raises(TransportError):
        FileDropAdapter(link).handoff(plan, records)


def test_audit_rejects_symlink_and_fifo(tmp_path):
    original = tmp_path / "original"
    original.write_text("preserve")
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(AuditError):
        AuditLog(link).write({"event": "started"})
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(AuditError):
        AuditLog(fifo).write({"event": "started"})
    assert original.read_text() == "preserve"


def test_http_stops_on_partial_failure_without_automatic_retry():
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(202 if len(requests) == 1 else 503)
    plan = SimpleNamespace(dry_run=False, status="planned", ingest_mode="push")
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        receipt = HttpPushAdapter("http://localhost:8088", client=client).handoff(plan, [{"message": "x"}] * 3)
    assert receipt == Receipt(2, 1, True) and len(requests) == 2


def test_direct_bulk_partial_failure_counts_all_successful_items():
    class Client:
        def bulk(self, **kwargs):
            assert kwargs["pipeline"] == "approved" and kwargs["refresh"] == "wait_for"
            return {"errors": True, "items": [{"index": {"status": status, "_id": str(i)}}
                                              for i, status in enumerate([201, 400, 201])]}
    plan = SimpleNamespace(dry_run=False, status="planned", ingest_mode="direct_es", pipeline_id="approved")
    receipt = DirectESAdapter(Client(), "test").handoff(plan, [{"event_id": str(i)} for i in range(3)])
    assert receipt == Receipt(3, 2, True)


@pytest.mark.parametrize("adapter,mode", [(FileDropAdapter(None), "pull"),
                                           (HttpPushAdapter("http://localhost"), "push"),
                                           (DirectESAdapter(None, "test"), "direct_es")])
def test_adapters_cannot_execute_dry_run(adapter, mode):
    with pytest.raises(TransportError):
        adapter.handoff(SimpleNamespace(dry_run=True, status="planned", ingest_mode=mode), [])


def test_cli_onboard_defaults_to_dry_run(run, monkeypatch, capsys):
    monkeypatch.setenv("B3_ALLOWED_ROOTS", str(run.root))
    monkeypatch.setattr(cli, "load_b1_recognizer", lambda _: FakeRecognizer(RecogniseResult.unknown("unknown")))
    code = cli.main(["onboard", str(run.path), "--kind", "file", "--b1", "fake", "--dataset", "test.cli", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result["dry_run"] and result["status"] == "dry_run"
    assert not run.config.audit_path.exists()



def test_existing_pipeline_conflict_never_overwrites(run, monkeypatch):
    from group_B.agentic_ingestion.planner import plan_source
    from group_B.agentic_ingestion.execution import PipelineError
    plan = plan_source(run.source, InspectionPolicy(allowed_roots=(run.root,)),
                       recognizer=FakeRecognizer(RecogniseResult.unknown("unknown")),
                       registry=SchemaRegistry(run.root / "registry"))
    candidate = plan.schema_resolution.generation
    monkeypatch.setattr(execution, "validate_pipeline", lambda *a, **kw: candidate.validation)
    class Ingest:
        def get_pipeline(self, **kwargs):
            return {plan.pipeline_id: {"processors": [{"remove": {"field": "message"}}]}}
        def put_pipeline(self, **kwargs):
            pytest.fail("must never overwrite a conflicting pipeline")
    with pytest.raises(PipelineError, match="conflicts"):
        prepare_pipeline_original(plan, SchemaRegistry(run.root / "registry"), SimpleNamespace(ingest=Ingest()))
    assert not (run.root / "registry").exists()


def test_pipeline_rejected_by_live_validation_is_not_installed(run, monkeypatch):
    from group_B.agentic_ingestion.planner import plan_source
    from group_B.agentic_ingestion.execution import PipelineError
    plan = plan_source(run.source, InspectionPolicy(allowed_roots=(run.root,)),
                       recognizer=FakeRecognizer(RecogniseResult.unknown("unknown")))
    monkeypatch.setattr(execution, "validate_pipeline", lambda *a, **kw: SimpleNamespace(accepted=False))
    with pytest.raises(PipelineError, match="live sample validation"):
        prepare_pipeline_original(plan, None, object())


def test_known_pipeline_must_already_be_installed(run):
    from group_B.agentic_ingestion.planner import plan_source
    from group_B.agentic_ingestion.execution import PipelineError
    plan = plan_source(run.source, InspectionPolicy(allowed_roots=(run.root,)),
                       recognizer=FakeRecognizer(RecogniseResult(matched=True, format_id="known",
                           dataset="test.execution", pipeline_id="approved")),
                       known_pipelines={"known": "approved"})
    class Missing(Exception):
        status_code = 404
    class Ingest:
        def get_pipeline(self, **kwargs):
            raise Missing()
    with pytest.raises(PipelineError, match="not installed"):
        prepare_pipeline_original(plan, None, SimpleNamespace(ingest=Ingest()))
