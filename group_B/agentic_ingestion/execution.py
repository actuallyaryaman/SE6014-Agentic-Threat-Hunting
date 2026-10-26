"""Execute a captured source with live pipeline validation and independent verification."""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from uuid import uuid4

from elasticsearch import Elasticsearch

from group_B.common.errors import ConfigurationError, GroupBError, IngestionError
from group_B.schema_generation.models import CsvParser
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.validate import validate_pipeline

from .adapters import DirectESAdapter, FileDropAdapter, HttpPushAdapter, UdpStreamAdapter, Receipt
from .audit import AuditError, AuditLog
from .inspect import capture_source
from .models import ExecutionConfig, ExecutionReport
from .planner import plan_inspection
from .verify import check_documents, verify_documents


class PipelineError(IngestionError):
    code = "PIPELINE_PREPARATION_FAILED"


def es_client_from_env(role):
    url = os.environ.get("ES_URL")
    key = os.environ.get("ES_READ_API_KEY" if role == "read" else "ES_WRITE_API_KEY")
    if not url or not key:
        raise ConfigurationError(f"ES_URL and the {role} API key are required")
    if os.environ.get("ES_VERIFY_CERTS", "true").lower() != "true":
        raise ConfigurationError("TLS certificate verification cannot be disabled")
    options = {"api_key": key, "request_timeout": 5, "max_retries": 0}
    if os.environ.get("ES_CA_CERT"):
        options["ca_certs"] = os.environ["ES_CA_CERT"]
    return Elasticsearch(url, **options)


def event_id(source_id, ordinal, line):
    payload = json.dumps([source_id, ordinal, line], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def envelopes(plan, lines, source, run_id):
    resolution = plan.schema_resolution
    schema = None
    if resolution is not None:
        schema = (resolution.entry.schema_spec if resolution.entry is not None
                  else resolution.generation.schema_spec)
    has_header = (isinstance(schema.parser, CsvParser) and schema.parser.has_header
                  if schema is not None else
                  plan.inspection.signature.shape.get("has_header", False))
    records = []
    for ordinal, line in enumerate(lines):
        if has_header and ordinal == 0:
            continue
        identifier = event_id(plan.inspection.source_id, ordinal, line)
        record = {
            "message": line, "event_id": identifier, "event": {"id": identifier},
            "labels": {"source_id": plan.inspection.source_id, "run_id": run_id,
                       "ingest_mode": plan.ingest_mode, "ingest_pipeline": plan.pipeline_id},
        }
        if plan.inspection.timestamp and plan.inspection.timestamp.requires_year:
            record["labels"].update(log_year=str(source.log_year), log_timezone=source.timezone)
            # Validate every record, including those beyond the inspection sample.
            expected_syslog_timestamp(line, source.log_year, source.timezone)
        if source.host_name:
            record["host"] = {"name": source.host_name}
        records.append(record)
    if not records:
        raise IngestionError("source contains no data records after its header")
    return records


def expected_syslog_timestamp(line, year, zone):
    prefix = re.match(r"^[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}", line)
    if prefix is None:
        raise IngestionError("yearless source contains a record without a syslog timestamp")
    parsed = datetime.strptime(f"{year} {prefix.group()}", "%Y %b %d %H:%M:%S")
    local = parsed.replace(tzinfo=ZoneInfo(zone))
    # Ambiguous/nonexistent wall times need an offset or operator correction.
    alternate = local.replace(fold=1)
    if local.utcoffset() != alternate.utcoffset():
        raise IngestionError("ambiguous or nonexistent local timestamp requires an explicit offset")
    return local.astimezone(timezone.utc)


def prepare_pipeline(plan, registry, client):
    resolution = plan.schema_resolution
    candidate = None
    if resolution is not None:
        candidate = resolution.entry or resolution.generation
        schema = candidate.schema_spec
        pipeline = candidate.pipeline
        report = validate_pipeline(schema, pipeline, plan.inspection.samples,
                                   mode="es_simulate", es_client=client)
        if not report.accepted:
            raise PipelineError("live sample validation rejected the pipeline")
    try:
        existing = client.ingest.get_pipeline(id=plan.pipeline_id)
        existing = existing.body if hasattr(existing, "body") else existing
        existing = existing[plan.pipeline_id]
    except Exception as error:
        if getattr(error, "status_code", None) != 404:
            raise PipelineError("could not check the installed pipeline") from error
        if candidate is None:
            raise PipelineError("the approved known-format pipeline is not installed") from error
        existing = None
    if candidate is not None:
        if existing is not None and any(
            existing.get(key) != pipeline.get(key) for key in ("processors", "on_failure")
        ):
            raise PipelineError("installed pipeline conflicts with the validated candidate")
        if existing is None:
            try:
                client.ingest.put_pipeline(id=plan.pipeline_id, body=pipeline)
            except Exception as error:
                raise PipelineError("could not install the validated pipeline") from error
        if resolution.entry is None:
            registry.register(
                schema=schema, signature=resolution.signature, pipeline=pipeline,
                validation=report, provenance=candidate.provenance,
                samples=plan.inspection.samples, es_client=client,
            )


def onboard(source, policy, config: ExecutionConfig, *, recognizer=None,
            known_pipelines=None, registry=None, schema_provider=None,
            route_advisor=None, read_client=None, write_client=None,
            adapter=None, audit=None, verify_only=False):
    """Capture once; never trust an externally serialized or stale plan.

    Dry runs perform no output, registry, pipeline or Elasticsearch writes.
    Verification uses preserved logical event_id rather than transport _id.
    """
    run_id = str(uuid4())
    source_id = "b3-" + hashlib.sha256(source.location.encode()).hexdigest()[:24]
    effective_dry_run = source.dry_run and not verify_only
    audit = audit or AuditLog(config.audit_path)
    owned = []
    state = dict(run_id=run_id, source_id=source_id, status="failed",
                 ingest_mode=source.ingest_mode, dry_run=effective_dry_run)
    audit_started = False

    def finish(status, *codes):
        report = ExecutionReport(**dict(state, status=status, error_codes=tuple(codes)))
        if audit_started:
            try:
                audit.write(dict(report.model_dump(mode="json"), event="completed"))
            except AuditError:
                report = report.model_copy(update={"status": "failed",
                                                   "error_codes": report.error_codes + ("AUDIT_WRITE_FAILED",)})
        return report

    try:
        if not effective_dry_run:
            audit.write({"event": "started", "run_id": run_id, "source_id": source_id,
                         "operation": "verify" if verify_only else "onboard"})
            audit_started = True
        if source.kind == "stream":
            return finish("blocked", "STREAM_CONTRACT_UNRESOLVED")
        inspection, lines = capture_source(source, policy, max_records=config.max_records,
                                            max_bytes=config.max_bytes)
        state["source_id"] = source_id = inspection.source_id
        plan = plan_inspection(source, inspection, recognizer=recognizer,
                               known_pipelines=known_pipelines, registry=registry,
                               schema_provider=schema_provider, route_advisor=route_advisor)
        state.update(ingest_mode=plan.ingest_mode, pipeline_id=plan.pipeline_id,
                     dataset=plan.dataset, warnings=plan.warnings)
        if plan.status == "blocked":
            state["warnings"] = plan.reasons + plan.warnings
            return finish("blocked", "PLAN_BLOCKED")
        records = envelopes(plan, lines, source, run_id)
        state["record_count"] = len(records)
        if effective_dry_run:
            return finish("dry_run")
        state["warnings"] = tuple(w for w in plan.warnings if not w.startswith((
            "Indexing and", "Pipeline validation is offline", "The generated schema",
            "The selected pipeline",
        )))
        if read_client is None:
            read_client = es_client_from_env("read")
            owned.append(read_client)
        expected = {record["event_id"]: hashlib.sha256(record["message"].encode()).hexdigest()
                    for record in records}
        yearless = bool(plan.inspection.timestamp and plan.inspection.timestamp.requires_year)
        verification_policy = dict(
            expected_timestamps={r["event_id"]: expected_syslog_timestamp(r["message"], source.log_year, source.timezone)
                                 for r in records} if yearless else None,
            expected_labels={"log_year": str(source.log_year), "log_timezone": source.timezone} if yearless else None,
        )
        before = check_documents(read_client, config.search_pattern, expected,
                                 source_id=source_id, dataset=plan.dataset, **verification_policy)
        state.update(indexed_count=len(before.found), parse_failure_count=before.parse_failures)
        if before.unavailable:
            return finish("unverified", "ES_VERIFICATION_UNAVAILABLE")
        if before.invalid:
            return finish("failed", "EXISTING_DOCUMENT_CONFLICT")
        if verify_only:
            return finish("verified" if len(before.found) == len(expected) else "failed",
                          *(() if len(before.found) == len(expected) else ("VERIFICATION_FAILED",)))
        state["reused_count"] = len(before.found)
        pending = [record for record in records if record["event_id"] not in before.found]
        receipt = Receipt()
        if pending:
            if write_client is None:
                write_client = es_client_from_env("write")
                owned.append(write_client)
            writable_registry = registry or SchemaRegistry()
            prepare_pipeline(plan, writable_registry, write_client)
            if adapter is None:
                if plan.ingest_mode == "pull":
                    adapter = FileDropAdapter(config.incoming_dir)
                elif plan.ingest_mode == "stream":
                    adapter = UdpStreamAdapter(config.a3_udp_url)
                elif plan.ingest_mode == "push":
                    adapter = HttpPushAdapter(config.push_url, timeout=config.timeout_seconds)
                else:
                    adapter = DirectESAdapter(write_client, config.index_prefix)
            receipt = adapter.handoff(plan, pending)
            state.update(submitted_count=receipt.submitted, acknowledged_count=receipt.acknowledged)
        after = verify_documents(read_client, config.search_pattern, expected,
                                 source_id=source_id, dataset=plan.dataset,
                                 attempts=config.verify_attempts, interval=config.verify_interval, **verification_policy)
        state.update(indexed_count=len(after.found), parse_failure_count=after.parse_failures)
        if after.unavailable:
            return finish("unverified", "ES_VERIFICATION_UNAVAILABLE",
                          *(("TRANSPORT_FAILED",) if receipt.failed else ()))
        if receipt.failed or after.invalid or len(after.found) != len(expected):
            codes = []
            if receipt.failed:
                codes.append("TRANSPORT_FAILED")
            if after.invalid or len(after.found) != len(expected):
                codes.append("VERIFICATION_FAILED")
            return finish("failed", *codes)
        return finish("verified")
    except (GroupBError, OSError, ValueError, TypeError) as error:
        return finish("failed", getattr(error, "code", "EXECUTION_FAILED"))
    finally:
        for client in owned:
            client.close()
