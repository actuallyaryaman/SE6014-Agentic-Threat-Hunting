"""Explicit year policy must survive transport and detect stale indexed dates."""
import hashlib
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from group_B.common.errors import IngestionError
from group_B.agentic_ingestion.models import SourceSpec, InspectionPolicy
from group_B.agentic_ingestion.planner import plan_source
from group_B.agentic_ingestion.execution import envelopes, expected_syslog_timestamp
from group_B.agentic_ingestion.verify import check_documents
from group_B.common.recognizer import load_b1_recognizer


@pytest.mark.parametrize("year", [True, "2024", 1969, 10000])
def test_year_requires_bounded_integer(year):
    with pytest.raises(ValidationError):
        SourceSpec(kind="file", location="/tmp/source", log_year=year)


@pytest.mark.parametrize("year,zone,status", [(None, "UTC", "blocked"), (2024, None, "blocked"), (2024, "UTC", "planned")])
def test_onboarding_requires_confirmed_year_and_zone(tmp_path, year, zone, status):
    path = tmp_path / "auth.log"
    line = "Feb 29 00:15:00 host sshd[12]: Failed password for demo from 203.0.113.1 port 4000 ssh2"
    path.write_text(line + "\n" + line)
    source = SourceSpec(kind="file", location=str(path), log_year=year, timezone=zone)
    plan = plan_source(source, InspectionPolicy(allowed_roots=(tmp_path,)),
                       recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
                       known_pipelines={"linux_auth": "linux-auth"})
    assert plan.status == status, plan.reasons
    if status == "planned":
        records = envelopes(plan, (line, line), source, "run")
        assert len({r["event_id"] for r in records}) == 2
        assert all(r["labels"]["log_year"] == "2024" and r["labels"]["log_timezone"] == "UTC" for r in records)


def test_timezone_crosses_year_boundary():
    assert expected_syslog_timestamp("Jan  1 00:15:00 host rest", 2024, "Asia/Singapore") == datetime(2023, 12, 31, 16, 15, tzinfo=timezone.utc)


@pytest.mark.parametrize("line,year,zone", [("Feb 29 12:00:00 host rest", 2023, "UTC"),
    ("Nov  3 01:30:00 host rest", 2024, "America/New_York"),
    ("Mar 10 02:30:00 host rest", 2024, "America/New_York"), ("invalid", 2024, "UTC")])
def test_invalid_or_ambiguous_wall_time_rejected(line, year, zone):
    with pytest.raises((ValueError, IngestionError)):
        expected_syslog_timestamp(line, year, zone)


def test_verification_rejects_current_year_or_changed_policy():
    document = {"event_id": "id", "message": "original", "event": {"original": "original", "dataset": "linux.auth"},
                "@timestamp": "2026-02-28T00:00:00Z", "labels": {"source_id": "source", "log_year": "2024", "log_timezone": "UTC"}}
    class Store:
        def search(self, **kwargs):
            return {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_source": document}]}}
    args = dict(source_id="source", dataset="linux.auth", expected_timestamps={"id": datetime(2024, 2, 28, tzinfo=timezone.utc)},
                expected_labels={"log_year": "2024", "log_timezone": "UTC"})
    expected = {"id": hashlib.sha256(b"original").hexdigest()}
    assert check_documents(Store(), "index", expected, **args).invalid
    document["@timestamp"] = "2024-02-28T00:00:00Z"
    assert check_documents(Store(), "index", expected, **args).found == {"id"}
    document["labels"]["log_year"] = "2028"
    assert check_documents(Store(), "index", expected, **args).invalid


def test_invalid_date_after_sample_limit_fails_before_transport(tmp_path):
    from group_B.agentic_ingestion import onboard, ExecutionConfig
    path = tmp_path / "auth.log"
    valid = "Feb 28 00:15:00 host sshd[12]: Failed password for demo from 203.0.113.1 port 4000 ssh2"
    path.write_text("\n".join([valid] * 50 + [valid.replace("Feb 28", "Feb 29")]))
    source = SourceSpec(kind="file", location=str(path), log_year=2023, timezone="UTC", dry_run=False)
    result = onboard(source, InspectionPolicy(allowed_roots=(tmp_path,)),
                     ExecutionConfig(audit_path=tmp_path / "audit.jsonl"),
                     recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
                     known_pipelines={"linux_auth": "linux-auth"}, read_client=object(), write_client=object())
    assert result.status == "failed" and result.submitted_count == 0
