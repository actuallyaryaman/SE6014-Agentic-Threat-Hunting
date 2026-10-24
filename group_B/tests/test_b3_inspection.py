"""Source access boundaries and bounded sampling, without external services."""

import io
import json
import socket

import pytest
from pydantic import ValidationError

from group_B.agentic_ingestion import (
    InspectionPolicy, SourceInspectionError, SourceSpec, inspect_source,
)
from group_B.agentic_ingestion import inspect as inspection_module


@pytest.fixture
def source_file(tmp_path):
    path = tmp_path / "source.jsonl"
    path.write_text('\n'.join(json.dumps({
        "timestamp": "2026-10-24T12:00:00Z", "message": "private-test-record",
    }) for _ in range(5)))
    return path


def test_source_defaults_and_invalid_timezone():
    source = SourceSpec(kind="file", location="/logs/test")
    assert source.dry_run is True
    assert source.ingest_mode == "auto"
    with pytest.raises(ValidationError):
        SourceSpec(kind="file", location="/logs/test", timezone="invalid/zone")
    with pytest.raises(ValidationError):
        SourceSpec(kind="file", location="/logs/test", dry_run="false")


def test_file_inspection_excludes_raw_records_from_json(source_file, tmp_path):
    result = inspect_source(SourceSpec(kind="file", location=str(source_file)),
                            InspectionPolicy(allowed_roots=(tmp_path,)))
    assert result.sample_count == 5
    assert result.signature.kind.value == "json"
    assert result.timestamp.source == "timestamp"
    assert not result.timestamp.requires_timezone
    assert "private-test-record" not in result.model_dump_json()
    assert "private-test-record" in result.samples[0]


def test_file_sampling_stops_at_bound(source_file, tmp_path):
    result = inspect_source(SourceSpec(kind="file", location=str(source_file)),
                            InspectionPolicy(allowed_roots=(tmp_path,), max_samples=2))
    assert result.sample_count == 2
    assert result.sample_limit_reached


def test_denied_path_and_symlink_escape(source_file, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    link = allowed / "escape"
    link.symlink_to(source_file)
    policy = InspectionPolicy(allowed_roots=(allowed,))
    for location in (str(source_file), str(link), str(allowed / ".." / source_file.name)):
        with pytest.raises(SourceInspectionError):
            inspect_source(SourceSpec(kind="file", location=location), policy)


@pytest.mark.parametrize("content", [b"", b"\n \n", b"\xff\n", b"abc\x00\n", b"a" * 101])
def test_empty_binary_or_oversized_records_fail(tmp_path, content):
    path = tmp_path / "bad"
    path.write_bytes(content)
    with pytest.raises(SourceInspectionError):
        inspect_source(SourceSpec(kind="file", location=str(path)),
                       InspectionPolicy(allowed_roots=(tmp_path,), max_line_bytes=100))


def test_total_byte_limit_includes_empty_lines(tmp_path):
    path = tmp_path / "blanks"
    path.write_text("\n" * 100)
    with pytest.raises(SourceInspectionError, match="byte limit"):
        inspect_source(SourceSpec(kind="file", location=str(path)),
                       InspectionPolicy(allowed_roots=(tmp_path,), max_bytes=10))


def test_fifo_is_rejected_without_blocking(tmp_path):
    import os
    path = tmp_path / "pipe"
    os.mkfifo(path)
    with pytest.raises(SourceInspectionError, match="regular file"):
        inspect_source(SourceSpec(kind="file", location=str(path)),
                       InspectionPolicy(allowed_roots=(tmp_path,)))


def test_format_hint_is_checked(source_file, tmp_path):
    with pytest.raises(SourceInspectionError, match="format hint"):
        inspect_source(SourceSpec(kind="file", location=str(source_file), format_hint="csv"),
                       InspectionPolicy(allowed_roots=(tmp_path,)))


def test_symlink_swap_after_resolution_is_rejected(source_file, tmp_path, monkeypatch):
    original_open = inspection_module.os.open
    def swapped_open(path, flags, **kwargs):
        if path == source_file.name and kwargs.get("dir_fd") is not None:
            source_file.unlink()
            source_file.symlink_to(tmp_path / "other")
        return original_open(path, flags, **kwargs)
    monkeypatch.setattr(inspection_module.os, "open", swapped_open)
    with pytest.raises(SourceInspectionError):
        inspect_source(SourceSpec(kind="file", location=str(source_file)),
                       InspectionPolicy(allowed_roots=(tmp_path,)))


def test_event_timestamp_is_preferred_to_alarm_timestamp(tmp_path):
    path = tmp_path / "events"
    path.write_text(json.dumps({"alarm_time": "2026-10-24T13:00:00Z",
                                "event_time": "2026-10-24T12:00:00Z"}))
    result = inspect_source(SourceSpec(kind="file", location=str(path)),
                            InspectionPolicy(allowed_roots=(tmp_path,)))
    assert result.timestamp.source == "event_time"


@pytest.fixture
def http_source(monkeypatch):
    connections = []
    responses = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ])

    class Response(io.BytesIO):
        def __init__(self, status=200, headers=None, body=b"hello\n"):
            super().__init__(body)
            self.status = status
            self.headers = headers or {}

        def getheader(self, key, default=None):
            return self.headers.get(key, default)

    class Connection:
        def __init__(self, host, port, timeout):
            self.host, self.port = host, port
            self.closed = False
            self.sock = self
            connections.append(self)

        def connect(self):
            pass

        def settimeout(self, value):
            self.timeout = value

        def request(self, method, target, headers):
            self.request_data = method, target, headers

        def getresponse(self):
            return responses.pop(0)

        def close(self):
            self.closed = True

    monkeypatch.setattr(inspection_module.http.client, "HTTPConnection", Connection)
    return connections, responses, Response


def test_http_connections_are_pinned_and_host_header_preserved(http_source):
    connections, responses, response = http_source
    responses.append(response(body=b'{"timestamp":"2026-10-24T12:00:00Z","message":"ok"}\n'))
    result = inspect_source(SourceSpec(kind="http", location="http://logs.test:8080/logs?q=1"),
                            InspectionPolicy(allowed_hosts=("logs.test",)))
    assert result.sample_count == 1
    assert connections[0].host == "127.0.0.1"
    assert connections[0].port == 8080
    assert connections[0].request_data == (
        "GET", "/logs?q=1", {"Host": "logs.test:8080", "Accept-Encoding": "identity"},
    )
    assert connections[0].closed


def test_http_source_produces_a_push_plan(http_source, tmp_path):
    from group_B.agentic_ingestion import plan_source
    from group_B.common import FakeRecognizer, RecogniseResult
    from group_B.schema_generation import SchemaRegistry

    _, responses, response = http_source
    responses.append(response(body=b'{"timestamp":"2026-10-24T12:00:00Z","message":"ok"}\n'))
    plan = plan_source(
        SourceSpec(kind="http", location="http://logs.test/logs"),
        InspectionPolicy(allowed_hosts=("logs.test",)),
        recognizer=FakeRecognizer(RecogniseResult.unknown("unknown format")),
        registry=SchemaRegistry(tmp_path / "registry"),
    )
    assert plan.status == "planned"
    assert plan.ingest_mode == "push"
    assert plan.registration_required
    assert not (tmp_path / "registry").exists()


def test_https_preserves_sni_and_rejects_downgrade(http_source, monkeypatch):
    connections, responses, response = http_source
    names = []
    class Context:
        def wrap_socket(self, sock, *, server_hostname):
            names.append(server_hostname)
            return sock
    monkeypatch.setattr(inspection_module.ssl, "create_default_context", Context)
    responses.append(response(status=302, headers={"Location": "http://logs.test/logs"}))
    with pytest.raises(SourceInspectionError, match="downgrade"):
        inspect_source(SourceSpec(kind="http", location="https://logs.test/logs"),
                       InspectionPolicy(allowed_hosts=("logs.test",)))
    assert names == ["logs.test"]
    assert len(connections) == 1 and connections[0].closed


@pytest.mark.parametrize("target", [
    "http://evil.test/logs", "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd", "http://user:pass@logs.test/logs",
])
def test_redirects_recheck_permissions_before_connecting(http_source, target):
    connections, responses, response = http_source
    responses.append(response(status=302, headers={"Location": target}))
    with pytest.raises(SourceInspectionError):
        inspect_source(SourceSpec(kind="http", location="http://logs.test/logs"),
                       InspectionPolicy(allowed_hosts=("logs.test",)))
    assert len(connections) == 1
    assert connections[0].closed


def test_allowed_relative_redirect(http_source):
    connections, responses, response = http_source
    responses.extend([response(status=302, headers={"Location": "/new"}), response()])
    result = inspect_source(SourceSpec(kind="http", location="http://logs.test/old"),
                            InspectionPolicy(allowed_hosts=("logs.test",)))
    assert result.sample_count == 1
    assert connections[1].request_data[1] == "/new"
    assert all(c.closed for c in connections)


@pytest.mark.parametrize("address", ["169.254.169.254", "100.100.100.200", "0.0.0.0", "::ffff:169.254.169.254", "ff02::1"])
def test_forbidden_dns_addresses_even_when_host_allowlisted(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 80)),
    ])
    with pytest.raises(SourceInspectionError, match="forbidden address"):
        inspection_module.validate_url("http://logs.test", InspectionPolicy(allowed_hosts=("logs.test",)))


def test_compressed_or_failed_http_response_is_rejected(http_source):
    _, responses, response = http_source
    source = SourceSpec(kind="http", location="http://logs.test")
    policy = InspectionPolicy(allowed_hosts=("logs.test",))
    for item in (response(status=500), response(headers={"Content-Encoding": "gzip"})):
        responses.append(item)
        with pytest.raises(SourceInspectionError):
            inspect_source(source, policy)


def test_content_length_eof_does_not_touch_closed_socket():
    import http.client
    body = b"hello\n"
    class WireSocket:
        def makefile(self, *args):
            return io.BytesIO(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\n" + body)
    response = http.client.HTTPResponse(WireSocket())
    response.begin()
    def before_read():
        assert not response.isclosed(), "must not reset a closed socket"
    assert inspection_module._read_records(
        response, InspectionPolicy(), before_read=before_read,
    ) == ["hello"]


def test_stream_requires_samples_and_blocks_unbounded_blanks(http_source):
    source = SourceSpec(kind="stream", location="udp://logs.test:9999")
    policy = InspectionPolicy(allowed_hosts=("logs.test",), max_samples=1)
    with pytest.raises(SourceInspectionError, match="supplied"):
        inspect_source(source, policy)
    with pytest.raises(SourceInspectionError, match="empty"):
        inspect_source(source, policy, stream_samples=iter([""] * 101))
    result = inspect_source(source, policy, stream_samples=["hello"])
    assert result.sample_count == 1


@pytest.mark.parametrize("lines,fmt,needs_zone,needs_year", [
    (["timestamp,message", "2026-10-24T12:00:00,ok", "2026-10-24T12:01:00,hi"], "ISO8601", True, False),
    (["timestamp=2026-10-24T12:00:00Z msg=ok"], "ISO8601", False, False),
    (["type=EXECVE msg=audit(1604994492.123:42):"], "auditd", False, False),
    (['192.0.2.1 - - [24/Oct/2026:12:00:00 +0800] "GET / HTTP/1.1" 200 123'], "dd/MMM/yyyy:HH:mm:ss Z", False, False),
    (["Oct 24 12:00:00 host sshd: hello"], "syslog", True, True),
])
def test_timestamp_detection(tmp_path, lines, fmt, needs_zone, needs_year):
    path = tmp_path / "logs"
    path.write_text("\n".join(lines))
    result = inspect_source(SourceSpec(kind="file", location=str(path)),
                            InspectionPolicy(allowed_roots=(tmp_path,)))
    assert result.timestamp.format == fmt
    assert result.timestamp.requires_timezone is needs_zone
    assert result.timestamp.requires_year is needs_year
