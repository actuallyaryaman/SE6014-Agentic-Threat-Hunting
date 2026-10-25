"""Bounded source inspection with explicit path and host permissions."""

from __future__ import annotations

import csv
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import time
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from group_B.common.errors import IngestionError
from group_B.schema_generation.signature import build_signature

from .models import InspectionPolicy, SourceInspection, SourceSpec, TimestampCandidate


class SourceInspectionError(IngestionError):
    code = "SOURCE_INSPECTION_FAILED"


def _open_file(location: str, policy: InspectionPolicy):
    """Resolve symlinks, then walk the permitted root using no-follow dirfds."""
    try:
        path = Path(location).expanduser().resolve(strict=True)
        roots = [root.expanduser().resolve(strict=True) for root in policy.allowed_roots]
        root = next((root for root in roots if path.is_relative_to(root)), None)
        if root is None or path == root:
            raise SourceInspectionError("file is outside the permitted roots")
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = path.relative_to(root).parts
            for part in parts[:-1]:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
                os.close(directory)
                directory = child
            descriptor = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
        finally:
            os.close(directory)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise SourceInspectionError("source must be a regular file")
        return os.fdopen(descriptor, "rb"), str(path)
    except SourceInspectionError:
        raise
    except (OSError, ValueError, RuntimeError) as error:
        raise SourceInspectionError("could not open an allowed source file") from error


def _host_key(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def validate_url(location: str, policy: InspectionPolicy, *, stream=False):
    """Return a validated URL and resolved addresses, before any connection."""
    try:
        parsed = urlsplit(location)
        schemes = {"udp"} if stream else {"http", "https"}
        if parsed.scheme not in schemes or not parsed.hostname:
            raise SourceInspectionError("unsupported source URL scheme or host")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise SourceInspectionError("source URLs cannot contain credentials or fragments")
        if any(ord(c) < 33 for c in location) or "\\" in location or "%" in parsed.hostname:
            raise SourceInspectionError("invalid source URL")
        host = _host_key(parsed.hostname)
        allowed = {_host_key(h) for h in policy.allowed_hosts}
        if host not in allowed:
            raise SourceInspectionError("source host is not allowlisted")
        if host in {"metadata.google.internal", "metadata.goog", "instance-data"}:
            raise SourceInspectionError("cloud metadata sources are forbidden")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if stream and (parsed.port is None or parsed.path not in ("", "/") or parsed.query):
            raise SourceInspectionError("stream sources require udp://host:port")
        if not 1 <= port <= 65535:
            raise SourceInspectionError("invalid source port")
        addresses = sorted({
            item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        })
        if not addresses:
            raise SourceInspectionError("source host has no addresses")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if (ip.is_link_local or ip.is_multicast or ip.is_unspecified
                    or ip.is_reserved or str(ip) == "100.100.100.200"):
                raise SourceInspectionError("source resolves to a forbidden address")
        return parsed, host, port, addresses
    except SourceInspectionError:
        raise
    except (OSError, ValueError, UnicodeError) as error:
        raise SourceInspectionError("could not validate source URL") from error


def _read_records(reader, policy: InspectionPolicy, deadline: float | None = None,
                  before_read=None, *, max_records=None, max_bytes=None):
    record_limit = max_records if max_records is not None else policy.max_samples
    byte_limit = max_bytes if max_bytes is not None else policy.max_bytes
    lines = []
    consumed = 0
    pending = b""
    ended = False
    while len(lines) < record_limit:
        if deadline is not None and time.monotonic() > deadline:
            raise SourceInspectionError("source inspection exceeded its time limit")
        # HTTPResponse closes its socket as soon as Content-Length is consumed.
        # Do not touch that socket or attempt another read after this point.
        if getattr(reader, "isclosed", lambda: False)():
            ended = True
        if b"\n" not in pending and not ended:
            if before_read is not None:
                before_read()
            chunk = reader.read1(min(4096, byte_limit - consumed + 1))
            consumed += len(chunk)
            if consumed > byte_limit:
                raise SourceInspectionError("source sampling exceeded its byte limit")
            pending += chunk
            ended = not chunk
            if b"\n" not in pending and not ended:
                if len(pending) > policy.max_line_bytes + 1:
                    raise SourceInspectionError("source record exceeds its line limit")
                continue
        if not pending:
            break
        raw, separator, rest = pending.partition(b"\n")
        pending = rest if separator else b""
        raw = raw.rstrip(b"\r\n")
        if len(raw) > policy.max_line_bytes:
            raise SourceInspectionError("source record exceeds its line limit")
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SourceInspectionError("source records must be UTF-8 text") from error
        if "\x00" in line:
            raise SourceInspectionError("binary source records are unsupported")
        if line.strip():
            lines.append(line)
    if not lines:
        raise SourceInspectionError("source has no usable records")
    return lines


def _http_samples(location: str, policy: InspectionPolicy, **limits):
    # Resolve every redirect, pin the validated IP, and keep TLS SNI/Host tied
    # to the original hostname. Environment proxies and DNS rebinding cannot
    # change the peer after validation.
    deadline = time.monotonic() + policy.timeout_seconds
    for hop in range(policy.max_redirects + 1):
        parsed, host, port, addresses = validate_url(location, policy)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SourceInspectionError("HTTP inspection exceeded its time limit")
        connection = http.client.HTTPConnection(addresses[0], port, timeout=remaining)
        try:
            connection.connect()
            if parsed.scheme == "https":
                connection.sock = ssl.create_default_context().wrap_socket(
                    connection.sock, server_hostname=host,
                )
            peer = connection.sock
            authority = f"[{host}]" if ":" in host else host
            default_port = 443 if parsed.scheme == "https" else 80
            if port != default_port:
                authority += f":{port}"
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            connection.request("GET", target, headers={
                "Host": authority, "Accept-Encoding": "identity",
            })
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                redirect = response.getheader("Location")
                if not redirect or hop == policy.max_redirects:
                    raise SourceInspectionError("HTTP redirect limit or missing target")
                next_location = urljoin(location, redirect)
                if parsed.scheme == "https" and urlsplit(next_location).scheme != "https":
                    raise SourceInspectionError("HTTPS source redirects cannot downgrade TLS")
                location = next_location
                continue
            if response.status != 200:
                raise SourceInspectionError("HTTP source did not return status 200", status=response.status)
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise SourceInspectionError("compressed HTTP sources are unsupported")
            def before_read():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SourceInspectionError("HTTP inspection exceeded its time limit")
                peer.settimeout(remaining)
            return _read_records(response, policy, deadline, before_read, **limits), location
        except SourceInspectionError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as error:
            raise SourceInspectionError("could not read the HTTP source") from error
        finally:
            connection.close()
    raise SourceInspectionError("HTTP redirect limit exceeded")


def _timestamp(lines: list[str], signature) -> TimestampCandidate | None:
    records = []
    if signature.kind.value == "json":
        def flatten(value, prefix=""):
            result = {}
            for key, item in value.items():
                path = f"{prefix}.{key}" if prefix else key
                if isinstance(item, dict):
                    result.update(flatten(item, path))
                else:
                    result[path] = item
            return result
        records = [flatten(json.loads(line)) for line in lines]
    elif signature.kind.value == "csv" and signature.shape.get("has_header"):
        records = list(csv.DictReader(lines, delimiter=signature.shape["delimiter"]))
    elif signature.kind.value == "kv":
        records = [dict(re.findall(r'(\S+)=("[^"]*"|\S+)', line)) for line in lines]
    keys = list(records[0]) if records else []
    def timestamp_rank(key):
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in {"timestamp", "ts", "utctime", "systemtime"}:
            return 0, key
        if re.search(r"event.*(?:date|time)", normalized):
            return 1, key
        return (2 if re.search(r"timestamp|date|time", normalized) else 3), key
    keys.sort(key=timestamp_rank)
    for key in keys:
        values = [row.get(key) for row in records]
        parsed = []
        try:
            for value in values:
                if not isinstance(value, str):
                    raise ValueError
                parsed.append(datetime.fromisoformat(value.strip('"').replace("Z", "+00:00")))
        except ValueError:
            continue
        if parsed:
            return TimestampCandidate(
                source=key, format="ISO8601",
                requires_timezone=any(p.tzinfo is None for p in parsed),
            )
    audit = r"audit\([0-9]+(?:\.[0-9]+)?:[0-9]+\):"
    if all(re.search(audit, line) for line in lines):
        return TimestampCandidate(source="msg", format="auditd")
    apache = [re.search(
        r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]", line,
    ) for line in lines]
    if all(apache):
        try:
            for match in apache:
                datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        return TimestampCandidate(source="$raw", format="dd/MMM/yyyy:HH:mm:ss Z")
    iso = r"^\d{4}-\d{2}-\d{2}T\S+"
    if all(re.match(iso, line) for line in lines):
        try:
            parsed = [datetime.fromisoformat(line.split()[0].replace("Z", "+00:00")) for line in lines]
        except ValueError:
            return None
        return TimestampCandidate(source="$raw", format="ISO8601 prefix",
                                  requires_timezone=any(p.tzinfo is None for p in parsed))
    if all(re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s", line) for line in lines):
        return TimestampCandidate(source="$raw", format="syslog",
                                  requires_timezone=True, requires_year=True)
    return None


def inspect_source(source: SourceSpec, policy: InspectionPolicy, *,
                   stream_samples: Iterable[str] | None = None) -> SourceInspection:
    if source.kind == "file":
        stream, identity = _open_file(source.location, policy)
        with stream:
            lines = _read_records(stream, policy)
    elif source.kind == "http":
        lines, identity = _http_samples(source.location, policy)
    else:
        validate_url(source.location, policy, stream=True)
        if stream_samples is None:
            raise SourceInspectionError("stream inspection requires supplied sample records")
        if isinstance(stream_samples, (str, bytes)):
            raise SourceInspectionError("stream samples must be an iterable of records")
        lines = []
        consumed = 0
        for index, line in enumerate(stream_samples):
            if index >= policy.max_samples * 100:
                raise SourceInspectionError("too many empty stream sample records")
            if not isinstance(line, str) or "\n" in line.rstrip("\r\n") or "\x00" in line:
                raise SourceInspectionError("stream samples must be individual text records")
            size = len(line.encode("utf-8"))
            consumed += size
            if size > policy.max_line_bytes or consumed > policy.max_bytes:
                raise SourceInspectionError("stream samples exceed inspection limits")
            if line.strip():
                lines.append(line.rstrip("\r\n"))
            if len(lines) == policy.max_samples:
                break
        if not lines:
            raise SourceInspectionError("stream has no usable sample records")
        identity = source.location
    return inspection_from_records(source, lines, identity, policy)


def inspection_from_records(source, lines, identity, policy):
    lines = lines[:policy.max_samples]
    signature = build_signature(lines)
    if source.format_hint != "auto" and source.format_hint != signature.kind.value:
        raise SourceInspectionError("format hint disagrees with inspected records")
    return SourceInspection(
        kind=source.kind,
        source_id="b3-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
        signature=signature, samples=tuple(lines), sample_count=len(lines),
        sample_limit_reached=len(lines) == policy.max_samples,
        timestamp=_timestamp(lines, signature),
    )


def capture_source(source, policy, *, max_records, max_bytes):
    """Capture one complete bounded snapshot; never execute a truncated sample."""
    limits = {"max_records": max_records + 1, "max_bytes": max_bytes}
    if source.kind == "file":
        stream, identity = _open_file(source.location, policy)
        with stream:
            lines = _read_records(stream, policy, **limits)
    elif source.kind == "http":
        lines, identity = _http_samples(source.location, policy, **limits)
    else:
        raise SourceInspectionError("stream execution is not supported until A3 contract agreement")
    if len(lines) > max_records:
        raise SourceInspectionError("source exceeds the execution record limit")
    return inspection_from_records(source, lines, identity, policy), lines
