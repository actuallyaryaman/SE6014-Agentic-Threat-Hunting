"""Bounded transport adapters. A receipt is never proof of indexing."""

import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

import httpx

from group_B.common.errors import IngestionError


class TransportError(IngestionError):
    code = "TRANSPORT_FAILED"


@dataclass(frozen=True)
class Receipt:
    submitted: int = 0
    acknowledged: int = 0
    failed: bool = False


class IngestionAdapter(Protocol):
    def handoff(self, plan, records: list[dict]) -> Receipt: ...


def _execute_only(plan):
    if plan.dry_run or plan.status != "planned":
        raise TransportError("transport requires an executable non-dry-run plan")


class FileDropAdapter:
    def __init__(self, incoming_dir):
        self.incoming_dir = incoming_dir

    def handoff(self, plan, records):
        _execute_only(plan)
        if plan.ingest_mode != "pull":
            raise TransportError("file drop requires pull mode")
        if self.incoming_dir is None:
            raise TransportError("A2_INCOMING_DIR is required for pull execution")
        directory = descriptor = None
        temporary = ".b3-" + secrets.token_hex(12) + ".tmp"
        final = temporary[1:-4] + ".ndjson"
        try:
            directory = os.open(self.incoming_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                for record in records:
                    stream.write((json.dumps(record) + "\n").encode())
                stream.flush()
                os.fsync(descriptor)
            # Atomic publication with no overwrite of any existing filename.
            os.link(temporary, final, src_dir_fd=directory, dst_dir_fd=directory)
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
        except OSError as error:
            raise TransportError("could not publish the A2 source file") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
                os.close(directory)
        return Receipt(len(records), len(records))


class HttpPushAdapter:
    def __init__(self, url, *, timeout=5, client=None):
        self.url, self.timeout, self.client = url, timeout, client

    def handoff(self, plan, records):
        _execute_only(plan)
        if plan.ingest_mode != "push":
            raise TransportError("HTTP handoff requires push mode")
        owned = self.client is None
        client = self.client or httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False)
        sent = acknowledged = 0
        deadline = time.monotonic() + 60
        try:
            for record in records:
                if time.monotonic() >= deadline:
                    return Receipt(sent, acknowledged, True)
                sent += 1
                try:
                    response = client.post(self.url, json=record)
                    if not 200 <= response.status_code < 300:
                        return Receipt(sent, acknowledged, True)
                    acknowledged += 1
                except httpx.HTTPError:
                    return Receipt(sent, acknowledged, True)
            return Receipt(sent, acknowledged)
        finally:
            if owned:
                client.close()


class DirectESAdapter:
    def __init__(self, client, index_prefix):
        self.client, self.index_prefix = client, index_prefix

    def handoff(self, plan, records):
        _execute_only(plan)
        if plan.ingest_mode != "direct_es":
            raise TransportError("direct Elasticsearch ingestion must be explicit")
        index = self.index_prefix + "-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
        sent = acknowledged = 0
        for start in range(0, len(records), 100):
            batch = records[start:start + 100]
            operations = []
            for record in batch:
                operations.extend([{"index": {"_index": index, "_id": record["event_id"]}}, record])
            sent += len(batch)
            try:
                response = self.client.bulk(operations=operations, pipeline=plan.pipeline_id, refresh="wait_for")
                data = response.body if hasattr(response, "body") else response
                items = data.get("items", [])
                if len(items) != len(batch):
                    return Receipt(sent, acknowledged, True)
                failed = bool(data.get("errors", False))
                for record, item in zip(batch, items):
                    result = item.get("index", {})
                    if (not 200 <= result.get("status", 0) < 300
                            or result.get("_id") != record["event_id"]):
                        failed = True
                    else:
                        acknowledged += 1
                if failed:
                    return Receipt(sent, acknowledged, True)
            except Exception:
                return Receipt(sent, acknowledged, True)
        return Receipt(sent, acknowledged)
