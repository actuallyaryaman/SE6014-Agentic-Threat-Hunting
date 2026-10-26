"""Verify logical event IDs across indices, independently of transport IDs."""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone


def get_field(document, path):
    if path in document:
        return document[path]
    value = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


@dataclass
class Verification:
    found: set[str] = field(default_factory=set)
    parse_failures: int = 0
    invalid: bool = False
    unavailable: bool = False


def check_documents(client, pattern, expected, *, source_id, dataset, expected_timestamps=None, expected_labels=None):
    result = Verification()
    ids = list(expected)
    try:
        for start in range(0, len(ids), 100):
            batch = ids[start:start + 100]
            response = client.search(
                index=pattern, query={"bool": {"filter": [{"bool": {
                    "should": [{"terms": {"event_id": batch}},
                               {"terms": {"event_id.keyword": batch}}],
                    "minimum_should_match": 1,
                }}]}}, size=len(batch) + 1, track_total_hits=True,
                allow_no_indices=True, ignore_unavailable=True,
            )
            data = response.body if hasattr(response, "body") else response
            if data.get("timed_out") or data.get("_shards", {}).get("failed", 0):
                result.unavailable = True
                return result
            hits = data["hits"]["hits"]
            total = data["hits"]["total"]
            if isinstance(total, dict):
                if total.get("relation") != "eq":
                    result.unavailable = True
                    return result
                total = total["value"]
            if total > len(batch) or total != len(hits):
                result.invalid = True
            seen = set()
            for hit in hits:
                document = hit.get("_source", {})
                event_id = document.get("event_id")
                if event_id not in batch or event_id in seen:
                    result.invalid = True
                    continue
                seen.add(event_id)
                original = get_field(document, "event.original")
                timestamp = document.get("@timestamp")
                try:
                    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    valid_time = parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
                except (AttributeError, TypeError, ValueError):
                    valid_time = False
                valid = (
                    isinstance(original, str)
                    and hashlib.sha256(original.encode()).hexdigest() == expected[event_id]
                    and get_field(document, "labels.source_id") == source_id
                    and get_field(document, "event.dataset") == dataset
                    and isinstance(document.get("message"), str) and bool(document["message"].strip())
                    and valid_time
                )
                if expected_timestamps is not None:
                    valid = valid and valid_time and parsed == expected_timestamps[event_id]
                if expected_labels:
                    valid = valid and all(get_field(document, "labels." + key) == value
                                          for key, value in expected_labels.items())
                if "_parse_failure" in document.get("tags", []):
                    result.parse_failures += 1
                    valid = valid and bool(get_field(document, "error.message"))
                if valid:
                    result.found.add(event_id)
                else:
                    result.invalid = True
        return result
    except Exception:
        result.unavailable = True
        return result


def verify_documents(client, pattern, expected, *, source_id, dataset, attempts=5, interval=1,
                     expected_timestamps=None, expected_labels=None):
    for attempt in range(attempts):
        result = check_documents(client, pattern, expected, source_id=source_id, dataset=dataset,
                                 expected_timestamps=expected_timestamps, expected_labels=expected_labels)
        if result.invalid or result.unavailable or len(result.found) == len(expected):
            return result
        if attempt + 1 < attempts:
            time.sleep(interval)
    return result
