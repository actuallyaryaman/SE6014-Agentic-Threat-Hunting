
from datetime import datetime, timezone


def validate_event(event):
    """Validate the basic structure of an ECS-compatible log event."""

    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    # Check the required top-level ECS fields.
    required_fields = {
        "@timestamp",
        "event",
        "message",
        "host",
    }

    missing_fields = required_fields - event.keys()

    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")

    # Check the timestamp.
    timestamp = event["@timestamp"]

    if not isinstance(timestamp, str):
        raise ValueError("@timestamp must be a string")

    try:
        parsed_timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError:
        raise ValueError("@timestamp must be a valid ISO 8601 timestamp")

    if parsed_timestamp.tzinfo is None:
        raise ValueError("@timestamp must include a timezone")

    if parsed_timestamp.utcoffset() != timezone.utc.utcoffset(parsed_timestamp):
        raise ValueError("@timestamp must use UTC")

    # Check the nested event object.
    event_details = event["event"]

    if not isinstance(event_details, dict):
        raise ValueError("event must be a dictionary")

    required_event_fields = {
        "id",
        "dataset",
        "category",
        "action",
        "outcome",
        "original",
    }

    missing_event_fields = required_event_fields - event_details.keys()

    if missing_event_fields:
        raise ValueError(
            f"Missing required event fields: {missing_event_fields}"
        )

    if not isinstance(event_details["category"], list):
        raise ValueError("event.category must be a list")

    # Check the host object.
    if not isinstance(event["host"], dict):
        raise ValueError("host must be a dictionary")

    if not event["host"].get("name"):
        raise ValueError("host.name is required")

    # Check human-readable message.
    if not isinstance(event["message"], str) or not event["message"].strip():
        raise ValueError("message must be a non-empty string")

    return event
