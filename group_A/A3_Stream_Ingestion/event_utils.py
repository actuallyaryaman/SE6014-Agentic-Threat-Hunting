
from datetime import datetime, timezone
import warnings


def validate_event(event):
    """Validate an ECS-compatible log event."""

    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    # The four required fields at the top level / inside event.
    required_top_level_fields = {"@timestamp", "event", "message"}
    missing_fields = required_top_level_fields - event.keys()

    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")

    # Validate the timestamp.
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

    # Validate the event object.
    event_details = event["event"]

    if not isinstance(event_details, dict):
        raise ValueError("event must be a dictionary")

    # event.dataset and event.original are mandatory.
    for field in ("dataset", "original"):
        value = event_details.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"event.{field} must be a non-empty string")

    if not event_details["dataset"].strip():
        raise ValueError("event.dataset must be a non-empty string")

    # Validate message.
    if not isinstance(event["message"], str) or not event["message"].strip():
        raise ValueError("message must be a non-empty string")

    # Optional fields: report missing values without rejecting the event.
    optional_fields = {
        "host.name": (
            isinstance(event.get("host"), dict)
            and bool(event["host"].get("name"))
        ),
        "event.action": bool(event_details.get("action")),
        "event.id": bool(event_details.get("id")),
        "event.category": bool(event_details.get("category")),
        "event.outcome": bool(event_details.get("outcome")),
    }

    missing_optional = [
        field for field, present in optional_fields.items() if not present
    ]

    if missing_optional:
        warnings.warn(
            f"Optional fields missing: {', '.join(missing_optional)}",
            UserWarning,
            stacklevel=2,
        )

    # Validate optional fields if they are provided.
    if "host" in event and not isinstance(event["host"], dict):
        raise ValueError("host must be a dictionary when provided")

    if "category" in event_details and not isinstance(
        event_details["category"], list
    ):
        raise ValueError("event.category must be a list when provided")

    return event
