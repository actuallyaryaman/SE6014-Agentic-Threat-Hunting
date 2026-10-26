
import socket
import json
import os
import uuid
import urllib.request
import urllib.error

from event_utils import validate_event

# UDP receiver settings
HOST = "127.0.0.1"
PORT = 9999

# A2 Logstash HTTP endpoint
LOGSTASH_URL = os.getenv(
    "LOGSTASH_URL",
    "http://127.0.0.1:8088/"
)

SOURCE_ID = "A3-Stream-Ingestion"
HTTP_TIMEOUT = 5


def forward_event(event):
    """Forward a validated event to the A2 Logstash HTTP input."""

    # Preserve existing labels and upstream source identifiers.
    labels = event.get("labels", {})
    if not isinstance(labels, dict):
        labels = {}

    labels["ingest_mode"] = "stream"

    source_id = labels.get("source_id")
    if not isinstance(source_id, str) or not source_id.strip():
        labels["source_id"] = SOURCE_ID

    event["labels"] = labels

    # Ensure the event object exists.
    event_details = event.get("event")
    if not isinstance(event_details, dict):
        raise ValueError("Event must contain an event dictionary")

    # Ensure every event has a usable ID.
    event_id = event_details.get("id")
    if not isinstance(event_id, str) or not event_id.strip():
        event_id = str(uuid.uuid4())
        event_details["id"] = event_id

    # Preserve compatibility with A2's legacy event_id field.
    event["event_id"] = event_id

    payload = json.dumps(event).encode("utf-8")

    request = urllib.request.Request(
        LOGSTASH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(
        request, timeout=HTTP_TIMEOUT
    ) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(
                f"Logstash returned HTTP {response.status}"
            )

        return response.status


def main():
    """Receive UDP events, validate them, and forward them to A2."""

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))

    print(f"Receiver listening on {HOST}:{PORT}")
    print(f"Forwarding events to {LOGSTASH_URL}")

    received_count = 0
    forwarded_count = 0
    failed_count = 0

    try:
        while True:
            data, address = server.recvfrom(4096)

            try:
                event = json.loads(data.decode("utf-8"))
                event = validate_event(event)

                received_count += 1

                event_details = event.get("event", {})
                print("Received event:", event_details.get("id", "(missing ID)"))
                print("Dataset:", event_details.get("dataset", "(unknown)"))

                try:
                    status = forward_event(event)
                    forwarded_count += 1
                    print(f"Forwarded successfully (HTTP {status})")

                except (
                    urllib.error.HTTPError,
                    urllib.error.URLError,
                    TimeoutError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as error:
                    failed_count += 1
                    print("Forwarding failed:", error)

                print("Total received:", received_count)
                print("Total forwarded:", forwarded_count)
                print("Total forwarding failures:", failed_count)
                print(json.dumps(event, indent=2))
                print("-" * 40)

            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                ValueError,
                KeyError,
                TypeError,
            ) as error:
                print("Invalid event received:", error)

    except KeyboardInterrupt:
        print("\nReceiver stopped.")
        print("Total valid events received:", received_count)
        print("Total events forwarded:", forwarded_count)
        print("Total forwarding failures:", failed_count)

    finally:
        server.close()


if __name__ == "__main__":
    main()
