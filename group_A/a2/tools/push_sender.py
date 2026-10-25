
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

LOGSTASH_URL = "http://127.0.0.1:8088"


def push_event(file_path):
    # Read and validate the JSON security event
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            event = json.load(file)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as error:
        print(f"Invalid or unreadable JSON file: {error}")
        sys.exit(1)

    if not isinstance(event, dict):
        raise ValueError("Security event must be a JSON object")

    payload = json.dumps(event).encode("utf-8")

    # Send the event to Logstash
    request = urllib.request.Request(
        LOGSTASH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(f"HTTP status: {response.status}")
            print(f"Logstash response: {response.read().decode()}")
            print(f"Sent event from: {file_path}")

    except urllib.error.URLError as error:
        print(f"Failed to send event: {error}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python push_sender.py <json_file>")
        sys.exit(1)

    path = Path(sys.argv[1])

    if not path.is_file():
        print(f"File not found: {path}")
        sys.exit(1)

    push_event(path)
