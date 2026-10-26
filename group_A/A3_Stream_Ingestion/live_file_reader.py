import json
import socket
import time
from pathlib import Path

from event_utils import validate_event
from log_parser import (
    parse_linux_auth,
    parse_apache_access,
    parse_firewall_log,
)

HOST = "127.0.0.1"
PORT = 9999
POLL_INTERVAL = 0.5

project_root = Path(__file__).resolve().parent
data_folder = project_root / "Data"

# Each raw log file is connected to its matching parser.
log_files = {
    "linux_auth.log": parse_linux_auth,
    "apache_access.log": parse_apache_access,
    "firewall.log": parse_firewall_log,
}

sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

file_handles = {}
sent_count = 0
rejected_count = 0

try:
    # Create the files if they do not exist, then open them.
    for filename in log_files:
        file_path = data_folder / filename
        file_path.touch(exist_ok=True)

        file_handles[filename] = open(
            file_path,
            "r",
            encoding="utf-8",
        )

    print("Live raw log reader started.")
    print("Watching these files:")

    for filename in log_files:
        print(f"- {data_folder / filename}")

    print("Append a raw log line to any file to send an event.")
    print("Press Ctrl+C to stop.")
    print("-" * 40)

    while True:
        found_line = False

        for filename, file_handle in file_handles.items():
            line = file_handle.readline()

            if not line:
                continue

            found_line = True

            if not line.strip():
                continue

            try:
                # Convert the raw log into structured ECS-style JSON.
                parser = log_files[filename]
                event = parser(line.strip())

                # Validate the converted event.
                validate_event(event)

                # Send the event to the local UDP receiver.
                message = json.dumps(event).encode("utf-8")
                sender.sendto(message, (HOST, PORT))

                sent_count += 1

                print(
                    f"Sent: {event['event']['id']} "
                    f"| Dataset: {event['event']['dataset']} "
                    f"| Total sent: {sent_count}"
                )

            except (ValueError, TypeError, KeyError) as error:
                rejected_count += 1
                print(
                    f"Rejected line from {filename}: {error}"
                )

        if not found_line:
            time.sleep(POLL_INTERVAL)

except KeyboardInterrupt:
    print("\nLive raw log reader stopped.")
    print("Total events sent:", sent_count)
    print("Total invalid lines rejected:", rejected_count)

finally:
    for file_handle in file_handles.values():
        file_handle.close()

    sender.close()
