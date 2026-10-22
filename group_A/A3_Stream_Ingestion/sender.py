
import json
import socket
import time
import sys
from pathlib import Path

HOST = "127.0.0.1"
PORT = 9999

try:
    replay_count = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 1

    if replay_count <= 0:
        raise ValueError("Replay count must be greater than zero.")

    if delay < 0:
        raise ValueError("Delay cannot be negative.")

except ValueError as error:
    print("Invalid settings:", error)
    sys.exit(1)

project_root = Path(__file__).resolve().parent
file_path = project_root / "data" / "fixed_events.jsonl"

sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    sent_count = 0

    for replay in range(replay_count):
        print(f"Starting replay {replay + 1}")

        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                event = json.loads(line)

                # Validate the event before sending it.
                from event_utils import validate_event
                validate_event(event)

                message = json.dumps(event).encode("utf-8")
                sender.sendto(message, (HOST, PORT))

                sent_count += 1
                print("Sent event:", event["event"]["id"])

                time.sleep(delay)

    print("Finished all replays.")
    print("Total events sent:", sent_count)

finally:
    sender.close()
