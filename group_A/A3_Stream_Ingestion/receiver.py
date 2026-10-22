
import socket
import json
from event_utils import validate_event

HOST = "127.0.0.1"
PORT = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))

print(f"Receiver listening on {HOST}:{PORT}")

received_count = 0

try:
    while True:
        data, address = server.recvfrom(4096)

        try:
            event = json.loads(data.decode("utf-8"))
            event = validate_event(event)

            received_count += 1

            print("Received event:", event["event"]["id"])
            print("Dataset:", event["event"]["dataset"])
            print("Total received:", received_count)
            print(json.dumps(event, indent=2))
            print("-" * 40)

        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            print("Invalid event received:", error)

except KeyboardInterrupt:
    print("\nReceiver stopped.")
    print("Total valid events received:", received_count)

finally:
    server.close()
