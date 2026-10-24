
import socket
import json

HOST = "127.0.0.1"
PORT = 9999

sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

event = {
    "event_id": "BAD-0001"
}

message = json.dumps(event).encode("utf-8")

sender.sendto(message, (HOST, PORT))

print("Sent an incomplete test event.")

sender.close()
