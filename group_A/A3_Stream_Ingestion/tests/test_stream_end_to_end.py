
import json
import socket
import threading
import unittest
from pathlib import Path

from event_utils import validate_event


class TestStreamEndToEnd(unittest.TestCase):

    def test_all_events_are_received(self):
        host = "127.0.0.1"
        received_events = []

        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind((host, 0))
        receiver.settimeout(2)

        port = receiver.getsockname()[1]

        def receive_events():
            try:
                while len(received_events) < 3:
                    data, address = receiver.recvfrom(4096)

                    event = json.loads(data.decode("utf-8"))
                    validate_event(event)
                    received_events.append(event)

            except socket.timeout:
                pass
            finally:
                receiver.close()

        receiver_thread = threading.Thread(target=receive_events)
        receiver_thread.start()

        project_root = Path(__file__).resolve().parent.parent
        log_file = project_root / "data" / "fixed_events.jsonl"

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            with open(log_file, "r", encoding="utf-8") as file:
                for line in file:
                    if line.strip():
                        sender.sendto(
                            line.encode("utf-8"),
                            (host, port)
                        )
        finally:
            sender.close()

        receiver_thread.join(timeout=3)

        self.assertEqual(
            len(received_events),
            3,
            "The receiver should receive all 3 events."
        )


if __name__ == "__main__":
    unittest.main()
