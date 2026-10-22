
import json
import socket
import unittest
from pathlib import Path

from event_utils import validate_event


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVENT_FILE = PROJECT_ROOT / "data" / "fixed_events.jsonl"


def load_events():
    """Load and validate the sample events."""
    with open(EVENT_FILE, "r", encoding="utf-8") as file:
        events = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    for event in events:
        validate_event(event)

    return events


class TestStreamReliability(unittest.TestCase):

    def test_expected_event_count(self):
        events = load_events()

        self.assertEqual(
            len(events),
            3,
            "The sample log file should contain exactly 3 events.",
        )

    def test_repeated_streaming_delivery(self):
        events = load_events()
        replay_count = 10
        expected_count = len(events) * replay_count

        # Use a temporary local UDP receiver.
        receiver = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)

        sender = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        try:
            destination = receiver.getsockname()

            # Replay the events ten times.
            for _ in range(replay_count):
                for event in events:
                    message = json.dumps(event).encode("utf-8")
                    sender.sendto(message, destination)

            received_events = []

            for _ in range(expected_count):
                data, _ = receiver.recvfrom(65535)
                event = json.loads(data.decode("utf-8"))
                validate_event(event)
                received_events.append(event)

            self.assertEqual(
                len(received_events),
                expected_count,
                "All replayed events should be received.",
            )

            received_datasets = [
                event["event"]["dataset"]
                for event in received_events
            ]

            self.assertEqual(
                received_datasets.count("linux.auth"),
                10,
            )
            self.assertEqual(
                received_datasets.count("firewall.log"),
                10,
            )
            self.assertEqual(
                received_datasets.count("apache.access"),
                10,
            )

        finally:
            sender.close()
            receiver.close()


if __name__ == "__main__":
    unittest.main()
