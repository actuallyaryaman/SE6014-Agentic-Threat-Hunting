
import json
import unittest
from pathlib import Path

from event_utils import validate_event


class TestLogFile(unittest.TestCase):

    def setUp(self):
        self.file_path = (
            Path(__file__).resolve().parent.parent
            / "Data"
            / "fixed_events.jsonl"
        )

    def test_all_log_events_are_valid(self):
        events = []

        with open(self.file_path, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    event = json.loads(line)
                    validate_event(event)
                    events.append(event)

        self.assertGreater(len(events), 0)

    def test_event_ids_are_unique(self):
        with open(self.file_path, "r", encoding="utf-8") as file:
            events = [
                json.loads(line)
                for line in file
                if line.strip()
            ]

        event_ids = [event["event"]["id"] for event in events]

        self.assertEqual(len(event_ids), len(set(event_ids)))


if __name__ == "__main__":
    unittest.main()
