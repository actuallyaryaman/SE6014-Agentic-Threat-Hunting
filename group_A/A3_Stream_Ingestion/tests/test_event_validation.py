
import unittest
from copy import deepcopy

from event_utils import validate_event


class TestEventValidation(unittest.TestCase):

    def setUp(self):
        self.valid_event = {
            "@timestamp": "2026-10-21T10:00:00Z",
            "event": {
                "id": "TEST-0001",
                "dataset": "linux.auth",
                "category": ["authentication"],
                "action": "user_login",
                "outcome": "failure",
                "original": "Failed password for alice"
            },
            "message": "Failed login for user alice",
            "host": {
                "name": "server01"
            },
            "user": {
                "name": "alice"
            }
        }

    def test_valid_event(self):
        result = validate_event(self.valid_event)
        self.assertEqual(result["event"]["id"], "TEST-0001")

    def test_missing_required_field(self):
        incomplete_event = {
            "event": {
                "id": "TEST-0002"
            }
        }

        with self.assertRaises(ValueError):
            validate_event(incomplete_event)

    def test_non_dictionary_event(self):
        with self.assertRaises(ValueError):
            validate_event("not a dictionary")

    def test_invalid_timestamp(self):
        event = deepcopy(self.valid_event)
        event["@timestamp"] = "not-a-timestamp"

        with self.assertRaises(ValueError):
            validate_event(event)

    def test_missing_nested_event_field(self):
        event = deepcopy(self.valid_event)
        del event["event"]["dataset"]

        with self.assertRaises(ValueError):
            validate_event(event)


if __name__ == "__main__":
    unittest.main()
