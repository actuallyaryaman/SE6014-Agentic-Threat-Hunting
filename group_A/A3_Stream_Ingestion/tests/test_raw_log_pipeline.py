
import json
import socket
import unittest

from event_utils import validate_event
from log_parser import (
    parse_linux_auth,
    parse_apache_access,
    parse_firewall_log,
)


class TestRawLogPipeline(unittest.TestCase):

    def setUp(self):
        # Create a temporary UDP receiver on an available port.
        self.receiver = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )
        self.receiver.bind(("127.0.0.1", 0))
        self.receiver.settimeout(2)

        self.address = self.receiver.getsockname()

        self.sender = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

    def tearDown(self):
        self.sender.close()
        self.receiver.close()

    def test_raw_logs_are_parsed_and_delivered(self):
        raw_logs = [
            (
                parse_linux_auth,
                "Oct 22 10:15:00 server01 sshd: "
                "Failed password for alice from 192.0.2.10",
            ),
            (
                parse_apache_access,
                '192.0.2.25 - - [22/Oct/2026:10:15:00 +0000] '
                '"GET /index.html HTTP/1.1" 200 1234',
            ),
            (
                parse_firewall_log,
                "Oct 22 10:15:00 fw01 firewall: "
                "Blocked connection from 198.51.100.20 "
                "to 203.0.113.10",
            ),
        ]

        for parser, raw_line in raw_logs:
            event = parser(raw_line)
            validate_event(event)

            message = json.dumps(event).encode("utf-8")
            self.sender.sendto(message, self.address)

        received_events = []

        for _ in range(3):
            data, _ = self.receiver.recvfrom(65535)
            event = json.loads(data.decode("utf-8"))
            validate_event(event)
            received_events.append(event)

        self.assertEqual(len(received_events), 3)

        datasets = {
            event["event"]["dataset"]
            for event in received_events
        }

        self.assertEqual(
            datasets,
            {"linux.auth", "apache.access", "firewall.log"},
        )

    def test_invalid_raw_log_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_linux_auth("This is not a valid SSH log")


if __name__ == "__main__":
    unittest.main()
