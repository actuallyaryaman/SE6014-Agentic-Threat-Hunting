
import unittest

from event_utils import validate_event
from log_parser import (
    parse_linux_auth,
    parse_apache_access,
    parse_firewall_log,
)


class TestLogParser(unittest.TestCase):

    def test_linux_failed_login(self):
        line = (
            "Oct 22 10:15:00 server01 sshd: "
            "Failed password for alice from 192.0.2.10"
        )
        event = parse_linux_auth(line)

        self.assertEqual(event["event"]["outcome"], "failure")
        self.assertEqual(event["user"]["name"], "alice")
        self.assertEqual(event["source"]["ip"], "192.0.2.10")
        validate_event(event)

    def test_apache_access(self):
        line = (
            '192.0.2.25 - - [22/Oct/2026:10:15:00 +0000] '
            '"GET /index.html HTTP/1.1" 200 1234'
        )
        event = parse_apache_access(line)

        self.assertEqual(event["event"]["dataset"], "apache.access")
        self.assertEqual(event["http"]["response"]["status_code"], 200)
        validate_event(event)

    def test_firewall_block(self):
        line = (
            "Oct 22 10:15:00 fw01 firewall: "
            "Blocked connection from 198.51.100.20 to 203.0.113.10"
        )
        event = parse_firewall_log(line)

        self.assertEqual(event["event"]["action"], "connection_blocked")
        self.assertEqual(event["destination"]["ip"], "203.0.113.10")
        validate_event(event)

    def test_invalid_linux_log(self):
        with self.assertRaises(ValueError):
            parse_linux_auth("This is not a supported SSH log")


if __name__ == "__main__":
    unittest.main()
