
import unittest

from event_utils import validate_event
from log_parser import (
    parse_linux_auth,
    parse_apache_access,
    parse_firewall_log,
    parse_windows_event,
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

    def test_windows_sysmon_network_event(self):
        line = (
            '{"@timestamp":"2020-10-22T18:32:43.779Z",'
            '"EventID":3,'
            '"RecordNumber":924068,'
            '"Message":"Network connection detected",'
            '"Hostname":"MORDORDC.theshire.local",'
            '"SourceIp":"192.0.2.10",'
            '"DestinationIp":"192.0.2.20",'
            '"SourcePort":"61901",'
            '"DestinationPort":"389",'
            '"Image":"C:\\\\Windows\\\\System32\\\\lsass.exe",'
            '"ProcessId":"696",'
            '"User":"NT AUTHORITY\\\\\\\\SYSTEM",'
            '"Protocol":"tcp"}'
        )

        event = parse_windows_event(line)

        self.assertEqual(event["event"]["dataset"], "windows.sysmon")
        self.assertEqual(event["event"]["code"], "3")
        self.assertEqual(event["event"]["action"], "network_connect")
        self.assertEqual(
            event["host"]["name"],
            "MORDORDC.theshire.local",
        )
        self.assertEqual(event["source"]["ip"], "192.0.2.10")
        self.assertEqual(event["destination"]["ip"], "192.0.2.20")
        self.assertEqual(event["source"]["port"], 61901)
        self.assertEqual(event["destination"]["port"], 389)
        self.assertEqual(event["process"]["pid"], 696)
        self.assertEqual(
            event["process"]["executable"],
            "C:\\Windows\\System32\\lsass.exe",
        )
        self.assertEqual(event["network"]["transport"], "tcp")
        validate_event(event)

    def test_invalid_windows_json(self):
        with self.assertRaises(ValueError):
            parse_windows_event("This is not JSON")

    def test_windows_event_missing_timestamp(self):
        line = (
            '{"EventID":3,'
            '"Message":"Network connection detected"}'
        )

        with self.assertRaises(ValueError):
            parse_windows_event(line)


if __name__ == "__main__":
    unittest.main()
