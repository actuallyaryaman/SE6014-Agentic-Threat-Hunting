
import re
import uuid
from datetime import datetime, timezone


def parse_linux_auth(line):
    """Convert a supported Linux SSH authentication log into ECS-style JSON."""

    pattern = (
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd:\s+"
        r"(?P<message>.+)$"
    )

    match = re.match(pattern, line)

    if not match:
        raise ValueError("Unsupported Linux authentication log format")

    details = match.groupdict()
    message = details["message"]

    failed = re.search(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)",
        message,
    )

    accepted = re.search(
        r"Accepted \S+ for (\S+) from (\S+)",
        message,
    )

    if failed:
        username, source_ip = failed.groups()
        action = "user_login"
        outcome = "failure"
        log_level = "warning"

    elif accepted:
        username, source_ip = accepted.groups()
        action = "user_login"
        outcome = "success"
        log_level = "info"

    else:
        raise ValueError("Unsupported SSH authentication event")

    current_year = datetime.now(timezone.utc).year

    timestamp_text = (
        f"{current_year} {details['month']} "
        f"{details['day']} {details['time']}"
    )

    timestamp = datetime.strptime(
        timestamp_text,
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)

    return {
        "@timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "event": {
            "id": str(uuid.uuid4()),
            "dataset": "linux.auth",
            "category": ["authentication"],
            "action": action,
            "outcome": outcome,
            "original": line,
        },
        "message": message,
        "host": {
            "name": details["host"],
        },
        "user": {
            "name": username,
        },
        "source": {
            "ip": source_ip,
        },
        "log": {
            "level": log_level,
        },
    }


def parse_apache_access(line):
    """Convert an Apache access log into ECS-style JSON."""

    pattern = (
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+'
        r'(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
    )

    match = re.match(pattern, line)

    if not match:
        raise ValueError("Unsupported Apache access log format")

    details = match.groupdict()

    try:
        timestamp = datetime.strptime(
            details["time"],
            "%d/%b/%Y:%H:%M:%S %z",
        )
    except ValueError as error:
        raise ValueError("Invalid Apache timestamp") from error

    status = int(details["status"])
    outcome = "success" if status < 400 else "failure"

    return {
        "@timestamp": (
            timestamp.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "event": {
            "id": str(uuid.uuid4()),
            "dataset": "apache.access",
            "category": ["web"],
            "action": "access",
            "outcome": outcome,
            "original": line,
        },
        "message": (
            f"HTTP {details['method']} {details['path']} "
            f"returned {status}"
        ),
        "host": {
            "name": "web-server",
        },
        "source": {
            "ip": details["ip"],
        },
        "http": {
            "request": {
                "method": details["method"],
            },
            "response": {
                "status_code": status,
            },
            "version": details["protocol"].replace("HTTP/", ""),
        },
        "url": {
            "path": details["path"],
        },
    }


def parse_firewall_log(line):
    """Convert a supported firewall log into ECS-style JSON."""

    pattern = (
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+firewall:\s+"
        r"Blocked connection from (?P<src>\S+) to (?P<dst>\S+)$"
    )

    match = re.match(pattern, line)

    if not match:
        raise ValueError("Unsupported firewall log format")

    details = match.groupdict()
    current_year = datetime.now(timezone.utc).year

    timestamp_text = (
        f"{current_year} {details['month']} "
        f"{details['day']} {details['time']}"
    )

    timestamp = datetime.strptime(
        timestamp_text,
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)

    return {
        "@timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "event": {
            "id": str(uuid.uuid4()),
            "dataset": "firewall.log",
            "category": ["network"],
            "action": "connection_blocked",
            "outcome": "success",
            "original": line,
        },
        "message": (
            f"Firewall blocked connection from "
            f"{details['src']} to {details['dst']}"
        ),
        "host": {
            "name": details["host"],
        },
        "source": {
            "ip": details["src"],
        },
        "destination": {
            "ip": details["dst"],
        },
        "log": {
            "level": "warning",
        },
    }
