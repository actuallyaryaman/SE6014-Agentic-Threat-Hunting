
import re
import uuid
import json
from datetime import datetime, timezone


def parse_linux_auth(line):
    """Convert a supported Linux SSH authentication log into ECS-style JSON."""

    pattern = (
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd:\s+"
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
        action, outcome, log_level = "user_login", "failure", "warning"
    elif accepted:
        username, source_ip = accepted.groups()
        action, outcome, log_level = "user_login", "success", "info"
    else:
        raise ValueError("Unsupported SSH authentication event")

    current_year = datetime.now(timezone.utc).year
    timestamp_text = (
        f"{current_year} {details['month']} "
        f"{details['day']} {details['time']}"
    )

    timestamp = datetime.strptime(
        timestamp_text, "%Y %b %d %H:%M:%S"
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
        "host": {"name": details["host"]},
        "user": {"name": username},
        "source": {"ip": source_ip},
        "log": {"level": log_level},
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
            details["time"], "%d/%b/%Y:%H:%M:%S %z"
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
        "host": {"name": "web-server"},
        "source": {"ip": details["ip"]},
        "http": {
            "request": {"method": details["method"]},
            "response": {"status_code": status},
            "version": details["protocol"].replace("HTTP/", ""),
        },
        "url": {"path": details["path"]},
    }


def parse_firewall_log(line):
    """Convert a supported firewall log into ECS-style JSON."""

    pattern = (
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
        r"firewall:\s+Blocked connection from "
        r"(?P<src>\S+) to (?P<dst>\S+)$"
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
        timestamp_text, "%Y %b %d %H:%M:%S"
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
        "host": {"name": details["host"]},
        "source": {"ip": details["src"]},
        "destination": {"ip": details["dst"]},
        "log": {"level": "warning"},
    }


def parse_windows_event(line):
    """Convert a Windows Sysmon JSON event into ECS-style JSON."""

    try:
        record = json.loads(line)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError("Invalid Windows event JSON") from error

    if not isinstance(record, dict):
        raise ValueError("Windows event must be a JSON object")

    timestamp = record.get("@timestamp")
    message = record.get("Message")
    event_id = record.get("EventID")

    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("Windows event is missing @timestamp")

    try:
        parsed_timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("Invalid Windows event timestamp") from error

    if parsed_timestamp.tzinfo is None:
        raise ValueError("Windows event timestamp must include a timezone")

    if parsed_timestamp.utcoffset().total_seconds() != 0:
        raise ValueError("Windows event timestamp must use UTC")

    if not isinstance(message, str) or not message.strip():
        raise ValueError("Windows event is missing Message")

    if event_id is None:
        raise ValueError("Windows event is missing EventID")

    try:
        event_id = int(event_id)
    except (ValueError, TypeError) as error:
        raise ValueError("Windows EventID must be an integer") from error

    if event_id == 3:
        dataset = "windows.sysmon"
        category = ["network"]
        action = "network_connect"
    else:
        dataset = "windows.event"
        category = ["host"]
        action = "event"

    # Use the record's unique number when available.
    # Never use EventID as the unique event identifier.
    record_number = record.get("RecordNumber")
    if record_number is not None and str(record_number).strip():
        unique_event_id = str(record_number)
    else:
        unique_event_id = str(uuid.uuid4())

    event = {
        "@timestamp": (
            parsed_timestamp.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "event": {
            "id": unique_event_id,
            "code": str(event_id),
            "dataset": dataset,
            "category": category,
            "action": action,
            "original": line.strip(),
        },
        "message": message,
    }

    hostname = record.get("Hostname") or record.get("host")
    if hostname:
        event["host"] = {"name": hostname}

    if event_id == 3:
        if record.get("SourceIp"):
            event["source"] = {"ip": record["SourceIp"]}

        if record.get("DestinationIp"):
            event["destination"] = {"ip": record["DestinationIp"]}

        if record.get("DestinationPort") is not None:
            try:
                event.setdefault("destination", {})["port"] = int(
                    record["DestinationPort"]
                )
            except (ValueError, TypeError):
                pass

        if record.get("SourcePort") is not None:
            try:
                event.setdefault("source", {})["port"] = int(
                    record["SourcePort"]
                )
            except (ValueError, TypeError):
                pass

        if record.get("Image"):
            event["process"] = {"executable": record["Image"]}

        if record.get("ProcessId") is not None:
            try:
                event.setdefault("process", {})["pid"] = int(
                    record["ProcessId"]
                )
            except (ValueError, TypeError):
                pass

    if record.get("User"):
        event["user"] = {"name": record["User"]}

    if record.get("Protocol"):
        event.setdefault("network", {})["transport"] = (
            record["Protocol"].lower()
        )

    return event
