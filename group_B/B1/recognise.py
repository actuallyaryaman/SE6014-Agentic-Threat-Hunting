"""B1 log recogniser, following the adapter contract.

    recognise(lines: Sequence[str]) -> dict

Match:     {"format_id", "dataset", "pipeline_id", "confidence"}
No match:  {"reason_code": "no_match"}   (no match fields)

Usage:  python recognise.py yourfile.log
"""
import json
import re
import sys

# One Apache access log line: IP ident auth [time] "METHOD path ..." status size
APACHE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+)')


def _json_obj(line):
    try:
        d = json.loads(line)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def is_windows_json(line):
    """A JSON object that has an EventID (Sysmon / Windows Security events)."""
    d = _json_obj(line)
    return d is not None and ("EventID" in d or "event_id" in d)


# One firewall syslog line: Oct 22 10:20:01 fw01 firewall: Blocked connection from A to B
FIREWALL = re.compile(
    r'^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ firewall: (Allowed|Blocked) connection from \S+ to \S+')


# format_id -> test function
TEMPLATES = {
    "apache_access": lambda l: bool(APACHE.match(l)),
    "windows_json": is_windows_json,
    "firewall_syslog": lambda l: bool(FIREWALL.match(l)),
}

# format_id -> Elasticsearch ingest pipeline
PIPELINES = {
    "apache_access": "apache-access",
    "windows_json": "windows-json",
    "firewall_syslog": "firewall-syslog",
}


def _dataset(format_id, lines):
    """Dataset name: fixed for Apache, the Channel found in the sample for Windows."""
    if format_id == "windows_json":
        for l in lines:
            d = _json_obj(l)
            if d and d.get("Channel"):
                return str(d["Channel"])
        return "windows"
    if format_id == "firewall_syslog":
        return "firewall"
    return "apache.access"


def recognise(lines, min_conf=0.8):
    """Look at a sample of lines and say which known format they are."""
    lines = [l.lstrip("\ufeff") for l in lines if isinstance(l, str) and l.strip()]
    if not lines:
        return {"reason_code": "no_match"}
    scores = {n: sum(bool(f(l)) for l in lines) / len(lines) for n, f in TEMPLATES.items()}
    best = max(scores, key=scores.get)
    conf = scores[best]
    if conf < min_conf:
        return {"reason_code": "no_match"}
    return {
        "format_id": best,
        "dataset": _dataset(best, lines),
        "pipeline_id": PIPELINES[best],
        "confidence": conf,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python recognise.py <logfile>")
    with open(sys.argv[1], encoding="utf-8-sig", errors="replace") as f:
        sample = [next(f, "") for _ in range(50)]
    print(recognise(sample))
