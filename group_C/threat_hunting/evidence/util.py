"""Small helpers: UTC time handling and Markdown escaping for text that comes from logs or agents."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def parse_utc(value: str | datetime) -> datetime:
    """Parse an ISO-8601 string ('Z' or an offset) into an aware UTC datetime. A naive value is read as UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_utc_iso(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 UTC string ending in 'Z'."""
    dt = parse_utc(dt)
    text = dt.isoformat(timespec="milliseconds") if dt.microsecond else dt.isoformat(timespec="seconds")
    return text.replace("+00:00", "Z")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def md_cell(value: Any) -> str:
    """Escape text for use inside a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def md_inline(value: Any) -> str:
    """Escape Markdown and HTML control characters in agent- or log-controlled text."""
    text = "" if value is None else str(value)
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_\[\]#|])", r"\\\1", text)


def fence(text: Any) -> str:
    """Wrap text in a code fence longer than any backtick run inside it, so log content cannot close the fence."""
    content = "" if text is None else str(text)
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}text\n{content}\n{ticks}"
