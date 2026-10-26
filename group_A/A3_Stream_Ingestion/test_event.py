
import json
from pathlib import Path

from event_utils import validate_event

file_path = Path(__file__).resolve().parent / "Data" / "fixed_events.jsonl"

with file_path.open("r", encoding="utf-8") as file:
    for line in file:
        if not line.strip():
            continue

        event = json.loads(line)
        validate_event(event)

        event_id = event.get("event", {}).get("id", event.get("event_id"))
        print("Event is valid:", event_id)
