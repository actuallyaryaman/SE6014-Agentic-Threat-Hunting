import json
from event_utils import validate_event

file_path = "data/fixed_events.jsonl"

with open(file_path, "r") as file:
    for line in file:
        event = json.loads(line)
        validate_event(event)
        print("Event is valid:", event["event_id"])