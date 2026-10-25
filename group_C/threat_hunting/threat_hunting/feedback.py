"""Analyst memory (DESIGN.md 3.6): lessons from earlier hunts, written only by analysts, never by the agent.

  python -m threat_hunting.feedback add --run RUN --claim C-001 --label benign --note "backup server" --analyst NAME
  python -m threat_hunting.feedback list
  python -m threat_hunting.feedback revoke L-003 --analyst NAME

A lesson keeps the claim's technique and entities, which code copies from the claim's facts, plus the analyst's label
(benign, malicious or useful_pivot), note and name. Hunts use the active lessons in two ways: a finding whose entities match
a benign lesson gets a review reason (it is never suppressed), and the lessons about the hunt's techniques or entities are
shown to the investigator and the skeptic. result.json lists the lessons a hunt used."""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
from . import config

LABELS = ("benign", "malicious", "useful_pivot")
ENTITY_FIELDS = {"source.ip", "destination.ip", "host.name", "user.name", "process.executable", "process.name", "url.path",
                 "dns.question.registered_domain", "file.path"}


def _file() -> Path:
    return config.MEMORY_FILE


def load() -> list[dict]:
    f = _file()
    return [json.loads(line) for line in f.read_text().splitlines() if line.strip()] if f.exists() else []


def _save(lessons: list[dict]):
    _file().parent.mkdir(parents=True, exist_ok=True)
    _file().write_text("".join(json.dumps(x) + "\n" for x in lessons))


def _entities(claim: dict, steps: dict) -> list[dict]:
    out = [{"field": k, "value": v} for k, v in claim.get("facts", {}).items() if k in ENTITY_FIELDS and isinstance(v, str)]
    if "bucket_key" in claim.get("facts", {}):          # an aggregate claim: the bucket is a value of the step's terms field
        field = steps.get(claim.get("step_id"), {}).get("params", {}).get("field")
        if field:
            out.append({"field": field, "value": str(claim["facts"]["bucket_key"])})
    return out


def add(run_id: str, claim_id: str, label: str, note: str, analyst: str) -> dict:
    if label not in LABELS:
        raise SystemExit(f"label must be one of {LABELS}")
    run = config.RUNS_DIR / run_id
    r = json.loads((run / "result.json").read_text())
    claim = next((c for c in r["claims"] if c["claim_id"] == claim_id), None)
    if claim is None:
        raise SystemExit(f"{run_id} has no claim {claim_id}")
    plan = json.loads((run / "plan.json").read_text())
    steps = {s["step_id"]: s for s in plan.get("steps", []) + r.get("dynamic_steps", [])}
    ents = _entities(claim, steps)
    if not ents:
        raise SystemExit(f"{claim_id} has no entity facts to remember")
    lessons = load()
    lesson = {"id": f"L-{len(lessons) + 1:03d}", "added": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "analyst": analyst,
              "run_id": run_id, "claim_id": claim_id, "technique": claim["technique"], "entities": ents, "label": label,
              "note": note[:500], "status": "active"}
    _save(lessons + [lesson])
    return lesson


def revoke(lesson_id: str, analyst: str) -> dict:
    lessons = load()
    x = next((x for x in lessons if x["id"] == lesson_id), None)
    if x is None:
        raise SystemExit(f"no lesson {lesson_id}")
    x.update(status="revoked", revoked_by=analyst, revoked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _save(lessons)
    return x


def relevant(plan) -> list[dict]:
    """Active lessons about the hunt's techniques or about an entity the hypothesis names."""
    named = {*plan.entities.get("hosts", []), *plan.entities.get("ips", []), *plan.entities.get("users", [])}
    return [x for x in load() if x["status"] == "active"
            and (x["technique"] in plan.techniques or any(e["value"] in named for e in x["entities"]))]


def for_prompt(lessons: list[dict]) -> list[dict]:
    """What the LLM sees: the analyst's label and note, and the entities; not the claim text (that was built from logs)."""
    return [{k: x[k] for k in ("id", "label", "technique", "entities", "note")} for x in lessons]


def benign_matches(lessons: list[dict], claims: list) -> dict[str, list[str]]:
    """claim id -> ids of the benign lessons that share an entity (field and value) with the claim."""
    out: dict[str, list[str]] = {}
    benign = [x for x in lessons if x["label"] == "benign"]
    for c in claims:
        facts = {(k, str(v)) for k, v in c.facts.items() if not isinstance(v, list)}
        for x in benign:              # an aggregate claim's bucket_key is a value of the step's field: compare the value alone
            if any((e["field"], e["value"]) in facts or e["value"] == str(c.facts.get("bucket_key")) for e in x["entities"]):
                out.setdefault(c.claim_id, []).append(x["id"])
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Analyst lessons for later hunts.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("add")
    for k in ("--run", "--claim", "--label", "--note", "--analyst"):
        a1.add_argument(k, required=True)
    sub.add_parser("list")
    a3 = sub.add_parser("revoke"); a3.add_argument("lesson"); a3.add_argument("--analyst", required=True)
    a = ap.parse_args()
    if a.cmd == "add":
        print(json.dumps(add(a.run, a.claim, a.label, a.note, a.analyst), indent=1))
    elif a.cmd == "revoke":
        print(json.dumps(revoke(a.lesson, a.analyst), indent=1))
    else:
        for x in load():
            print(f"{x['id']} {x['status']:8s} {x['label']:12s} {x['technique']:10s} {x['entities']} {x['note']!r} ({x['analyst']}, {x['run_id']}/{x['claim_id']})")
