#!/usr/bin/env python3
"""Compare two C2 result.json files without hiding meaningful changes."""
import argparse
import json
from pathlib import Path

# Only execution identifiers are ignored; event timestamps and query values stay.
EXECUTION_KEYS = {"run_id", "call_id", "query_id"}
MANIFEST_EXECUTION_KEYS = {"seconds", "audit_files"}

def normalize(obj, *, manifest=False, action=False):
    if isinstance(obj, dict):
        excluded = EXECUTION_KEYS | (MANIFEST_EXECUTION_KEYS if manifest else set())
        result = {}
        for k, v in sorted(obj.items()):
            if k in excluded or (manifest and k == "phase_seconds" and isinstance(v, dict)):
                continue
            if action and k == "file" and isinstance(v, str) and v.startswith("runs/") and "/actions/" in v:
                # Normalize only the per-run output directory, preserving the artifact's relative path.
                v = "actions/" + v.split("/actions/", 1)[1]
            result[k] = normalize(v, action=action)
        return result
    if isinstance(obj, list):
        return [normalize(v, manifest=manifest, action=action) for v in obj]
    return obj

def validate(data, label):
    errors = []
    if not isinstance(data, dict):
        return [f"{label}: root must be a JSON object"]
    for key in ("hypothesis", "time_range", "verdict", "coverage", "claims", "evidence", "queries"):
        if key not in data or data[key] is None:
            errors.append(f"{label}: missing {key}")
    if not isinstance(data.get("hypothesis"), str) or not data.get("hypothesis", "").strip():
        errors.append(f"{label}: hypothesis must be nonempty")
    window = data.get("time_range")
    if not isinstance(window, dict) or not all(isinstance(window.get(k), str) and window[k] for k in ("from", "to")):
        errors.append(f"{label}: time_range.from and time_range.to required")
    verdict = data.get("verdict")
    if not isinstance(verdict, dict) or not isinstance(verdict.get("label"), str) or not verdict["label"]:
        errors.append(f"{label}: verdict.label required")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict) or not isinstance(coverage.get("data_sources"), dict) or not isinstance(coverage.get("coverage"), dict):
        errors.append(f"{label}: coverage.data_sources and coverage.coverage required")
    for key, identifier in (("claims", "claim_id"), ("evidence", "evidence_id"), ("queries", "request")):
        items = data.get(key)
        if not isinstance(items, list) or (key == "queries" and not items):
            errors.append(f"{label}: {key} must be a " + ("nonempty list" if key == "queries" else "list"))
            continue
        for i, item in enumerate(items):
            if not isinstance(item, dict) or identifier not in item or item[identifier] in (None, "", [], {}):
                errors.append(f"{label}: {key}[{i}].{identifier} required")
            if key == "claims" and (not isinstance(item, dict) or not isinstance(item.get("evidence_ids"), list)):
                errors.append(f"{label}: claims[{i}].evidence_ids required")
            if key == "evidence" and (not isinstance(item, dict) or not isinstance(item.get("event_ids"), list)):
                errors.append(f"{label}: evidence[{i}].event_ids required")
    if isinstance(verdict, dict) and verdict.get("label") == "SUPPORTED" and data.get("claims") == []:
        errors.append(f"{label}: SUPPORTED verdict requires claims")
    if isinstance(data.get("claims"), list) and isinstance(data.get("evidence"), list):
        known = {e.get("evidence_id") for e in data["evidence"] if isinstance(e, dict)}
        for i, claim in enumerate(data["claims"]):
            if isinstance(claim, dict) and isinstance(claim.get("evidence_ids"), list):
                for evidence_id in claim["evidence_ids"]:
                    if evidence_id not in known:
                        errors.append(f"{label}: claims[{i}] references missing evidence {evidence_id}")
    return errors

def compare(a, b):
    errors = validate(a, "Run A") + validate(b, "Run B")
    if errors:
        return {}, errors
    checks = {}
    def check(name, left, right):
        checks[name] = {"match": left == right, "run_a": left, "run_b": right}
    check("hypothesis", a["hypothesis"], b["hypothesis"])
    check("time_range", a["time_range"], b["time_range"])
    check("verdict", a["verdict"], b["verdict"])
    check("coverage", a["coverage"], b["coverage"])
    check("claims_and_evidence_links", normalize(a["claims"]), normalize(b["claims"]))
    check("evidence_contents", normalize(a["evidence"]), normalize(b["evidence"]))
    check("queries_and_values", normalize(a["queries"]), normalize(b["queries"]))
    # Other result fields can affect interpretation, even when primary checks agree.
    for name in sorted((set(a) | set(b)) - {"hypothesis", "time_range", "verdict", "coverage", "claims", "evidence", "queries", "run_id"}):
        check(name, normalize(a.get(name), manifest=(name == "manifest"), action=(name == "actions")),
              normalize(b.get(name), manifest=(name == "manifest"), action=(name == "actions")))
    return checks, []

def report(checks, errors, run_a, run_b):
    lines = ["# C4 C2 Repeatability Comparison", "",
             f"- Run A: `{run_a}`", f"- Run B: `{run_b}`", ""]
    if errors:
        lines += ["## INVALID INPUT — no MATCH result", ""]
        lines += [f"- {e}" for e in errors]
        return "\n".join(lines) + "\n"
    lines += ["| Check | Result |", "|---|---|"]
    for name, item in checks.items():
        lines.append(f"| {name} | {'MATCH' if item['match'] else 'DIFFERENT'} |")
    matches = sum(item["match"] for item in checks.values())
    lines += ["", f"**Matched checks: {matches}/{len(checks)}**", "",
              "## Differences", ""]
    diffs = [(name, item) for name, item in checks.items() if not item["match"]]
    if not diffs:
        lines.append("No meaningful differences detected in the compared C2 fields.")
    for name, item in diffs:
        lines += [f"### {name}", "", "**Run A**", "```json",
                  json.dumps(item["run_a"], indent=2, ensure_ascii=False), "```",
                  "**Run B**", "```json",
                  json.dumps(item["run_b"], indent=2, ensure_ascii=False), "```", ""]
    lines += ["", "## Notes", "",
              "Only execution IDs (run_id, call_id, query_id) and manifest execution "
              "duration, phase timings and audit-file paths are ignored. Event timestamps, claim facts, "
              "evidence links, evidence contents, and query requests/values are preserved.",
              "This compares saved C2 outputs; it does not rerun hunts or establish correctness.", ""]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_a", type=Path)
    parser.add_argument("run_b", type=Path)
    parser.add_argument("--output", type=Path, default=Path("c4_sample_comparison.md"))
    args = parser.parse_args()
    a = json.loads(args.run_a.read_text(encoding="utf-8"))
    b = json.loads(args.run_b.read_text(encoding="utf-8"))
    checks, errors = compare(a, b)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report(checks, errors, args.run_a, args.run_b), encoding="utf-8")
    print(f"Saved {args.output}")
    if errors:
        print("INVALID INPUT:", "; ".join(errors))
        return 2
    differences = [k for k, v in checks.items() if not v["match"]]
    print("MATCH" if not differences else "DIFFERENT: " + ", ".join(differences))
    return 1 if differences else 0

if __name__ == "__main__":
    raise SystemExit(main())
