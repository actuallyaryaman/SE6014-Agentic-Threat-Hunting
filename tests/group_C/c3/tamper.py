"""Plant known errors in copies of C2's real run folders, to check that C3 finds them.

C2's two sample runs (``c2_runs/``) are clean, and every claim in them is true. A verifier that says "all verified"
on clean input has shown nothing. Each case below copies a run, changes one thing in ``result.json`` the way a
hallucinating hunter could, and states what C3 must conclude. The original files are never modified.

    python -m tests.group_C.c3.tamper --out group_C/experiments/c2_tampered_runs
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .recorded_gateway import C2_RUNS, run_paths

Mutation = Callable[[dict[str, Any]], None]
SSH, LSASS = "share-ssh-bruteforce", "share-lsass-lateral"


def _claim(result: dict[str, Any], claim_id: str) -> dict[str, Any]:
    return next(c for c in result["claims"] if c["claim_id"] == claim_id)


def inflate_count(result: dict[str, Any]) -> None:
    _claim(result, "C-001")["text"] = "Source 203.0.113.99 produced 50 failed SSH logins"


def wrong_user(result: dict[str, Any]) -> None:
    c = _claim(result, "C-002")
    c["facts"]["user.name"] = "root"
    c["text"] = c["text"].replace("as admin", "as root")


def invented_host(result: dict[str, Any]) -> None:
    c = _claim(result, "C-002")                      # quoted facts stay true; only the sentence names another host
    c["text"] = c["text"].replace("WS-02", "WS-09")


def invented_user(result: dict[str, Any]) -> None:
    c = _claim(result, "C-002")
    c["text"] = c["text"].replace("as admin", "as svc_backup")


def invented_narrative(result: dict[str, Any]) -> None:
    result["verdict"]["reasons"].append("A second attacker at 198.51.100.23 also touched WS-01 and moved to FS-09.")


def fake_event_id(result: dict[str, Any]) -> None:
    _claim(result, "C-002")["event_ids"] = ["security-events-c2test/deadbeefdeadbeefdead"]


def invented_claim(result: dict[str, Any]) -> None:
    result["claims"].append({
        "claim_id": "C-003", "text": "The attacker copied /etc/shadow from WS-02 after logging in", "technique": "T1078",
        "evidence_ids": [], "facts": {}, "confidence": "medium", "step_id": "T1078-b-203.0.113.99", "kind": "events",
        "first_seen": "", "event_ids": [], "context_only": False, "status": "self_checked", "verifier_notes": "", "replay": {}})


def forged_aggregate(result: dict[str, Any]) -> None:
    c = _claim(result, "C-013")
    c["text"] = "External address 203.0.113.50 produced 40 error responses (404/500), consistent with scanning"
    c["facts"]["count"] = "40"
    c["replay"]["count"] = 40


def two_indicators_wrong(result: dict[str, Any]) -> None:
    c1, c2 = _claim(result, "C-001"), _claim(result, "C-002")
    c1["facts"]["winlog.event_data.GrantedAccess"] = "0x1410"
    c1["text"] = c1["text"].replace("0x1fffff", "0x1410")
    c2["facts"]["process.command_line"] = "notepad.exe C:\\Users\\alice\\notes.txt"
    c2["text"] = "A process command line on WS-01 matches LSASS-dump tooling: notepad.exe C:\\Users\\alice\\notes.txt"


def unknown_ioc(result: dict[str, Any]) -> None:
    c = _claim(result, "C-008")
    c["facts"]["ioc"] = "198.51.100.99"
    c["text"] = "Destination 198.51.100.99 matches a threat-intel entry (known C2 infrastructure)"
    c["replay"]["value"] = "198.51.100.99"


@dataclass
class Case:
    name: str
    run_id: str
    what: str
    mutate: Mutation
    expect_claims: dict[str, str]                  # claim_id -> status C3 must give
    expect_verdict: str = "Confirmed"              # C2 said SUPPORTED in every case; "Confirmed" here means C3 still agrees
    expect_review: str = "agrees"                  # agrees | downgraded | kept_c2_caution | contradicts
    why: str = ""
    expect_replay_mismatch: bool = False
    expect_flags: list[str] = field(default_factory=list)


CASES: list[Case] = [
    Case("inflated_count", SSH, "C-001 says 50 failed logins; the data shows 30", inflate_count,
         {"C-001": "contradicted", "C-002": "verified"}, expect_verdict="Inconclusive", expect_review="downgraded",
         why="the number 50 appears nowhere in the claim's evidence; T1110 loses its only indicator"),
    Case("wrong_user", SSH, "C-002 says the login was as root; the stored event says admin", wrong_user,
         {"C-001": "verified", "C-002": "contradicted"}, expect_verdict="Inconclusive", expect_review="downgraded",
         why="user.name=root is not in the cited event; T1078 loses its only indicator"),
    Case("fake_event_id", SSH, "C-002 cites an event ID that does not exist", fake_event_id,
         {"C-001": "verified", "C-002": "unsupported"}, expect_verdict="Inconclusive", expect_review="downgraded",
         why="the cited event cannot be retrieved; T1078 loses its only indicator"),
    Case("invented_host", SSH, "C-002 says the login was on WS-09; the event is from WS-02", invented_host,
         {"C-001": "verified", "C-002": "contradicted"}, expect_verdict="Inconclusive", expect_review="downgraded",
         why="WS-09 appears in no evidence; T1078 loses its only indicator"),
    Case("invented_user", SSH, "C-002 says the login was as svc_backup; the event says admin (facts unchanged)", invented_user,
         {"C-001": "verified", "C-002": "contradicted"}, expect_verdict="Inconclusive", expect_review="downgraded",
         why="svc_backup appears in no evidence; T1078 loses its only indicator"),
    Case("invented_claim", SSH, "C-003 'copied /etc/shadow' has no evidence and no event", invented_claim,
         {"C-001": "verified", "C-002": "verified", "C-003": "unsupported"},
         why="no evidence record, no cited event"),
    Case("forged_aggregate", LSASS, "C-013 says 40 error responses, text and replay data agree with each other (27 is true)",
         forged_aggregate, {"C-013": "contradicted"},
         why="the replayed aggregate gives 27, not 40"),
    Case("unknown_ioc", LSASS, "C-008 names an IP the threat-intel feed does not list", unknown_ioc,
         {"C-008": "contradicted"},
         why="the replayed check_ioc finds no match"),
    Case("invented_narrative", LSASS, "C2's verdict reasons name an IP and a host that appear in no evidence", invented_narrative,
         {}, expect_flags=["narrative_unsupported_entity"],
         why="198.51.100.23 and FS-09 are in no evidence; every claim still verifies, so the verdict stands but needs review"),
    Case("two_indicators_wrong", LSASS, "C-001 and C-002 (2 of the 3 LSASS indicators) quote values that are not in the events",
         two_indicators_wrong, {"C-001": "contradicted", "C-002": "contradicted", "C-003": "verified"},
         expect_verdict="Inconclusive", expect_review="downgraded",
         why="T1003.001 needs 2 independent indicators and only 1 survives, so C2's SUPPORTED cannot stand"),
]
CASES_BY_NAME = {c.name: c for c in CASES}


def write_case(case: Case, out_root: Path, source_root: Path = C2_RUNS) -> tuple[Path, Path, Path, Path]:
    """Copy the run folder, apply the mutation to result.json, and return the new plan, result, audit and trace paths."""
    plan, result_path, audit, trace = run_paths(case.run_id, source_root)
    run_dir = out_root / case.name / "runs" / case.run_id
    audit_dir = out_root / case.name / "audit"
    run_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(plan, run_dir / "plan.json")
    shutil.copy(trace, run_dir / "trace.jsonl")
    shutil.copy(audit, audit_dir / audit.name)
    result = copy.deepcopy(json.loads(result_path.read_text(encoding="utf-8")))
    case.mutate(result)
    (run_dir / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return run_dir / "plan.json", run_dir / "result.json", audit_dir / audit.name, run_dir / "trace.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="write tampered copies of C2's sample runs")
    parser.add_argument("--out", required=True)
    out = Path(parser.parse_args(argv).out)
    for case in CASES:
        write_case(case, out)
        print(f"{case.name:22} {case.run_id:22} {case.what}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
