#!/usr/bin/env python3
"""Local B3 -> A2 HTTPS ES -> MCP -> C2 SSH hunt, with no live LLM.

Uses C2's existing development C1 stand-in. It does not certify the final
C1/C3 services or modify Group C's files/environment. See DEMO_RUNBOOK.md.
"""

import argparse
import io
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
from datetime import datetime, timezone

from check_a1_a2_integration import Integration, REPO, command
from group_B.agentic_ingestion import ExecutionConfig, InspectionPolicy, SourceSpec, onboard
from group_B.common import load_b1_recognizer
from group_B.schema_generation.registry import SchemaRegistry


class HuntDemo(Integration):
    def c2_snapshot(self, python):
        root = self.root / "c2"
        root.mkdir()
        data = subprocess.check_output(["git", "archive", "HEAD:group_C/threat_hunting"], cwd=REPO)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(root, filter="data")
        assert not (root / ".env").exists() and not (root / ".env.test").exists()
        self.c2_root = root
        self.hunt_python = str(python.absolute())
        self.report["c2_tree"] = command("git", "rev-parse", "HEAD:group_C/threat_hunting")
        versions = command(self.hunt_python, "-c", "import importlib.metadata,json; print(json.dumps({p:importlib.metadata.version(p) for p in ('mcp','elasticsearch','pydantic','PyYAML')}))")
        self.report["c2_dependencies"] = json.loads(versions)
        template = json.loads((root / "dev/index_template.json").read_text())
        # C2's unchanged development template affects only its test namespace.
        self.api("PUT", "/_index_template/smtd-c2-demo", json=template)
        self.case("c2_test_template_installed")
        key = self.api("POST", "/_security/api_key", json={"name": "smtd_c2_readonly",
            "role_descriptors": {"hunt": {"cluster": [], "indices": [{
                "names": ["security-events-c2test*"], "privileges": ["read", "view_index_metadata"]}]}}})["encoded"]
        self.secrets.append(key)
        # Construct an allowlisted environment. No developer .env or paid API keys.
        self.hunt_env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(root),
                         "ES_URL": self.url, "ES_API_KEY": key,
                         "ES_CA_CERT": str(self.root / "certs/http_ca.crt"),
                         "HUNT_INDEX": "security-events-c2test*", "HUNT_INDEX_PREFIX": "security-events-",
                         "HUNT_FORCE_RULES": "1", "PYTHONUNBUFFERED": "1"}
        self.case("isolated_c2_snapshot_and_readonly_key")
        settings = self.ls_env.read_text()
        assert "A2_INDEX_PREFIX=security-events\n" in settings
        self.ls_env.write_text(settings.replace("A2_INDEX_PREFIX=security-events\n",
                                                "A2_INDEX_PREFIX=security-events-c2test\n"))
        self.case("a2_and_hunt_index_namespace_aligned")

    def ingest(self):
        path = self.root / "sources/ssh-demo.log"
        lines = []
        for i in range(30):
            lines.append(f"2026-10-25T00:10:{i:02d}Z DEMO-SSH sshd[123]: Failed password for demo from 203.0.113.99 port {40000+i} ssh2")
        lines.append("2026-10-25T00:11:00Z DEMO-SSH sshd[123]: Accepted password for demo from 203.0.113.99 port 41000 ssh2")
        for i in range(3):
            lines.append(f"2026-10-25T00:10:{i:02d}Z BENIGN-SSH sshd[456]: Failed password for demo from 198.51.100.20 port {42000+i} ssh2")
        lines.append("2026-10-25T00:11:00Z BENIGN-SSH sshd[456]: Accepted password for demo from 198.51.100.20 port 43000 ssh2")
        path.write_text("\n".join(lines))
        config = ExecutionConfig(push_url=self.push_url, index_prefix="security-events-c2test",
                                 search_pattern="security-events-c2test*", audit_path=self.root / "audit.jsonl",
                                 verify_attempts=20, verify_interval=2)
        source = SourceSpec(kind="file", location=str(path), ingest_mode="push", dry_run=False,
                            dataset_hint="linux.auth")
        policy = InspectionPolicy(allowed_roots=(path.parent,))
        options = dict(recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
                       known_pipelines={"linux_auth": "linux-auth"}, registry=SchemaRegistry(self.root / "registry"))
        result = onboard(source, policy, config, **options)
        assert result.status == "verified", result.model_dump()
        assert result.indexed_count == 35 and result.parse_failure_count == 0
        self.report["onboarding"] = result.model_dump(mode="json")
        replay = onboard(source, policy, config, **options)
        assert replay.status == "verified" and replay.reused_count == 35 and replay.submitted_count == 0
        self.case("b3_a2_real_b1_https_ingestion", indexed=35, replay_submitted=0)
        self.api("POST", "/security-events-c2test*/_refresh")
        hits = self.api("POST", "/security-events-c2test*/_search", json={"size": 100,
            "query": {"term": {"source.ip": "203.0.113.99"}}})["hits"]["hits"]
        self.expected = {hit["_index"] + "/" + hit["_id"] for hit in hits}
        assert len(self.expected) == 31
        self.case("ground_truth_31_attack_events")

    def run_hunt(self, run_id, hypothesis, output):
        self.phase("Hunting " + run_id + " through MCP...")
        args = [self.hunt_python, "-m", "threat_hunting.run", hypothesis, "--run-id", run_id]
        process = subprocess.Popen(args, cwd=self.c2_root, env=self.hunt_env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            raise RuntimeError("C2 hunt exceeded its 180-second limit")
        if process.returncode:
            raise RuntimeError(self.redact((stdout + stderr)[-5000:]))
        folder = self.c2_root / "runs" / run_id
        result = json.loads((folder / "result.json").read_text())
        assert result["manifest"]["planner"] == "rules"
        assert result["manifest"]["backend"].startswith("rules")
        trace = [json.loads(line) for line in (folder / "trace.jsonl").read_text().splitlines()]
        assert trace and all(row["ok"] for row in trace), "MCP tool failed"
        assert {row["server"] for row in trace} == {"es", "analytics"}
        ids = {event for claim in result["claims"] for event in claim["event_ids"]}
        # Check every citation using ES independently of C2's structural self-check.
        for reference in ids:
            index, separator, identifier = reference.partition("/")
            assert separator and index.startswith("security-events-c2test") and re.fullmatch(r"[a-f0-9]{64}", identifier)
            document = self.api("GET", "/" + index + "/_doc/" + identifier)["_source"]
            assert document["event"]["dataset"] == "linux.auth"
            assert document["event"]["original"] and document["labels"]["source_id"] == self.report["onboarding"]["source_id"]
        destination = output / run_id
        shutil.copytree(folder, destination)
        audit = self.c2_root / "audit" / (run_id + ".jsonl")
        if audit.exists():
            shutil.copy2(audit, destination / "mcp-audit.jsonl")
        self.report.setdefault("hunts", []).append({"run_id": run_id, "verdict": result["verdict"]["label"],
            "claims": len(result["claims"]), "cited_events": len(ids), "tool_calls": len(trace),
            "self_check": result["self_check"], "independently_checked_ids": len(ids)})
        return result, trace, ids

    def hunts(self, output):
        attack = "An external IP brute-forced SSH on DEMO-SSH and then logged in successfully on 2026-10-25."
        positive, trace, ids = self.run_hunt("attack", attack, output)
        assert positive["verdict"]["label"] == "SUPPORTED", positive["verdict"]
        assert ids == self.expected and not positive["self_check"]["failed"]
        self.case("attack_supported_exact_ground_truth", cited=31, precision=1.0, recall=1.0)
        negative, _, no_ids = self.run_hunt("benign", attack.replace("DEMO-SSH", "BENIGN-SSH"), output)
        assert negative["verdict"]["label"] == "NOT_SUPPORTED" and not no_ids, negative["verdict"]
        self.case("benign_not_supported")
        missing, _, _ = self.run_hunt("missing-host", attack.replace("DEMO-SSH", "NO-SUCH-HOST"), output)
        assert missing["verdict"]["label"] == "INCONCLUSIVE", missing["verdict"]
        self.case("missing_host_inconclusive")
        empty, _, _ = self.run_hunt("empty-window", attack.replace("2026-10-25", "2030-01-01"), output)
        assert empty["verdict"]["label"] == "INSUFFICIENT_DATA", empty["verdict"]
        self.case("empty_window_insufficient_data")
        repeated, repeated_trace, repeated_ids = self.run_hunt("attack-repeat", attack, output)
        assert repeated["verdict"] == positive["verdict"] and repeated_ids == ids
        assert [r["request_hash"] for r in trace] == [r["request_hash"] for r in repeated_trace]
        assert [c["text"] for c in positive["claims"]] == [c["text"] for c in repeated["claims"]]
        self.case("hunt_repeatability")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hunt-python", type=Path, required=True, help="separate interpreter with C2 requirements")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for synthetic evidence")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    test = HuntDemo("8b86c10eb5ee5248f087aa6c8273c8fadb82758c")
    test.report["scope"] = "isolated B3/A2/ES/MCP/C2 demo; C1 development stand-in; no live LLM or C3"
    status = 1
    try:
        test.source_files()
        test.report["demo_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        test.certificates()
        test.start_es()
        test.credentials()
        test.c2_snapshot(args.hunt_python)
        test.start_logstash("push")
        test.ingest()
        test.hunts(output)
        test.report["status"] = "passed"
        status = 0
    except Exception as error:
        detail = error.output if isinstance(error, subprocess.CalledProcessError) else str(error)
        test.report.update(status="failed", error=test.redact(detail), diagnostics=test.diagnostics())
        test.phase("FAILED: " + test.redact(detail))
    finally:
        test.cleanup()
        test.report["completed_at"] = datetime.now(timezone.utc).isoformat()
        (output / "summary.json").write_text(json.dumps(test.report, indent=2) + "\n")
        print("Demo evidence: " + str(output), flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
