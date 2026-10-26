#!/usr/bin/env python3
"""Local B3 -> A2 HTTPS ES -> MCP -> C2 SSH hunt, with no live LLM.

Uses C2's existing development C1 stand-in and optionally C3's verifier.
It does not certify final C1 or modify Group C's files/environment. See DEMO_RUNBOOK.md.
"""

import argparse
import io
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import socket
import time
import signal
import subprocess
import tarfile
from datetime import datetime, timezone

from check_a1_a2_integration import Integration, REPO, command
from group_B.agentic_ingestion import ExecutionConfig, InspectionPolicy, SourceSpec, onboard
from group_B.common import load_b1_recognizer
from group_B.schema_generation.registry import SchemaRegistry
from group_B.agentic_ingestion.planner import plan_source


class HuntDemo(Integration):
    def c2_snapshot(self, python, c2_ref="HEAD", c3_ref=None):
        root = self.root / "c2"
        root.mkdir()
        data = subprocess.check_output(["git", "archive", c2_ref + ":group_C/threat_hunting"], cwd=REPO)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(root, filter="data")
        assert not (root / ".env").exists() and not (root / ".env.test").exists()
        if c3_ref:
            data = subprocess.check_output(["git", "archive", c3_ref, "group_C/threat_hunting/evidence"], cwd=REPO)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                archive.extractall(self.root / "c3", filter="data")
            self.c3_root = self.root / "c3"
            self.report["c3_commit"] = command("git", "rev-parse", c3_ref)
        self.report["c2_commit"] = command("git", "rev-parse", c2_ref)
        self.c2_root = root
        self.hunt_python = str(python.absolute())
        self.report["c2_tree"] = command("git", "rev-parse", c2_ref + ":group_C/threat_hunting")
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
        self.hunt_env["HUNT_ES_MCP_CMD"] = self.hunt_python + " -m " + self.es_mcp_module
        if self.llm_env_file:
            allowed = {"LLM_PROVIDER", "LLM_BASE_URL", "LLM_API_KEY", "HUNT_MODEL"}
            values = {}
            for line in self.llm_env_file.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    name, value = line.split("=", 1)
                    if name.strip() in allowed:
                        values[name.strip()] = value.strip().strip("\"'")
            if not all(values.get(k) for k in allowed):
                raise ValueError("provider config needs LLM_PROVIDER, LLM_BASE_URL, LLM_API_KEY and HUNT_MODEL")
            self.secrets.append(values["LLM_API_KEY"])
            self.llm_settings = dict(values, HUNT_FORCE_RULES="0", HUNT_LLM_MAX_CALLS="8",
                                     HUNT_AGENT_MAX_STEPS="2", LLM_TIMEOUT_S="45")
            self.report["llm"] = {"provider": values["LLM_PROVIDER"], "model": values["HUNT_MODEL"],
                                  "max_calls_per_hunt": 8, "max_investigator_steps": 2}
        self.report["es_mcp_module"] = self.es_mcp_module
        self.case("isolated_c2_snapshot_and_readonly_key")
        settings = self.ls_env.read_text()
        assert "A2_INDEX_PREFIX=security-events\n" in settings
        self.ls_env.write_text(settings.replace("A2_INDEX_PREFIX=security-events\n",
                                                "A2_INDEX_PREFIX=security-events-c2test\n"))
        self.case("a2_and_hunt_index_namespace_aligned")

    def start_a3(self, pipelines):
        self.stop_a3()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.a3_url = f"udp://127.0.0.1:{port}"
        log = self.root / "a3.log"
        log.write_text("")
        self.a3_log = log.open("a")
        root = REPO / "group_A/A3_Stream_Ingestion"
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONUNBUFFERED": "1", "A3_UDP_PORT": str(port),
               "LOGSTASH_URL": self.push_url, "A3_ALLOW_B3_RAW": "true", "A3_B3_PIPELINES": ",".join(pipelines)}
        self.a3_process = subprocess.Popen([self.hunt_python, str(root / "receiver.py")], cwd=root, env=env,
                                           stdout=self.a3_log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if self.a3_process.poll() is not None:
                raise RuntimeError("A3 receiver failed to start")
            if "Receiver listening" in log.read_text():
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("A3 receiver readiness timed out")
        self.report["a3_sha256"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                    for name in ("receiver.py", "event_utils.py", "log_parser.py")}

    def stop_a3(self):
        process = getattr(self, "a3_process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if getattr(self, "a3_log", None):
            self.a3_log.close()
        self.a3_process = None

    def cleanup(self):
        self.stop_a3()
        super().cleanup()

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
        if self.stream_mode:
            self.start_a3(["linux-auth"])
        config = ExecutionConfig(push_url=self.push_url, a3_udp_url=getattr(self, "a3_url", "udp://127.0.0.1:9999"), index_prefix="security-events-c2test",
                                 search_pattern="security-events-c2test*", audit_path=self.root / "audit.jsonl",
                                 verify_attempts=20, verify_interval=2)
        source = SourceSpec(kind="file", location=str(path), ingest_mode="stream" if self.stream_mode else "push", dry_run=False,
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
        benign = self.api("POST", "/security-events-c2test*/_search", json={"size": 100,
            "query": {"bool": {"filter": [{"term": {"host.name": "BENIGN-SSH"}},
                                            {"term": {"source.ip": "198.51.100.20"}}]}}})["hits"]["hits"]
        self.benign_expected = {hit["_index"] + "/" + hit["_id"] for hit in benign}
        assert len(self.benign_expected) == 4


    def run_hunt(self, run_id, hypothesis, output):
        self.phase("Hunting " + run_id + " through MCP...")
        args = [self.hunt_python, "-m", "threat_hunting.run", hypothesis, "--run-id", run_id]
        env = dict(self.hunt_env)
        if self.llm_env_file:
            env.update(self.llm_settings)  # provider key goes only to C2, never C3's MCP subprocesses
        process = subprocess.Popen(args, cwd=self.c2_root, env=env, text=True,
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
        destination = output / run_id
        shutil.copytree(folder, destination)
        audit = self.c2_root / "audit" / (run_id + ".jsonl")
        if audit.exists():
            shutil.copy2(audit, destination / "mcp-audit.jsonl")
        analytics_audit = self.c2_root / "audit" / (run_id + "-analytics.jsonl")
        if analytics_audit.exists():
            shutil.copy2(analytics_audit, destination / "analytics-audit.jsonl")
        result = json.loads((folder / "result.json").read_text())
        if self.llm_env_file:
            assert result["manifest"]["backend"].startswith("llm:"), "agent fell back to rules"
            llm_file = folder / "llm.jsonl"
            calls = [json.loads(line) for line in llm_file.read_text().splitlines()]
            assert calls and any(row["role"] == "investigator" for row in calls), "investigator made no live LLM call"
        else:
            assert result["manifest"]["planner"] == "rules"
            assert result["manifest"]["backend"].startswith("rules")
        trace = [json.loads(line) for line in (folder / "trace.jsonl").read_text().splitlines()]
        assert trace and all(row["ok"] for row in trace), "MCP tool failed"
        assert {row["server"] for row in trace} == {"es", "analytics"}
        ids = {event for claim in result["claims"] for event in claim["event_ids"]}
        allowed_ids = self.expected if run_id in {"attack", "attack-repeat"} else (
            self.benign_expected if run_id == "benign" and self.llm_env_file else set())
        self.report.setdefault("ground_truth_checks", []).append({
            "run_id": run_id, "actual_label": result["verdict"]["label"],
            "expected_attack_ids": len(self.expected) if run_id in {"attack", "attack-repeat"} else 0,
            "cited_ids": len(ids), "missing_ids": sorted(self.expected - ids) if run_id in {"attack", "attack-repeat"} else [],
            "allowed_scope_ids": len(allowed_ids), "unexpected_ids": sorted(ids - allowed_ids),
        })
        expected_c3 = self.check_ground_truth(run_id, result, ids)
        # Check every citation using ES independently of C2's structural self-check.
        for reference in ids:
            index, separator, identifier = reference.partition("/")
            assert separator and index.startswith("security-events-c2test") and re.fullmatch(r"[a-f0-9]{64}", identifier)
            document = self.api("GET", "/" + index + "/_doc/" + identifier)["_source"]
            assert document["event"]["dataset"] == "linux.auth"
            assert document["event"]["original"] and document["labels"]["source_id"] == self.report["onboarding"]["source_id"]
        assert result["manifest"]["mcp_servers"]["es"] == self.hunt_env["HUNT_ES_MCP_CMD"]
        self.report.setdefault("hunts", []).append({"run_id": run_id, "verdict": result["verdict"]["label"],
            "claims": len(result["claims"]), "cited_events": len(ids), "tool_calls": len(trace),
            "self_check": result["self_check"], "independently_checked_ids": len(ids),
            "llm_calls": len(calls) if self.llm_env_file else 0})
        if hasattr(self, "c3_root"):
            self.verify_c3(run_id, folder, output, expected_verdict=expected_c3)
        return result, trace, ids

    def check_ground_truth(self, run_id, result, ids):
        label = result["verdict"]["label"]
        assert not result["self_check"]["failed"], f"{run_id}: failed claim self-check"
        if run_id == "benign" and getattr(self, "llm_env_file", None) and label == "INCONCLUSIVE":
            # C2 INTERFACES 4.2-4.3: verified LLM leads block refutation, never establish support.
            claims = result["claims"]
            assert claims and ids and ids <= self.benign_expected, "benign: leads cite outside independent benign scope"
            assert all(c.get("origin") == "llm" and c.get("status") == "self_checked" for c in claims), "benign: expected LLM leads only"
            assert set(result["verdict"].get("leads", [])) == {c["claim_id"] for c in claims}, "benign: lead attribution differs"
            assert result["verdict"].get("confidence") == "low" and result["verdict"].get("requires_analyst_review") is True, "benign: leads require low confidence and analyst review"
            techniques = result.get("techniques", [])
            assert techniques and all(not t.get("supported") and not t.get("supporting_steps") and not t.get("accepted_claims") for t in techniques), "benign: leads must not count as vetted support"
            return "Inconclusive"
        expected = {"attack": "SUPPORTED", "attack-repeat": "SUPPORTED", "benign": "NOT_SUPPORTED",
                    "missing-host": "INCONCLUSIVE", "empty-window": "INSUFFICIENT_DATA"}[run_id]
        assert label == expected, f"{run_id}: wrong seeded-scenario verdict"
        if run_id in {"attack", "attack-repeat"}:
            assert ids == self.expected, f"{run_id}: citations differ from independent attack ground truth"
        else:
            assert not result["claims"] and not ids, f"{run_id}: unexpected claims for negative scenario"
        return {"SUPPORTED": "Confirmed", "NOT_SUPPORTED": "Refuted",
                "INCONCLUSIVE": "Inconclusive", "INSUFFICIENT_DATA": "Inconclusive"}[expected]

    def verify_c3(self, run_id, folder, output, *, expected_verdict):
        destination = output / run_id / "c3"
        destination.mkdir()
        env = dict(self.hunt_env)
        env.update(PYTHONPATH=os.pathsep.join((str(self.c3_root), str(self.c2_root))),
                   C3_MCP_COMMAND=self.hunt_python, C3_MCP_ARGS="-m " + self.es_mcp_module,
                   C3_MCP_ANALYTICS_COMMAND=self.hunt_python,
                   C3_MCP_ANALYTICS_ARGS="-m analytics_server.server", C3_MCP_CWD=str(self.c2_root))
        base = [self.hunt_python, "-m", "group_C.threat_hunting.evidence.cli"]
        bundle = destination / "bundle.json"
        commands = [base + ["from-run", "--plan", str(folder / "plan.json"), "--result", str(folder / "result.json"),
                           "--audit", str(self.c2_root / "audit" / (run_id + ".jsonl")), "--out", str(bundle)],
                    base + ["report", "--bundle", str(bundle), "--verify", "mcp", "--out-dir", str(destination),
                            "--formats", "json,md,html"]]
        for args in commands:
            done = subprocess.run(args, cwd=self.c2_root, env=env, text=True, capture_output=True, timeout=180)
            if done.returncode:
                raise RuntimeError(self.redact((done.stdout + done.stderr)[-5000:]))
        reports = [p for p in destination.glob("*.json") if p.name != "bundle.json"]
        assert len(reports) == 1, reports
        report = json.loads(reports[0].read_text())
        assert report["verification_mode"] == "mcp", report["verification_mode"]
        if self.require_c3_agreement:
            checks = report["verification"]
            assert report["decision"]["verdict"] == expected_verdict, report["decision"]
            assert not checks["unsupported"] and not checks["contradicted"] and not checks["unverified"], checks
            replay = checks["replay"]
            assert replay["replayed"] > 0 and replay["identical"] == replay["replayed"], replay
            assert not replay["mismatches"] and not replay["skipped"], replay
        self.report.setdefault("c3_reports", []).append({"run_id": run_id, "decision": report["decision"],
                                                       "verification": report["verification"]})
        self.case("c3_live_mcp_report_" + run_id, verdict=report["decision"]["verdict"])

    def hunts(self, output):
        attack = "An external IP brute-forced SSH on DEMO-SSH and then logged in successfully on 2026-10-25."
        if self.llm_env_file:
            self.run_hunt("attack", attack, output)
            self.run_hunt("benign", attack.replace("DEMO-SSH", "BENIGN-SSH"), output)
            self.run_hunt("attack-repeat", attack, output)
            return
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

    def extra_stream_cases(self):
        registry = SchemaRegistry(self.root / "extra-registry")
        recognizer = load_b1_recognizer("group_B.B1.recognizer:recognise")
        approved = {"apache_access": "apache-access", "windows_json": "windows-json", "linux_auth": "linux-auth"}
        for kind, path, dataset in self.sources("stream"):
            if kind not in ("apache", "json", "csv"):
                continue
            if kind == "apache":
                with path.open("a") as f:
                    f.write('\n192.0.2.10 - - [25/Oct/2026:00:00:00 +0000] "TRACE /" 400 0 "-" "-"')
            source = SourceSpec(kind="file", location=str(path), dataset_hint=dataset, ingest_mode="stream", dry_run=False)
            policy = InspectionPolicy(allowed_roots=(path.parent,))
            options = dict(registry=registry, recognizer=recognizer, known_pipelines=approved)
            plan = plan_source(source, policy, **options)
            assert plan.status == "planned", plan.reasons
            self.start_a3([plan.pipeline_id])
            config = ExecutionConfig(a3_udp_url=self.a3_url, index_prefix="security-events-c2test",
                                     search_pattern="security-events-c2test*", audit_path=self.root / "extra-audit.jsonl",
                                     verify_attempts=20, verify_interval=2)
            result = onboard(source, policy, config, **options)
            assert result.status == "verified", result.model_dump()
            replay = onboard(source, policy, config, **options)
            assert replay.status == "verified" and replay.submitted_count == 0
            assert result.parse_failure_count == 0 and replay.reused_count == result.record_count
            if kind == "apache":
                hits = self.api("POST", "/security-events-c2test*/_search", json={"size": 200, "query": {"match_all": {}}})["hits"]["hits"]
                assert any("malformed_request" in h["_source"].get("tags", [])
                           and h["_source"]["labels"]["source_id"] == result.source_id for h in hits)
            self.case("a3_stream_" + kind, indexed=result.indexed_count, pipeline_id=result.pipeline_id, replay_submitted=0)
        self.legacy_a3_and_rejection()

    def year_policy_cases(self):
        recognizer = load_b1_recognizer("group_B.B1.recognizer:recognise")
        approved = {"linux_auth": "linux-auth", "firewall_syslog": "firewall-syslog"}
        self.start_a3(list(approved.values()))
        config = ExecutionConfig(a3_udp_url=self.a3_url, index_prefix="security-events-c2test",
                                 search_pattern="security-events-c2test*", audit_path=self.root / "year-audit.jsonl",
                                 verify_attempts=20, verify_interval=2)
        cases = [
            ("linux", "Feb 29 00:15:00 YEAR-SSH sshd[123]: Failed password for demo from 203.0.113.99 port 40000 ssh2", "UTC", "2024-02-29T00:15:00+00:00"),
            ("firewall", "Jan  1 00:15:00 YEAR-FW firewall: Blocked connection from 203.0.113.99 to 192.0.2.10", "Asia/Singapore", "2023-12-31T16:15:00+00:00"),
        ]
        for name, line, zone, expected_time in cases:
            path = self.root / ("sources/year-" + name + ".log")
            path.write_text(line + "\n" + line + "\n")
            policy = InspectionPolicy(allowed_roots=(path.parent,))
            source = SourceSpec(kind="file", location=str(path), ingest_mode="stream", dry_run=False,
                                timezone=zone, log_year=2024)
            options = dict(recognizer=recognizer, known_pipelines=approved)
            blocked = onboard(source.model_copy(update={"log_year": None}), policy, config, **options)
            assert blocked.status == "blocked" and blocked.submitted_count == 0
            result = onboard(source, policy, config, **options)
            assert result.status == "verified" and result.indexed_count == 2 and result.parse_failure_count == 0, result.model_dump()
            hits = self.api("POST", "/security-events-c2test*/_search", json={"size": 10, "query": {
                "term": {"labels.source_id": result.source_id}}})["hits"]["hits"]
            assert len(hits) == 2 and len({h["_source"]["event_id"] for h in hits}) == 2
            for hit in hits:
                doc = hit["_source"]
                assert datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00")) == datetime.fromisoformat(expected_time)
                assert doc["labels"]["log_year"] == "2024" and doc["labels"]["log_timezone"] == zone
                assert doc["labels"]["ingest_pipeline"] == result.pipeline_id
                assert doc["event"]["original"] == line and doc["event"]["id"] == doc["event_id"]
            replay = onboard(source, policy, config, **options)
            assert replay.status == "verified" and replay.submitted_count == 0 and replay.reused_count == 2
            changed = onboard(source.model_copy(update={"log_year": 2028}), policy, config, **options)
            assert changed.status == "failed" and "EXISTING_DOCUMENT_CONFLICT" in changed.error_codes
            missing = self.api("POST", "/_ingest/pipeline/" + result.pipeline_id + "/_simulate", json={
                "docs": [{"_source": {"message": line, "labels": {"envelope": "b3.raw.v1"}}}]})["docs"][0]["doc"]["_source"]
            assert "_parse_failure" in missing["tags"] and "labels.log_year" in missing["error"]["message"]
            self.case("year_policy_" + name, indexed=2, identical_records_distinct_ids=True,
                      log_year=2024, log_timezone=zone, expected_timestamp=expected_time,
                      replay_submitted=0, changed_year_rejected=True, missing_policy_rejected=True)

    def legacy_a3_and_rejection(self):
        self.start_a3([])
        fixtures = REPO / "group_A/A3_Stream_Ingestion/Data/fixed_events.jsonl"
        events = [json.loads(line) for line in fixtures.read_text().splitlines() if line.strip()]
        for event in events:
            event["labels"] = {"source_id": "legacy-a3-e2e"}
        target = int(self.a3_url.rsplit(":", 1)[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for _ in range(2):
                for event in events:
                    sender.sendto(json.dumps(event).encode(), ("127.0.0.1", target))
                    time.sleep(0.02)
        def legacy_hits():
            self.api("POST", "/security-events-c2test*/_refresh")
            hits = self.api("POST", "/security-events-c2test*/_search", json={"size": 200, "query": {"match_all": {}}})["hits"]["hits"]
            return [h["_source"] for h in hits if h["_source"].get("labels", {}).get("source_id") == "legacy-a3-e2e"]
        self.wait("legacy A3 normalized indexing", lambda: len(legacy_hits()) == len(events))
        actual = {d["event"]["id"]: d for d in legacy_hits()}
        assert len(actual) == len(events)
        for event in events:
            doc = actual[event["event"]["id"]]
            assert doc["event_id"] == event["event"]["id"]
            assert doc["event"]["original"] == event["event"]["original"]
            assert doc["labels"]["ingest_mode"] == "stream"
        self.case("legacy_normalized_a3_replay", indexed=len(events), sent=2 * len(events))
        path = self.root / "sources/rejected-stream.log"
        path.write_text("2026-10-25T00:00:00Z demo sshd[123]: Failed password for demo from 192.0.2.10 port 12345 ssh2")
        result = onboard(SourceSpec(kind="file", location=str(path), ingest_mode="stream", dry_run=False, dataset_hint="linux.auth"),
                         InspectionPolicy(allowed_roots=(path.parent,)),
                         ExecutionConfig(a3_udp_url=self.a3_url, index_prefix="security-events-c2test",
                                         search_pattern="security-events-c2test*", audit_path=self.root / "negative-audit.jsonl",
                                         verify_attempts=2, verify_interval=0.2),
                         recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
                         known_pipelines={"linux_auth": "linux-auth"})
        assert result.status == "failed" and result.indexed_count == 0, result.model_dump()
        assert "VERIFICATION_FAILED" in result.error_codes and result.acknowledged_count == 0
        self.case("a3_unapproved_pipeline_never_verified")

    def compare_c4(self, ref, output):
        path = "group_C/threat_hunting/c4_repeatability/compare_c2_results.py"
        data = subprocess.check_output(["git", "show", ref + ":" + path], cwd=REPO)
        script = self.root / "c4_compare.py"
        script.write_bytes(data)
        self.report["c4_commit"] = command("git", "rev-parse", ref)
        self.report["c4_script_sha256"] = hashlib.sha256(data).hexdigest()
        module = runpy.run_path(str(script))
        a, b = (output / name / "result.json" for name in ("attack", "attack-repeat"))
        compared = module["compare"](json.loads(a.read_text()), json.loads(b.read_text()))
        if isinstance(compared, tuple) and len(compared) == 2:
            metrics, errors = compared
            markdown = module["report"](metrics, errors, "attack/result.json", "attack-repeat/result.json")
        elif isinstance(compared, dict):
            metrics, errors = compared, []
            markdown = module["report"](metrics, "attack/result.json", "attack-repeat/result.json")
        else:
            raise TypeError("unsupported C4 comparison API")
        (output / "c4-comparison.json").write_text(json.dumps({"checks": metrics, "errors": errors}, indent=2) + "\n")
        (output / "c4-comparison.md").write_text(markdown)
        if errors:
            self.report["c4"] = {"status": "invalid_input", "errors": errors}
            raise ValueError("C4 input validation failed: " + "; ".join(errors))
        if not isinstance(metrics, dict) or not metrics:
            raise ValueError("C4 returned no comparison checks")
        differing = [name for name, value in metrics.items() if not value["match"]]
        matched = len(metrics) - len(differing)
        self.report["c4"] = {"status": "compared", "matched": matched, "checks": len(metrics),
                             "all_match": not differing, "differing_fields": differing}
        if getattr(self, "require_c4_match", False) and differing:
            raise AssertionError("C4 repeatability differences: " + ", ".join(differing))
        self.case("c4_repeatability_comparison", matched=matched, total=len(metrics))



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hunt-python", type=Path, required=True, help="separate interpreter with C2 requirements")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for synthetic evidence")
    parser.add_argument("--c2-ref", default="HEAD", help="committed C2 snapshot to test")
    parser.add_argument("--c3-ref", help="optional C3 evidence snapshot; does not replace C2")
    parser.add_argument("--es-mcp-module", choices=("dev.es_mcp_standin.server", "es_mcp_server.server"),
                        default="dev.es_mcp_standin.server")
    parser.add_argument("--require-c3-agreement", action="store_true", help="require expected verdicts and full query replay")
    parser.add_argument("--llm-env", type=Path, help="explicit private provider config; enables bounded live agent checks")
    parser.add_argument("--a3-stream", action="store_true", help="send bounded raw records through actual A3 UDP receiver")
    parser.add_argument("--require-c4-match", action="store_true", help="fail on any C4 difference, including execution metadata")
    parser.add_argument("--c4-ref", help="optional pinned C4 comparator snapshot")
    args = parser.parse_args()
    if not args.hunt_python.is_file():
        parser.error("--hunt-python must point to an existing Group C interpreter")
    if args.require_c3_agreement and not args.c3_ref:
        parser.error("--require-c3-agreement needs --c3-ref")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    test = HuntDemo("8b86c10eb5ee5248f087aa6c8273c8fadb82758c")
    test.require_c4_match = args.require_c4_match
    test.llm_env_file = args.llm_env
    test.stream_mode = args.a3_stream
    test.es_mcp_module = args.es_mcp_module
    test.require_c3_agreement = args.require_c3_agreement
    test.report["scope"] = "isolated B3/A2/B1/HTTPS ES/MCP/C2; " + args.es_mcp_module + ("; bounded live LLM" if args.llm_env else "; no live LLM") + "; optional C3/C4"
    status = 1
    try:
        test.source_files()
        test.report["demo_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        test.certificates()
        test.start_es()
        test.credentials()
        test.c2_snapshot(args.hunt_python, args.c2_ref, args.c3_ref)
        test.start_logstash("push")
        test.ingest()
        test.hunts(output)
        if args.c4_ref:
            test.compare_c4(args.c4_ref, output)
        if args.a3_stream and not args.llm_env:
            test.extra_stream_cases()
            test.year_policy_cases()
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
