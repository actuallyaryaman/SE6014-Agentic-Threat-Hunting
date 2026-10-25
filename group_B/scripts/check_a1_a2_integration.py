#!/usr/bin/env python3
"""Opt-in, isolated HTTPS integration using unchanged A1/A2 Logstash pipelines.

Run from the repo root with group_B/.venv/bin/python. Docker access, OpenSSL,
and the pinned ES/Logstash images are required. No existing cluster, Docker
network, credential or data is reused. All owned resources are cleaned up.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from group_B.agentic_ingestion import ExecutionConfig, InspectionPolicy, SourceSpec, onboard
from group_B.common import load_b1_recognizer
from group_B.schema_generation.registry import SchemaRegistry
from group_B.agentic_ingestion.verify import get_field

VERSION = "8.19.23"
ES_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:" + VERSION
LS_IMAGE = "docker.elastic.co/logstash/logstash:" + VERSION
A2_REF = "8b86c10eb5ee5248f087aa6c8273c8fadb82758c"
LABEL = "smtd.b3.integration"


def command(*args, timeout=180):
    return subprocess.check_output(args, cwd=REPO, text=True, stderr=subprocess.STDOUT, timeout=timeout).strip()


class Integration:
    def __init__(self, a2_ref):
        self.root = Path(tempfile.mkdtemp(prefix="smtd-a1-a2-"))
        self.token = secrets.token_hex(6)
        self.network = "smtd-int-" + self.token
        self.containers = []
        self.network_created = False
        self.secrets = []
        self.env_before = {}
        self.admin = None
        self.report = {"started_at": datetime.now(timezone.utc).isoformat(), "a2_ref": a2_ref,
                       "cases": [], "scope": "isolated A1/A2 configurations over authenticated HTTPS"}
        self.a2_ref = a2_ref
        for name in ("certs", "a1", "pull", "push", "incoming", "samples", "sources"):
            (self.root / name).mkdir()

    def redact(self, value):
        for secret in self.secrets:
            value = value.replace(secret, "<REDACTED>")
        return value

    def phase(self, message):
        print(message, flush=True)

    def case(self, name, **details):
        self.report["cases"].append(dict(name=name, status="passed", **details))
        self.phase("PASS " + name)

    def env_file(self, name, values):
        path = self.root / name
        path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
        path.chmod(0o600)
        return path

    def source_files(self):
        paths = {"a1": "group_A/logstash/pipeline/logstash.conf",
                 "pull": "group_A/a2/pipeline/pull.conf",
                 "push": "group_A/a2/push-pipeline/push.conf"}
        hashes = {}
        for name, path in paths.items():
            if name == "a1":
                data = (REPO / path).read_bytes()
            else:
                data = subprocess.check_output(["git", "show", self.a2_ref + ":" + path], cwd=REPO)
            (self.root / name / "pipeline.conf").write_bytes(data)
            hashes[path] = hashlib.sha256(data).hexdigest()
        self.report["pipeline_sha256"] = hashes
        self.report["code_head"] = command("git", "rev-parse", "HEAD")
        self.report["harness_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        for image in (ES_IMAGE, LS_IMAGE):
            self.report.setdefault("images", {})[image] = json.loads(command(
                "docker", "image", "inspect", image))[0]["RepoDigests"]
        shutil.copy2(REPO / "group_A/sample-data/security-events.ndjson",
                     self.root / "samples/security-events.ndjson")

    def certificates(self):
        certs = self.root / "certs"
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SMTD isolated integration CA", "-keyout", str(certs / "ca.key"),
                "-out", str(certs / "http_ca.crt"))
        command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=elasticsearch", "-keyout", str(certs / "server.key"),
                "-out", str(certs / "server.csr"))
        extensions = certs / "extensions.cnf"
        extensions.write_text("subjectAltName=DNS:elasticsearch,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        command("openssl", "x509", "-req", "-in", str(certs / "server.csr"), "-CA", str(certs / "http_ca.crt"),
                "-CAkey", str(certs / "ca.key"), "-CAcreateserial", "-days", "2",
                "-extfile", str(extensions), "-out", str(certs / "server.crt"))
        for path in certs.glob("*.key"):
            path.chmod(0o600)
        # Mount only public trust/server material; the CA signing key stays host-only.
        self.ssl = ssl.create_default_context(cafile=str(certs / "http_ca.crt"))

    def start_es(self):
        self.phase("Starting isolated authenticated HTTPS Elasticsearch...")
        command("docker", "network", "create", "--label", LABEL + "=" + self.token, self.network)
        self.network_created = True
        password = secrets.token_urlsafe(32)
        self.secrets.append(password)
        env = self.env_file("es.env", {"ELASTIC_PASSWORD": password})
        name = "smtd-es-" + self.token
        self.containers.append(name)
        certs = self.root / "certs"
        command("docker", "run", "-d", "--rm", "--name", name, "--label", LABEL + "=" + self.token,
                "--network", self.network, "--network-alias", "elasticsearch", "--memory", "1536m", "--cpus", "2",
                "-p", "127.0.0.1::9200", "--env-file", str(env),
                "--tmpfs", "/usr/share/elasticsearch/data:uid=1000,gid=0,mode=0770,size=512m",
                "-v", str(certs / "http_ca.crt") + ":/usr/share/elasticsearch/config/test-ca.crt:ro,z",
                "-v", str(certs / "server.crt") + ":/usr/share/elasticsearch/config/test-server.crt:ro,z",
                "-v", str(certs / "server.key") + ":/usr/share/elasticsearch/config/test-server.key:ro,z",
                "-e", "discovery.type=single-node", "-e", "xpack.security.enabled=true",
                "-e", "xpack.security.autoconfiguration.enabled=false",
                "-e", "xpack.security.http.ssl.enabled=true",
                "-e", "xpack.security.http.ssl.key=test-server.key",
                "-e", "xpack.security.http.ssl.certificate=test-server.crt",
                "-e", "xpack.security.http.ssl.certificate_authorities=test-ca.crt",
                "-e", "ES_JAVA_OPTS=-Xms384m -Xmx384m", ES_IMAGE)
        self.url = "https://" + command("docker", "port", name, "9200/tcp")
        self.admin = httpx.Client(base_url=self.url, auth=("elastic", password), verify=self.ssl,
                                  timeout=10, trust_env=False)
        self.wait("Elasticsearch HTTPS", lambda: self.admin.get("/").status_code == 200)
        assert self.admin.get("/").json()["version"]["number"] == VERSION
        self.case("authenticated_https")
        assert httpx.get(self.url, verify=self.ssl, trust_env=False).status_code == 401
        self.case("unauthenticated_rejected")
        try:
            httpx.get(self.url, timeout=5, trust_env=False)
        except httpx.ConnectError:
            self.case("untrusted_ca_rejected")
        else:
            raise AssertionError("untrusted TLS connection unexpectedly succeeded")

    def wait(self, name, predicate, seconds=180):
        started = last = time.monotonic()
        while time.monotonic() - started < seconds:
            try:
                if predicate():
                    return
            except (httpx.HTTPError, ValueError):
                pass
            if time.monotonic() - last > 20:
                self.phase("Waiting for " + name + "...")
                last = time.monotonic()
            time.sleep(1)
        raise AssertionError(name + " did not become ready")

    def api(self, method, path, **options):
        response = self.admin.request(method, path, **options)
        response.raise_for_status()
        return response.json()

    def credentials(self):
        password = secrets.token_urlsafe(32)
        self.secrets.append(password)
        self.api("PUT", "/_security/role/smtd_logstash", json={
            "cluster": ["monitor", "manage_index_templates", "manage_ilm"],
            "indices": [{"names": ["security-events-*", "a2-quarantine-*"],
                         "privileges": ["write", "create_index", "manage"]}],
        })
        self.api("PUT", "/_security/user/smtd_logstash", json={"password": password, "roles": ["smtd_logstash"]})
        self.ls_env = self.env_file("logstash.env", {
            "ELASTICSEARCH_URL": "https://elasticsearch:9200", "ELASTICSEARCH_USER": "smtd_logstash",
            "ELASTICSEARCH_PASSWORD": password, "A2_INDEX_PREFIX": "security-events",
        })
        values = {"ES_URL": self.url, "ES_CA_CERT": str(self.root / "certs/http_ca.crt"), "ES_VERIFY_CERTS": "true"}
        for role, cluster, privileges in (("READ", [], ["read"]),
                                           ("WRITE", ["manage_pipeline"], ["write", "create_index"])):
            key = self.api("POST", "/_security/api_key", json={"name": "smtd_b3_" + role.lower(),
                "role_descriptors": {"bounded": {"cluster": cluster,
                    "indices": [{"names": ["security-events-*"], "privileges": privileges}]}}})["encoded"]
            self.secrets.append(key)
            values["ES_" + role + "_API_KEY"] = key
        for name, value in values.items():
            self.env_before[name] = os.environ.get(name)
            os.environ[name] = value
        read_headers = {"Authorization": "ApiKey " + values["ES_READ_API_KEY"]}
        denied = self.admin.put("/_ingest/pipeline/forbidden-test", headers=read_headers,
                                 auth=None, json={"processors": [{"set": {"field": "x", "value": "x"}}]})
        assert denied.status_code == 403
        self.case("read_key_cannot_install_pipeline")
        denied = self.admin.post("/security-events-*/_search", auth=None,
                                 headers={"Authorization": "ApiKey " + values["ES_WRITE_API_KEY"]}, json={"size": 0})
        assert denied.status_code == 403
        self.case("write_key_cannot_search")
        for path in (REPO / "group_B/B1/Pipelines").glob("*.json"):
            self.api("PUT", "/_ingest/pipeline/" + path.stem, json=json.loads(path.read_text()))
        self.case("real_b1_pipelines_installed")

    def start_logstash(self, mode):
        self.phase("Starting unchanged " + mode + " Logstash configuration...")
        name = "smtd-ls-" + mode + "-" + self.token
        self.containers.append(name)
        args = ["docker", "run", "-d", "--rm", "--name", name, "--label", LABEL + "=" + self.token,
                "--network", self.network, "--memory", "1536m", "--cpus", "2", "--env-file", str(self.ls_env),
                "-e", "LS_JAVA_OPTS=-Xms384m -Xmx384m", "-e", "XPACK_MONITORING_ENABLED=false",
                "-e", "DEAD_LETTER_QUEUE_ENABLE=true", "-e", "PIPELINE_WORKERS=1", "-e", "LOG_LEVEL=warn",
                "-p", "127.0.0.1::9600", "--tmpfs", "/usr/share/logstash/data:uid=1000,gid=0,mode=0770,size=128m",
                "-v", str(self.root / mode) + ":/usr/share/logstash/pipeline:ro,z",
                "-v", str(self.root / "certs/http_ca.crt") + ":/usr/share/logstash/config/certs/http_ca.crt:ro,z"]
        if mode == "a1":
            args += ["-v", str(self.root / "samples") + ":/usr/share/logstash/ingest_data:ro,z"]
        if mode == "pull":
            args += ["-v", str(self.root / "incoming") + ":/usr/share/logstash/a2_incoming:ro,z"]
        if mode == "push":
            args += ["-p", "127.0.0.1::8088"]
        command(*args, LS_IMAGE)
        api = "http://" + command("docker", "port", name, "9600/tcp")
        with httpx.Client(timeout=3, trust_env=False) as client:
            self.wait("Logstash " + mode, lambda: client.get(api + "/_node/stats/pipelines/main").status_code == 200)
        if mode == "push":
            self.push_url = "http://" + command("docker", "port", name, "8088/tcp")
            endpoint = urlsplit(self.push_url)
            refused = 0
            def listening():
                nonlocal refused
                try:
                    with socket.create_connection((endpoint.hostname, endpoint.port), timeout=2):
                        return True
                except OSError:
                    refused += 1
                    return False
            internal_refusals = 0
            def internal_listener():
                nonlocal internal_refusals
                try:
                    command("docker", "exec", name, "bash", "-c",
                            "exec 3<>/dev/tcp/127.0.0.1/8088", timeout=10)
                    return True
                except subprocess.CalledProcessError:
                    internal_refusals += 1
                    return False
            self.wait("A2 container HTTP listener", internal_listener)
            # The monitoring API can answer before the HTTP input has bound.
            # A TCP-only probe does not inject a health-check event into A2.
            self.wait("A2 HTTP input listener", listening)
            self.case("push_listener_ready", host_refusals=refused, container_refusals=internal_refusals)
        return name

    def count(self):
        return self.api("GET", "/security-events-*/_count", params={"ignore_unavailable": "true"})["count"]

    def refresh(self):
        self.api("POST", "/security-events-*/_refresh", params={"ignore_unavailable": "true"})
        return self.count()

    def a1_baseline(self):
        name = self.start_logstash("a1")
        self.wait("A1 sample indexing", lambda: self.refresh() == 3)
        self.case("a1_unchanged_pipeline_three_events", indexed_count=3)
        command("docker", "rm", "-f", name)
        for index in self.api("GET", "/security-events-*"):
            self.api("DELETE", "/" + index)

    def sources(self, mode):
        # Synthetic fixtures only: no private source records enter Logstash stdout.
        apache = '192.0.2.10 - - [25/Oct/2026:00:00:00 +0000] "GET /demo HTTP/1.1" 200 123 "-" "Demo/1.0"'
        linux = '2026-10-25T00:00:00Z demo sshd[123]: Failed password for demo from 192.0.2.10 port 12345 ssh2'
        windows = json.dumps({"@timestamp": "2026-10-25T00:00:00Z", "Channel": "Security", "EventID": 4625,
                              "Hostname": "demo", "SubjectUserName": "demo", "IpAddress": "192.0.2.10"})
        unknown = json.dumps({"timestamp": "2026-10-25T00:00:00Z", "message": "synthetic unknown source"})
        cases = [("apache", [apache] * 5, "apache.access"), ("linux", [linux] * 5, "linux.auth"),
                 ("windows", [windows] * 5, "Security"), ("json", [unknown] * 61, "test.generated"),
                 ("csv", ["timestamp,message"] + ["2026-10-25T00:00:00Z,synthetic csv"] * 6, "test.csv")]
        for kind, lines, dataset in cases:
            path = self.root / "sources" / (mode + "-" + kind + ".log")
            path.write_text("\n".join(lines))
            yield kind, path, dataset

    def b3_cases(self, mode):
        name = self.start_logstash(mode)
        registry = SchemaRegistry(self.root / "registry")
        recognizer = load_b1_recognizer("group_B.B1.recognizer:recognise")
        approved = {"apache_access": "apache-access", "windows_json": "windows-json", "linux_auth": "linux-auth"}
        config = ExecutionConfig(incoming_dir=self.root / "incoming", push_url=getattr(self, "push_url", "http://127.0.0.1:8088"),
                                 audit_path=self.root / "audit.jsonl", verify_attempts=20, verify_interval=2)
        policy = InspectionPolicy(allowed_roots=(self.root / "sources",))
        for kind, path, dataset in self.sources(mode):
            self.phase("Onboarding " + mode + "/" + kind + "...")
            source = SourceSpec(kind="file", location=str(path), dataset_hint=dataset, ingest_mode=mode, dry_run=False)
            options = dict(registry=registry, recognizer=recognizer, known_pipelines=approved)
            before = self.refresh()
            result = onboard(source, policy, config, **options)
            if result.status != "verified":
                raise AssertionError(json.dumps(result.model_dump(mode="json")))
            assert result.indexed_count == result.record_count and result.parse_failure_count == 0
            docs = self.api("POST", "/security-events-*/_search", json={"size": 100,
                "query": {"term": {"labels.source_id.keyword": result.source_id}}})["hits"]["hits"]
            assert len(docs) == result.record_count
            assert all(hit["_id"] != hit["_source"]["event_id"] for hit in docs), "A2 IDs should be fingerprints"
            assert all(get_field(hit["_source"], "labels.ingest_mode") == mode for hit in docs)
            for hit in docs:
                timestamp = datetime.fromisoformat(hit["_source"]["@timestamp"].replace("Z", "+00:00"))
                assert timestamp == datetime(2026, 10, 25, tzinfo=timezone.utc), "event time was not preserved"
            if kind == "apache":
                assert all(get_field(hit["_source"], "source.ip") == "192.0.2.10" for hit in docs)
            replay = onboard(source, policy, config, **options)
            assert replay.status == "verified" and replay.submitted_count == 0
            assert replay.reused_count == result.record_count
            self.refresh()
            assert self.count() == before + result.record_count
            verified = onboard(source, policy, config, verify_only=True, **options)
            assert verified.status == "verified" and verified.submitted_count == 0
            self.case(mode + "_" + kind, indexed=result.indexed_count, reused=replay.reused_count,
                      pipeline_id=result.pipeline_id, event_time_preserved=True)
        command("docker", "rm", "-f", name)

    def contract_guards_and_audit(self):
        policy = InspectionPolicy(allowed_roots=(self.root / "sources",))
        config = ExecutionConfig(audit_path=self.root / "audit.jsonl")
        source = self.root / "sources/firewall.log"
        source.write_text("Oct 22 10:20:01 demo firewall: Blocked connection from 192.0.2.10 to 198.51.100.1\n")
        result = onboard(SourceSpec(kind="file", location=str(source), dry_run=False, timezone="UTC"),
                         policy, config, recognizer=load_b1_recognizer("group_B.B1.recognizer:recognise"),
                         known_pipelines={"firewall_syslog": "firewall-syslog"})
        assert result.status == "blocked" and result.submitted_count == 0
        self.case("yearless_firewall_blocked")
        result = onboard(SourceSpec(kind="stream", location="udp://127.0.0.1:9999", dry_run=False), policy, config)
        assert result.status == "blocked" and result.error_codes == ("STREAM_CONTRACT_UNRESOLVED",)
        self.case("unagreed_a3_stream_blocked")
        records = [json.loads(line) for line in config.audit_path.read_text().splitlines()]
        started = {r["run_id"] for r in records if r["event"] == "started"}
        completed = [r for r in records if r["event"] == "completed"]
        assert len(started) == len(completed) and started == {r["run_id"] for r in completed}
        assert all(r["status"] in {"verified", "blocked"} for r in completed)
        assert "synthetic unknown source" not in config.audit_path.read_text()
        self.case("durable_audit_pairs", runs=len(completed), entries=len(records))
        for kind in ("json", "csv"):
            candidates = [r["pipeline_id"] for r in self.report["cases"]
                          if r["name"] in {"pull_" + kind, "push_" + kind}]
            if len(candidates) == 2:
                assert candidates[0] == candidates[1]
        self.case("generated_pipeline_reused_across_routes")

    def diagnostics(self):
        result = {}
        for name in self.containers:
            try:
                result[name] = self.redact(command("docker", "logs", "--tail", "20", name, timeout=15))
            except (subprocess.SubprocessError, OSError):
                pass
        return result

    def cleanup(self):
        if self.admin is not None:
            self.admin.close()
        for name in self.containers[::-1]:
            try:
                labels = json.loads(command("docker", "inspect", name, timeout=15))[0]["Config"]["Labels"]
                if labels.get(LABEL) == self.token:
                    command("docker", "rm", "-f", name, timeout=30)
            except subprocess.CalledProcessError:
                pass
        if self.network_created:
            command("docker", "network", "rm", self.network, timeout=30)
        for name, value in self.env_before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(self.root)
        self.report["cleanup"] = "owned containers, network, data, credentials and certificates removed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a2-ref", default=A2_REF)
    parser.add_argument("--output", type=Path, default=Path("/tmp/smtd-a1-a2-results.json"))
    parser.add_argument("--modes", nargs="+", choices=("pull", "push"), default=("pull", "push"))
    parser.add_argument("--skip-a1-baseline", action="store_true", help="debug subset; not full integration evidence")
    args = parser.parse_args()
    test = Integration(args.a2_ref)
    code = 1
    try:
        test.source_files()
        test.certificates()
        test.start_es()
        test.credentials()
        test.report["modes"] = args.modes
        test.report["a1_baseline_skipped"] = args.skip_a1_baseline
        if not args.skip_a1_baseline:
            test.a1_baseline()
        for mode in args.modes:
            test.b3_cases(mode)
        test.contract_guards_and_audit()
        test.report["status"] = "passed"
        test.report["completed_at"] = datetime.now(timezone.utc).isoformat()
        code = 0
    except Exception as error:
        test.report["status"] = "failed"
        # Never serialize HTTP request headers, credentials or unsanitized errors.
        detail = error.output if isinstance(error, subprocess.CalledProcessError) else str(error)
        test.report["error"] = test.redact(detail)
        test.report["diagnostics"] = test.diagnostics()
        test.phase("FAILED: " + test.redact(detail))
    finally:
        test.cleanup()
        args.output.write_text(json.dumps(test.report, indent=2) + "\n")
        print("Report: " + str(args.output), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
