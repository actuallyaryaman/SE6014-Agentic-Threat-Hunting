"""B1 tests: recogniser, pipeline policy, and (when Elasticsearch is available) the pipelines.

Run from anywhere:   python -m unittest discover -s group_B/B1/tests -v
Set ES_URL (for example http://localhost:9200) to also run the Elasticsearch tests;
without it those tests are skipped. Standard library only.
"""
import json
import os
import sys
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
B1 = os.path.dirname(HERE)
sys.path.insert(0, B1)

from recognise import recognise  # noqa: E402
import load_file  # noqa: E402  (shares the Elasticsearch settings: ES_URL, ES_API_KEY, ES_CA_CERT ...)

REQUIRED = ["@timestamp", "event.dataset", "event.original", "message"]
DATA = os.path.join(HERE, "data")

APACHE = ('76.103.128.42 - - [07/Apr/2017:00:00:00 +0530] "PUT /usr/admin HTTP/1.0" 404 4864 '
          '"http://example.org/" "Mozilla/5.0" 4927')
APACHE_NO_RT = '10.0.0.5 - - [07/Apr/2017:00:00:01 +0000] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "curl/8.0"'
WIN_SECURITY = json.dumps({"@timestamp": "2020-10-22T18:33:36.923Z", "Channel": "Security", "EventID": 5145,
                           "EventType": "AUDIT_SUCCESS", "Severity": "INFO", "SubjectUserName": "pgustavo",
                           "IpAddress": "172.18.39.5", "IpPort": "64546", "Hostname": "MORDORDC.theshire.local"})
WIN_SYSMON = json.dumps({"@timestamp": "2020-10-22T18:34:00.000Z",
                         "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
                         "Hostname": "WKS1.theshire.local", "Image": "C:\\Windows\\System32\\cmd.exe",
                         "ProcessId": 4242, "Message": "Process Create:"})
FIREWALL = "Oct 22 10:20:01 fw01 firewall: Blocked connection from 198.51.100.20 to 203.0.113.10"
LINUX_ISO = ("2026-10-23T16:27:19.047481-04:00 kali sshd-session[275922]: "
             "Failed password for invalid user fakeuser from ::1 port 58244 ssh2")
LINUX_CLASSIC = "Oct  5 09:01:02 web1 sshd[812]: Accepted password for alice from 10.1.2.3 port 50022 ssh2"

# (pipeline id, good lines, bad line)
CASES = {
    "apache-access": ([APACHE, APACHE_NO_RT], "this is not an apache line"),
    "windows-json": ([WIN_SECURITY, WIN_SYSMON], "not json at all"),
    "firewall-syslog": ([FIREWALL], "garbage line"),
    "linux-auth": ([LINUX_ISO, LINUX_CLASSIC], "garbage line"),
}


def find_dir(parent, name):
    """Find a sub-folder ignoring letter case (Pipelines or pipelines)."""
    for entry in os.listdir(parent):
        if entry.lower() == name.lower() and os.path.isdir(os.path.join(parent, entry)):
            return os.path.join(parent, entry)
    raise FileNotFoundError(f"no '{name}' folder in {parent}")


def load_pipelines():
    folder = find_dir(B1, "pipelines")
    out = {}
    for fn in sorted(os.listdir(folder)):
        if fn.endswith(".json"):
            with open(os.path.join(folder, fn), encoding="utf-8") as f:
                out[fn[:-5]] = json.load(f)
    return out


def read_lines(name):
    with open(os.path.join(DATA, name), encoding="utf-8-sig") as f:
        return [l.rstrip("\r\n") for l in f if l.strip()]


def get(doc, dotted):
    """Read 'a.b.c' from a document stored either nested or flat."""
    if dotted in doc:
        return doc[dotted]
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def required_ok(doc):
    """All four required fields present and not empty."""
    for f in REQUIRED:
        v = get(doc, f)
        if v is None or (isinstance(v, str) and not v.strip()):
            return False
    return True


class TestRecogniser(unittest.TestCase):
    def check(self, lines, fmt, dataset, pipeline):
        r = recognise(lines)
        self.assertIs(r["matched"], True)
        self.assertEqual(r["format_id"], fmt)
        self.assertEqual(r["dataset"], dataset)
        self.assertEqual(r["pipeline_id"], pipeline)
        self.assertGreaterEqual(r["confidence"], 0.8)

    def test_apache(self):
        self.check([APACHE, APACHE_NO_RT], "apache_access", "apache.access", "apache-access")

    def test_windows_dataset_is_channel(self):
        self.check([WIN_SECURITY], "windows_json", "Security", "windows-json")

    def test_firewall_sample_file(self):
        self.check(read_lines("firewall_sample.txt"), "firewall_syslog", "firewall", "firewall-syslog")

    def test_linux_sample_file(self):
        self.check(read_lines("linux_auth_sample.txt"), "linux_auth", "linux.auth", "linux-auth")

    def test_linux_classic(self):
        self.check([LINUX_CLASSIC], "linux_auth", "linux.auth", "linux-auth")

    def test_bom_on_first_line(self):
        self.check(["\ufeff" + FIREWALL, FIREWALL], "firewall_syslog", "firewall", "firewall-syslog")

    def test_no_match_has_no_match_fields(self):
        for lines in (["hello world", "not a log"], [], ["", "  "], ["{bad json"]):
            r = recognise(lines)
            self.assertEqual(r, {"matched": False, "reason_code": "no_match"})

    def test_mixed_below_threshold_is_no_match(self):
        self.assertEqual(recognise([FIREWALL, "junk", "junk", "junk"]),
                         {"matched": False, "reason_code": "no_match"})


class TestShim(unittest.TestCase):
    """recognizer.py (the allowlisted import name) exposes the same function."""

    def test_shim_returns_same_result(self):
        import recognizer
        self.assertIs(recognizer.recognise, recognise)
        self.assertEqual(recognizer.recognise([FIREWALL])["matched"], True)

    def test_package_import(self):
        import importlib
        sys.path.insert(0, os.path.dirname(B1))  # folder that contains B1
        try:
            mod = importlib.import_module(os.path.basename(B1) + ".recognizer")
        finally:
            sys.path.pop(0)
        self.assertEqual(mod.recognise(["hello"]), {"matched": False, "reason_code": "no_match"})


class TestPipelinePolicy(unittest.TestCase):
    """B1 policy: no script processors; every pipeline has an on_failure that keeps the required fields."""

    @classmethod
    def setUpClass(cls):
        cls.pipelines = load_pipelines()

    def test_all_four_present(self):
        self.assertEqual(set(self.pipelines), set(CASES))

    def test_no_script_processors(self):
        def walk(procs):
            for p in procs:
                self.assertNotIn("script", p, "script processor found")
                for cfg in p.values():
                    if isinstance(cfg, dict) and "on_failure" in cfg:
                        walk(cfg["on_failure"])
        for name, p in self.pipelines.items():
            with self.subTest(pipeline=name):
                walk(p["processors"])
                walk(p.get("on_failure", []))

    def test_on_failure_keeps_required_fields_and_tags(self):
        for name, p in self.pipelines.items():
            with self.subTest(pipeline=name):
                of = p.get("on_failure")
                self.assertTrue(of, "pipeline has no on_failure")
                fields = {list(x.values())[0].get("field") for x in of}
                for f in ["message", "event.original", "@timestamp", "event.dataset", "tags", "error.message"]:
                    self.assertIn(f, fields)
                tag = [x for x in of if "append" in x][0]["append"]
                self.assertIn("_parse_failure", tag["value"])


@unittest.skipUnless(os.environ.get("ES_URL"), "set ES_URL to run Elasticsearch tests")
class TestOnElasticsearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.es = load_file.ES
        cls.pipelines = load_pipelines()
        for name, body in cls.pipelines.items():
            cls.call(f"/_ingest/pipeline/{name}", body, "PUT")

    @classmethod
    def call(cls, path, body, method="POST"):
        req = urllib.request.Request(cls.es + path, data=json.dumps(body).encode(), method=method,
                                     headers={"Content-Type": "application/json"})
        return load_file.send(req)

    def simulate(self, name, lines):
        res = self.call(f"/_ingest/pipeline/{name}/_simulate",
                        {"docs": [{"_source": {"message": l}} for l in lines]})
        return [d["doc"]["_source"] for d in res["docs"]]

    def test_good_lines_have_required_fields_and_no_failure(self):
        for name, (good, _) in CASES.items():
            with self.subTest(pipeline=name):
                for doc in self.simulate(name, good):
                    self.assertTrue(required_ok(doc), doc)
                    self.assertNotIn("_parse_failure", doc.get("tags", []))

    def test_bad_lines_keep_required_fields_and_are_tagged(self):
        for name, (_, bad) in CASES.items():
            with self.subTest(pipeline=name):
                doc = self.simulate(name, [bad])[0]
                self.assertTrue(required_ok(doc), doc)
                self.assertIn("_parse_failure", doc["tags"])
                self.assertTrue(get(doc, "error.message"))

    def test_samples_files_parse_cleanly(self):
        for name, fn in (("firewall-syslog", "firewall_sample.txt"), ("linux-auth", "linux_auth_sample.txt")):
            with self.subTest(pipeline=name):
                for doc in self.simulate(name, read_lines(fn)):
                    self.assertTrue(required_ok(doc), doc)
                    self.assertNotIn("_parse_failure", doc.get("tags", []))

    def test_apache_malformed_requests_are_parsed(self):
        """Scanners send broken request lines; Apache answers 400. They must keep their real time."""
        lines = ['172.17.0.1 - - [26/Oct/2026:01:23:43 +0000] "TRACE /" 400 0 "-" "-"',
                 '172.17.0.1 - - [26/Oct/2026:01:23:56 +0000] "<script>alert(1)</script> / HTTP/1.1" 400 0 "-" "-"']
        for doc in self.simulate("apache-access", lines):
            self.assertNotIn("_parse_failure", doc.get("tags", []), doc)
            self.assertIn("malformed_request", doc["tags"])
            self.assertTrue(get(doc, "@timestamp").startswith("2026-10-26T01:23:"), doc)
            self.assertEqual(get(doc, "source.ip"), "172.17.0.1")
            self.assertEqual(get(doc, "http.response.status_code"), 400)

    def test_b3_yearless_requires_policy_and_normalizes_timezone(self):
        cases = {
            "linux-auth": "Jan  1 00:15:00 host sshd[12]: Failed password for demo from 203.0.113.1 port 4000 ssh2",
            "firewall-syslog": "Jan  1 00:15:00 host firewall: Blocked connection from 203.0.113.1 to 192.0.2.1",
        }
        for name, line in cases.items():
            with self.subTest(pipeline=name):
                def simulate(labels):
                    result = self.call(f"/_ingest/pipeline/{name}/_simulate", {"docs": [
                        {"_source": {"message": line, "labels": dict(labels, envelope="b3.raw.v1")}}]})
                    return result["docs"][0]["doc"]["_source"]
                for labels in ({}, {"log_year": "2024"}, {"log_timezone": "UTC"}):
                    self.assertIn("_parse_failure", simulate(labels)["tags"])
                doc = simulate({"log_year": "2024", "log_timezone": "Asia/Singapore"})
                self.assertNotIn("_parse_failure", doc.get("tags", []), doc)
                self.assertEqual(doc["@timestamp"], "2023-12-31T16:15:00.000Z")
                self.assertEqual(doc["event"]["original"], line)

    def simulate_labels(self, name, line, labels):
        res = self.call(f"/_ingest/pipeline/{name}/_simulate",
                        {"docs": [{"_source": {"message": line, "labels": labels}}]})
        return res["docs"][0]["doc"]["_source"]

    def test_log_year_is_used_for_yearless_timestamps(self):
        doc = self.simulate_labels("firewall-syslog", FIREWALL, {"log_year": "2024"})
        self.assertTrue(get(doc, "@timestamp").startswith("2024-10-22T10:20:01"), doc)
        self.assertEqual(get(doc, "labels.log_year"), "2024")
        doc = self.simulate_labels("linux-auth", LINUX_CLASSIC, {"log_year": 2023})
        self.assertTrue(get(doc, "@timestamp").startswith("2023-10-05T09:01:02"), doc)

    def test_log_year_does_not_change_iso_timestamps(self):
        doc = self.simulate_labels("linux-auth", LINUX_ISO, {"log_year": "2019"})
        self.assertTrue(get(doc, "@timestamp").startswith("2026-10-23T20:27:19"), doc)

    def test_without_log_year_current_year_is_used(self):
        import datetime
        doc = self.simulate("firewall-syslog", [FIREWALL])[0]
        self.assertTrue(get(doc, "@timestamp").startswith(str(datetime.datetime.now(datetime.timezone.utc).year)), doc)

    def test_bad_log_year_is_a_parse_failure_not_a_crash(self):
        for value in ("abcd", "202", "20245", "20x4", "0000"):
            with self.subTest(value=value):
                doc = self.simulate_labels("firewall-syslog", FIREWALL, {"log_year": value})
                self.assertIn("_parse_failure", doc["tags"])
                self.assertTrue(required_ok(doc), doc)

    def test_windows_attack_event(self):
        doc = self.simulate("windows-json", [WIN_SECURITY])[0]
        self.assertEqual(get(doc, "event.code"), "5145")
        self.assertEqual(get(doc, "event.category"), ["file"])


class TestRequiredOk(unittest.TestCase):
    """The required-field check rejects empty values too."""

    def test_rejects_empty_and_missing(self):
        good = {"@timestamp": "t", "event": {"dataset": "d", "original": "o"}, "message": "m"}
        self.assertTrue(required_ok(good))
        for field, value in (("message", ""), ("message", "   "), ("message", None)):
            bad = dict(good)
            bad[field] = value
            self.assertFalse(required_ok(bad), (field, value))
        self.assertFalse(required_ok({**good, "event": {"dataset": "", "original": "o"}}))
        self.assertFalse(required_ok({k: v for k, v in good.items() if k != "@timestamp"}))


if __name__ == "__main__":
    unittest.main()
