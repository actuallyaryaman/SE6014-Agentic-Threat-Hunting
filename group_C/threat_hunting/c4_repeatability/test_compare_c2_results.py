import copy
import json
import unittest
from pathlib import Path
from compare_c2_results import compare, normalize

SAMPLE = {
    "hypothesis": "SSH brute force",
    "time_range": {"from": "2026-10-25T00:00:00Z", "to": "2026-10-25T01:00:00Z"},
    "verdict": {"label": "SUPPORTED"},
    "coverage": {"data_sources": {"auth": 1}, "coverage": {"auth": {"coverage_ratio": 1}}},
    "claims": [{"claim_id": "C1", "text": "One login", "evidence_ids": ["E1"], "event_ids": ["event1"]}],
    "evidence": [{"evidence_id": "E1", "event_ids": ["event1"], "excerpt": [{"@timestamp": "2026-10-25T00:01:00Z", "count": 1}]}],
    "queries": [{"query_id": "r1", "request": {"filters": [{"field": "source.ip", "value": "1.2.3.4"}]}}],
    "run_id": "r1",
    "manifest": {"seconds": 1.2, "audit_files": ["audit/r1.jsonl"]},
}

class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.a = copy.deepcopy(SAMPLE)
        self.b = copy.deepcopy(SAMPLE)

    def assert_detects(self, key):
        checks, errors = compare(self.a, self.b)
        self.assertFalse(errors)
        self.assertFalse(checks[key]["match"])

    def test_only_execution_metadata_ignored(self):
        self.b["run_id"] = "r2"
        self.b["queries"][0]["query_id"] = "r2-1"
        self.b["manifest"]["seconds"] = 2.9
        self.b["manifest"]["audit_files"] = ["audit/r2.jsonl"]
        checks, errors = compare(self.a, self.b)
        self.assertFalse(errors)
        self.assertTrue(all(c["match"] for c in checks.values()))

    def test_action_run_path_ignored_but_query_preserved(self):
        self.a["actions"] = {"detections": [{"file": "runs/a/actions/detections/test.yml", "es_query": {"size": 10}}]}
        self.b["actions"] = {"detections": [{"file": "runs/b/actions/detections/test.yml", "es_query": {"size": 10}}]}
        checks, errors = compare(self.a, self.b)
        self.assertFalse(errors)
        self.assertTrue(checks["actions"]["match"])
        self.b["actions"]["detections"][0]["es_query"]["size"] = 20
        self.assert_detects("actions")

    def test_missing_required_field_is_invalid(self):
        del self.b["verdict"]
        checks, errors = compare(self.a, self.b)
        self.assertTrue(errors)
        self.assertEqual(checks, {})

    def test_claim_text_change_detected(self):
        self.b["claims"][0]["text"] = "Two logins"
        self.assert_detects("claims_and_evidence_links")

    def test_evidence_link_change_detected(self):
        self.b["claims"][0]["evidence_ids"] = []
        self.assert_detects("claims_and_evidence_links")

    def test_evidence_content_change_detected(self):
        self.b["evidence"][0]["excerpt"][0]["count"] = 2
        self.assert_detects("evidence_contents")

    def test_event_timestamp_change_detected(self):
        self.b["evidence"][0]["excerpt"][0]["@timestamp"] = "2026-10-25T00:02:00Z"
        self.assert_detects("evidence_contents")

    def test_query_value_change_detected(self):
        self.b["queries"][0]["request"]["filters"][0]["value"] = "5.6.7.8"
        self.assert_detects("queries_and_values")

    def test_phase_timings_are_execution_metadata(self):
        self.a["manifest"]["phase_seconds"] = {"planning": 1.0, "total": 3.0}
        self.b["manifest"]["phase_seconds"] = {"planning": 2.0, "total": 9.0}
        checks, errors = compare(self.a, self.b)
        self.assertFalse(errors)
        self.assertTrue(checks["manifest"]["match"])

    def test_nested_manifest_settings_remain_meaningful(self):
        self.a["manifest"]["controls"] = {"seconds": 5, "phase_seconds": {"limit": 2}}
        self.b["manifest"]["controls"] = {"seconds": 10, "phase_seconds": {"limit": 3}}
        self.assert_detects("manifest")

    def test_zero_claim_negative_results_are_valid(self):
        for verdict in ("NOT_SUPPORTED", "INCONCLUSIVE", "INSUFFICIENT_DATA"):
            with self.subTest(verdict=verdict):
                for value in (self.a, self.b):
                    value["verdict"]["label"] = verdict
                    value["claims"] = []
                    value["evidence"] = []
                checks, errors = compare(self.a, self.b)
                self.assertFalse(errors)
                self.assertTrue(all(c["match"] for c in checks.values()))

    def test_supported_without_claims_is_invalid(self):
        self.b["claims"] = []
        checks, errors = compare(self.a, self.b)
        self.assertEqual(checks, {})
        self.assertIn("SUPPORTED verdict requires claims", "; ".join(errors))

    def test_missing_lists_remain_invalid(self):
        self.b["claims"] = None
        self.b["queries"] = []
        checks, errors = compare(self.a, self.b)
        self.assertEqual(checks, {})
        self.assertTrue(any("claims" in e for e in errors))
        self.assertTrue(any("queries" in e for e in errors))

if __name__ == "__main__":
    unittest.main()
