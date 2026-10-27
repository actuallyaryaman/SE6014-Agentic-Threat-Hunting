"""Regression tests for C3 comparison using the actual saved reports."""
import copy
import json
import unittest
from pathlib import Path
from compare_c3_reports import compare_c3

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / 'group_B' / 'tests' / 'c2_c3_evidence'

class C3ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((EVIDENCE/'attack'/'c3'/'hunt_report_attack.json').read_text())

    def setUp(self):
        self.a = copy.deepcopy(self.original)
        self.b = copy.deepcopy(self.original)

    def assert_diff(self, field):
        checks, errors = compare_c3(self.a, self.b)
        self.assertFalse(errors)
        self.assertFalse(checks[field]['match'])

    def test_identical(self):
        checks, errors = compare_c3(self.a, self.b)
        self.assertFalse(errors)
        self.assertTrue(all(x['match'] for x in checks.values()))

    def test_execution_metadata_ignored(self):
        self.b['report_id'] = 'rpt-second'
        self.b['run_id'] = 'second'
        self.b['generated_at'] = '2026-10-26T09:00:00Z'
        self.b['audit'][0]['call_id'] = 'second-0001'
        self.b['audit'][0]['ts'] = '2026-10-26T09:00:00Z'
        self.b['meta']['seconds'] = 42
        checks, errors = compare_c3(self.a, self.b)
        self.assertFalse(errors)
        self.assertTrue(all(x['match'] for x in checks.values()))

    def test_missing_decision_invalid(self):
        del self.b['decision']
        checks, errors = compare_c3(self.a, self.b)
        self.assertEqual(checks, {})
        self.assertTrue(errors)

    def test_verdict_change(self):
        self.b['decision']['verdict'] = 'Confirmed'
        self.assert_diff('decision')

    def test_confidence_change(self):
        self.b['decision']['confidence'] = 'high'
        self.assert_diff('decision')

    def test_claim_verification_change(self):
        self.b['verification']['contradicted'] = 0
        self.assert_diff('verification')

    def test_replay_change(self):
        self.b['verification']['replay']['identical'] -= 1
        self.assert_diff('verification')

    def test_query_parameter_change(self):
        self.b['audit'][0]['params']['index_pattern'] = 'different-index*'
        self.assert_diff('audit')

    def test_event_timestamp_change(self):
        self.b['findings'][0]['verified_at'] = '2026-10-26T00:00:00Z'
        self.assert_diff('findings')

    def test_evidence_link_change(self):
        self.b['claim_queries']['C-001'][0]['index'] = 'different-index*'
        self.assert_diff('claim_queries')

if __name__ == '__main__':
    unittest.main()
