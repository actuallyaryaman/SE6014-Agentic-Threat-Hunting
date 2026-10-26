"""C3 - verdict rules per requirement group."""

from __future__ import annotations

import asyncio
import unittest

from group_C.threat_hunting.evidence import decide, verify_bundle

from .fake_tools import FakeGateway
from .fixture_builder import build_confirmed, build_data_gap, build_missing_host, build_refuted
from .mini_es import MiniES


def verdict_of(bundle, flags=None):
    out = asyncio.run(verify_bundle(bundle, FakeGateway(MiniES())))
    return decide(bundle, out.claims, flags if flags is not None else out.flags), out


class TestVerdict(unittest.TestCase):
    def test_confirmed_high_with_analyst_review(self):
        d, _ = verdict_of(build_confirmed())
        self.assertEqual((d.verdict, d.confidence, d.analyst_review), ("Confirmed", "high", True))
        rows = {r.technique: r for r in d.rows}
        self.assertEqual(rows["T1003.001"].supporting_steps, ["T1003.001-b", "T1003.001-c", "T1003.001-d"])
        self.assertTrue(rows["T1021.002"].supported and rows["T1021.002"].covered)

    def test_rejected_claims_never_count(self):
        d, out = verdict_of(build_confirmed())
        rows = {r.technique: r for r in d.rows}
        self.assertEqual(rows["T1003.001"].verified_claims, 3)        # C-008 and C-009 are not counted

    def test_below_minimum_support_is_inconclusive(self):
        b = build_confirmed()
        b.claims = [c for c in b.claims if c.step_id not in ("T1021.002-a", "T1021.002-b")]
        d, _ = verdict_of(b)
        self.assertEqual(d.verdict, "Inconclusive")
        self.assertTrue(any("has 1 of 2 independent indicators" in r for r in d.reasons))

    def test_same_step_in_two_windows_counts_once(self):
        b = build_confirmed()
        for c in b.claims:
            if c.step_id == "T1003.001-c":
                c.step_id = "T1003.001-b@w2"
            if c.step_id == "T1003.001-d":
                c.step_id = "T1003.001-b@w3"
        d, _ = verdict_of(b)
        self.assertEqual({r.technique: r for r in d.rows}["T1003.001"].supporting_steps, ["T1003.001-b"])
        self.assertEqual(d.verdict, "Inconclusive")

    def _one_technique(self):
        b = build_confirmed()
        b.plan.required_techniques = ["T1003.001"]
        b.plan.entities["requirement_groups"] = [{"label": "T1003.001", "kind": "technique", "techniques": ["T1003.001"]}]
        return b

    def test_two_independent_steps_give_high_even_from_one_log_source(self):
        d, _ = verdict_of(self._one_technique())
        self.assertEqual((d.verdict, d.confidence), ("Confirmed", "high"))

    def test_strict_option_needs_two_log_sources(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"C3_MIN_LOG_SOURCES": "2"}):
            d, _ = verdict_of(self._one_technique())
        self.assertEqual((d.verdict, d.confidence), ("Confirmed", "medium"))

    def test_one_verified_step_is_only_medium(self):
        b = self._one_technique()
        b.claims = [c for c in b.claims if c.technique != "T1003.001" or c.step_id == "T1003.001-b"]
        b.notes.min_support = {**b.notes.min_support, "T1003.001": 1}
        d, _ = verdict_of(b)
        self.assertEqual((d.verdict, d.confidence), ("Confirmed", "medium"))

    def test_missing_host_is_inconclusive(self):
        d, _ = verdict_of(build_missing_host())
        self.assertEqual(d.verdict, "Inconclusive")
        self.assertIn("HR-LAPTOP-99", d.reasons[0])
        self.assertTrue(any("host name" in s for s in d.next_steps))

    def test_window_without_data_is_inconclusive_not_refuted(self):
        d, _ = verdict_of(build_data_gap())
        self.assertEqual(d.verdict, "Inconclusive")
        self.assertTrue(any("gap-free" in r for r in d.reasons))

    def test_refuted_when_covered_and_silent(self):
        d, _ = verdict_of(build_refuted())
        self.assertEqual((d.verdict, d.confidence, d.analyst_review), ("Refuted", "medium", False))

    def test_llm_only_support_is_a_lead(self):
        b = build_confirmed()
        for c in b.claims:
            if c.technique == "T1021.002":
                c.origin = "llm"
        d, _ = verdict_of(b)
        self.assertEqual(d.verdict, "Inconclusive")
        self.assertTrue(any(g.llm_leads for g in d.groups))

    def test_techniques_chosen_only_by_llm_never_decide(self):
        b = build_confirmed()
        b.plan.entities["requirement_groups"] = [{"label": t, "kind": "llm", "techniques": [t]} for t in b.plan.required_techniques]
        d, _ = verdict_of(b)
        self.assertEqual(d.verdict, "Inconclusive")

    def test_no_playbook_is_inconclusive(self):
        b = build_refuted()
        b.plan.required_techniques, b.plan.entities["requirement_groups"] = [], []
        b.notes.out_of_scope = "hypothesis is about printer toner"
        d, _ = verdict_of(b)
        self.assertEqual((d.verdict, d.confidence), ("Inconclusive", "low"))

    def test_hostile_text_forces_review(self):
        b = build_refuted()
        d, _ = verdict_of(b, flags=[{"code": "hostile_event_text", "ref": "x/y", "claim_id": "C-1"}])
        self.assertTrue(d.analyst_review)

    def test_offline_never_decides(self):
        from group_C.threat_hunting.evidence import OfflineGateway

        for builder in (build_confirmed, build_refuted):
            b = builder()
            out = asyncio.run(verify_bundle(b, OfflineGateway()))
            self.assertEqual(decide(b, out.claims, out.flags, offline=True).verdict, "Inconclusive")

    def test_unverified_claim_blocks_refuted(self):
        from group_C.threat_hunting.evidence.contracts import Claim

        b = build_refuted()
        b.claims.append(Claim(claim_id="C-X", text="possible transfer", technique="T1048", status="unverified"))
        d = decide(b, b.claims)
        self.assertEqual(d.verdict, "Inconclusive")
        self.assertTrue(any("could not be re-verified" in r for r in d.reasons))


if __name__ == "__main__":
    unittest.main()

class TestReviewRules(unittest.TestCase):
    """INTERFACES 4.3: when an analyst must review, and why."""

    def test_confirmed_needs_review(self):
        d, _ = verdict_of(build_confirmed())
        self.assertTrue(d.analyst_review)
        self.assertIn("a Confirmed verdict is never acted on automatically", d.review_reasons)

    def test_low_confidence_needs_review(self):
        d, _ = verdict_of(build_missing_host())
        self.assertEqual((d.verdict, d.confidence), ("Inconclusive", "low"))
        self.assertTrue(d.analyst_review)
        self.assertIn("confidence is low", d.review_reasons)

    def test_coverage_gap_needs_review(self):
        d, _ = verdict_of(build_data_gap())
        self.assertTrue(d.analyst_review)
        self.assertTrue(any(r.startswith("coverage gap") for r in d.review_reasons))

    def test_failed_claim_needs_review(self):
        b = build_confirmed()
        b.claims[0].facts["host.name"] = "NOT-A-HOST"
        d, out = verdict_of(b)
        self.assertTrue(any("failed verification" in r for r in d.review_reasons))

    def test_gap_threshold_is_five_percent(self):
        from group_C.threat_hunting.evidence.contracts import _coverage_from_result
        block = {"coverage": {"auth": {"total": 9, "n_buckets": 10, "empty_buckets": ["h1"], "coverage_ratio": 0.9}}}
        self.assertIn("auth", _coverage_from_result({"coverage": block})[1])
        block["coverage"]["auth"].update(n_buckets=20, empty_buckets=["h1"], coverage_ratio=0.95)
        self.assertNotIn("auth", _coverage_from_result({"coverage": block})[1])

