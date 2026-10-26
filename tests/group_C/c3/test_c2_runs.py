"""C3 against C2's real run output (``c2_runs/``) and against tampered copies of it.

The log store is replaced by ``RecordedGateway`` (answers from the run's own audit log), so these tests
show that C3 reads the real file formats and catches planted errors; they do not prove anything about Elasticsearch.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from group_C.threat_hunting.evidence.contracts import bundle_from_run_dir
from group_C.threat_hunting.evidence.report import build_report_async, render_html, render_markdown

from .recorded_gateway import RUN_IDS, RecordedGateway, load_run
from .tamper import CASES, SSH, write_case


def report_for(bundle, truth):
    return asyncio.run(build_report_async(bundle, RecordedGateway(truth)))


class TestRealRunFolders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.truth = {r: load_run(r) for r in RUN_IDS}
        cls.reports = {r: report_for(cls.truth[r], cls.truth[r]) for r in RUN_IDS}

    def test_loader_reads_c2_output(self):
        b = self.truth[SSH]
        self.assertEqual(b.c2_verdict.label, "SUPPORTED")
        self.assertEqual([c.c2_status for c in b.claims], ["self_checked", "self_checked"])
        self.assertEqual(b.notes.technique_sources, {"T1110": ["auth"], "T1078": ["auth"]})
        self.assertEqual(b.notes.min_support, {"T1110": 1, "T1078": 1})
        self.assertEqual(len(b.trace), 15)
        self.assertEqual(len(b.queries), 15)         # schema 0.2: every MCP call in result.json queries[]
        self.assertEqual(len(b.audit), 12)       # ES calls, incl. the injection guard search
        self.assertEqual(len(b.analytics_audit), 3)   # audit/<run>-analytics.jsonl
        self.assertEqual(b.c2_verdict.review_reasons[-1], "1 event(s) in the window contain prompt-injection-like text")
        self.assertEqual(b.c2_findings["prompt_injection"]["total"], 1)
        self.assertGreater(len(b.dynamic_steps), 0)

    def test_nested_coverage_is_read(self):
        b = self.truth[SSH]
        self.assertEqual(b.notes.coverage["auth"].total, 631)
        self.assertEqual(b.notes.coverage["auth"].empty_buckets, [])
        self.assertEqual(b.notes.data_sources["sysmon"], 6315)

    def test_untouched_runs_verify_cleanly(self):
        for run_id, r in self.reports.items():
            with self.subTest(run=run_id):
                self.assertEqual(r.verification["unsupported"] + r.verification["contradicted"] + r.verification["unverified"], 0)
                self.assertEqual(r.verification["verified"], r.verification["claims"])
                self.assertEqual(r.verification["replay"]["mismatches"], [])
                self.assertEqual(r.verification["replay"]["skipped"], [])
                self.assertEqual([f["code"] for f in r.flags], ["c2_prompt_injection"], "only C2's own injection finding, no entity or narrative false alarms")

    def test_every_audited_and_analytics_call_replays_identically(self):
        self.assertEqual(self.reports[SSH].verification["replay"]["identical"], 14)       # 12 audited + 2 replayable analytics
        self.assertEqual(self.reports["share-lsass-lateral"].verification["replay"]["identical"], 47)

    def test_self_checked_claims_become_verified_and_keep_c2_status(self):
        for c in self.reports[SSH].findings:
            self.assertEqual((c.status, c.c2_status), ("verified", "self_checked"))

    def test_ioc_claim_backed_by_analytics_call_in_trace(self):
        c8 = next(c for c in self.reports["share-lsass-lateral"].context_findings if c.claim_id == "C-008")
        self.assertEqual(c8.status, "verified")

    def test_high_confidence_follows_design_rule(self):
        # DESIGN 4.1: high = supported, fully covered, at least two independent verified steps. C3 agrees with C2 here.
        for run_id, r in self.reports.items():
            with self.subTest(run=run_id):
                self.assertEqual(r.decision.review.c2_confidence, "high")
                self.assertEqual((r.decision.verdict, r.decision.confidence), ("Confirmed", "high"))
                self.assertEqual(r.decision.review.outcome, "agrees")
                self.assertTrue(r.decision.analyst_review)

    def test_strict_two_log_source_option(self):
        # optional stricter team rule: C3_MIN_LOG_SOURCES=2 lowers these single-source runs to medium
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"C3_MIN_LOG_SOURCES": "2"}):
            r = report_for(load_run(SSH), load_run(SSH))
        self.assertEqual((r.decision.confidence, r.decision.review.outcome), ("medium", "downgraded"))

    def test_dynamic_step_source_is_found_from_the_audited_call(self):
        # T1078-b-<ip> is not in plan.json; its log source must still be 'auth', not the raw index name
        self.assertNotIn("security-events-c2test", self.reports[SSH].decision.review.note)
        self.assertEqual(self.reports[SSH].decision.confidence, "high")

    def test_report_shows_the_c2_verdict(self):
        md = render_markdown(self.reports[SSH])
        self.assertIn("SUPPORTED", md)
        self.assertIn("C2's draft verdict | SUPPORTED (high confidence)", md)
        self.assertIn("C3 review: agrees", md)
        self.assertIn("SUPPORTED", render_html(self.reports[SSH]))

    def test_offline_mode_downgrades_c2_verdict(self):
        from group_C.threat_hunting.evidence.gateways import OfflineGateway
        b = self.truth[SSH]
        r = asyncio.run(build_report_async(b, OfflineGateway()))
        self.assertEqual(r.decision.verdict, "Inconclusive")
        self.assertEqual(r.decision.review.outcome, "downgraded")
        self.assertEqual(r.verification["unverified"], 2)


class TestPlantedErrors(unittest.TestCase):
    """Every case changes one thing in a copy of a real run; C3 must say exactly what the case lists."""

    def test_each_planted_error_is_caught(self):
        for case in CASES:
            with self.subTest(case=case.name), tempfile.TemporaryDirectory() as tmp:
                paths = write_case(case, Path(tmp))
                bundle = bundle_from_run_dir(*paths)
                r = report_for(bundle, load_run(case.run_id))
                got = {c.claim_id: c.status for c in (r.findings + r.context_findings + r.rejected + r.unverified)}
                for claim_id, status in case.expect_claims.items():
                    self.assertEqual(got[claim_id], status, f"{case.name}: {claim_id} ({case.why})")
                self.assertEqual(r.decision.verdict, case.expect_verdict, case.name)
                self.assertEqual(r.decision.review.outcome, case.expect_review, case.name)
                self.assertEqual([f["code"] for f in r.flags if f["code"] != "c2_prompt_injection"], case.expect_flags, case.name)
                if case.expect_flags:
                    self.assertTrue(r.decision.analyst_review)

    def test_only_the_planted_claim_is_rejected(self):
        for case in CASES:
            with self.subTest(case=case.name), tempfile.TemporaryDirectory() as tmp:
                r = report_for(bundle_from_run_dir(*write_case(case, Path(tmp))), load_run(case.run_id))
                rejected = {c.claim_id for c in r.rejected}
                expected = {k for k, v in case.expect_claims.items() if v in ("contradicted", "unsupported")}
                self.assertEqual(rejected, expected, f"{case.name}: no false alarms, no misses")

    def test_originals_are_not_modified(self):
        c2_dir = Path(__file__).with_name("c2_runs")
        before = {p: p.read_bytes() for p in c2_dir.rglob("*") if p.is_file()}
        with tempfile.TemporaryDirectory() as tmp:
            for case in CASES:
                write_case(case, Path(tmp))
        self.assertEqual(before, {p: p.read_bytes() for p in c2_dir.rglob("*") if p.is_file()})


if __name__ == "__main__":
    unittest.main()


class TestPdf(unittest.TestCase):
    def test_pdf_report(self):
        import shutil
        import subprocess

        from group_C.threat_hunting.evidence.report import PdfUnavailable, write_report

        truth = load_run(SSH)
        report = report_for(truth, truth)
        with tempfile.TemporaryDirectory() as tmp:
            try:
                paths = write_report(report, tmp, ["pdf"])
            except PdfUnavailable as exc:
                self.skipTest(str(exc))
            data = paths[0].read_bytes()
            self.assertTrue(data.startswith(b"%PDF"))
            self.assertGreater(len(data), 5000)
            if shutil.which("pdftotext"):
                text = subprocess.run(["pdftotext", "-layout", str(paths[0]), "-"], capture_output=True, text=True).stdout
                for needle in ("share-ssh-bruteforce", "CONFIRMED", "SUPPORTED", "203.0.113.99"):
                    self.assertIn(needle, text)


class TestSchema02(unittest.TestCase):
    """Behaviour added with C2's schema 0.2 (PR #22): injection finding, review reasons, analytics audit, old runs."""

    @classmethod
    def setUpClass(cls):
        cls.truth = load_run(SSH)
        cls.report = report_for(cls.truth, cls.truth)

    def test_c2_injection_finding_is_flagged_and_forces_review(self):
        flag = next(f for f in self.report.flags if f["code"] == "c2_prompt_injection")
        self.assertEqual(flag["count"], 1)
        self.assertTrue(self.report.decision.analyst_review)
        self.assertTrue(any("prompt-injection-like text" in r for r in self.report.decision.reasons))
        self.assertEqual((self.report.decision.verdict, self.report.decision.confidence), ("Confirmed", "high"))

    def test_injection_text_never_changes_a_claim(self):
        self.assertEqual(self.report.verification["verified"], self.report.verification["claims"])

    def test_analytics_calls_are_known_from_their_own_audit_file(self):
        ids = {a.call_id for a in self.truth.analytics_audit}
        self.assertTrue(ids and ids.isdisjoint({r.call_id for r in self.truth.audit}))

    def test_schema_01_runs_still_load(self):
        # runs written before PR #22 have trace.jsonl instead of queries[] and no analytics audit file
        root = Path(__file__).with_name("c2_runs_v01")
        old = load_run(SSH, root)
        self.assertEqual((len(old.queries), len(old.trace), len(old.analytics_audit)), (0, 14, 0))
        r = report_for(old, old)
        self.assertEqual((r.decision.verdict, r.decision.confidence), ("Confirmed", "high"))
