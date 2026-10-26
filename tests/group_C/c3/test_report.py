"""C3 - contracts, report rendering, determinism and CLI."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from group_C.threat_hunting.evidence import HuntBundle, build_report, render_html, render_markdown
from group_C.threat_hunting.evidence.cli import main as cli_main
from group_C.threat_hunting.evidence.contracts import bundle_from_run_dir
from group_C.threat_hunting.evidence.report import canonical_report_json

from .fake_tools import FakeGateway
from .fixture_builder import BUILDERS, FIXTURE_DIR, build_confirmed
from .mini_es import MiniES

SCHEMA_DIR = Path(__file__).resolve().parents[3] / "group_C" / "threat_hunting" / "evidence" / "schemas"


class TestContracts(unittest.TestCase):
    def test_fixtures_up_to_date(self):
        for name, fn in BUILDERS.items():
            on_disk = json.loads((FIXTURE_DIR / f"hunt_bundle_{name}.json").read_text())
            self.assertEqual(on_disk, json.loads(fn().model_dump_json()), f"{name} fixture is stale: rerun fixture_builder")

    def test_schema_matches_model(self):
        schema = json.loads((SCHEMA_DIR / "hunt_bundle.schema.json").read_text())
        self.assertEqual(schema["properties"], HuntBundle.model_json_schema()["properties"], "rerun export-schemas")

    def test_extra_fields_from_c2_are_kept(self):
        data = json.loads(build_confirmed().model_dump_json())
        data["claims"][0]["new_c2_field"] = 1
        self.assertEqual(HuntBundle.model_validate(data).claims[0].model_extra["new_c2_field"], 1)

    def test_bundle_from_hunter_run_folder(self):
        b = build_confirmed()
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "plan.json").write_text(b.plan.model_dump_json())
            (t / "result.json").write_text(json.dumps({
                "run_id": b.run_id, "claims": [c.model_dump() for c in b.claims], "evidence": [e.model_dump() for e in b.evidence],
                "step_results": b.step_results, "coverage": {k: v.model_dump() for k, v in b.notes.coverage.items()},
                "techniques": [{"technique": "T1003.001", "min_support": 2}, {"technique": "T1021.002", "min_support": 2}],
                "notes": [], "gaps": [], "dated": True, "data_sources": b.notes.data_sources}))
            (t / "audit.jsonl").write_text("".join(r.model_dump_json() + "\n" for r in b.audit))
            loaded = bundle_from_run_dir(t / "plan.json", t / "result.json", t / "audit.jsonl")
        self.assertEqual(len(loaded.audit), len(b.audit))
        self.assertEqual(loaded.notes.min_support, {"T1003.001": 2, "T1021.002": 2})
        r = build_report(loaded, FakeGateway(MiniES()))
        self.assertEqual(r.decision.verdict, "Confirmed")


class TestReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build_report(build_confirmed(), FakeGateway(MiniES()))
        cls.md = render_markdown(cls.report)
        cls.html = render_html(cls.report)

    def test_sections(self):
        for h in ("## 1. Summary", "**Why this verdict**", "## 2. Hunt plan", "Success criteria", "Refutation criteria",
                  "## 3. Coverage", "## 4. Findings (verified claims)", "## 5. Claims the verifier rejected",
                  "## 6. Benign explanations and baselines considered", "## 7. Verification summary",
                  "## 8. Limitations and data gaps", "## Appendix A. Every query executed", "## Appendix B. Run metadata"):
            self.assertIn(h, self.md)

    def test_every_call_listed(self):
        for a in self.report.audit:
            self.assertIn(a.call_id, self.md)

    def test_rejected_and_context_split(self):
        self.assertEqual({c.claim_id for c in self.report.rejected}, {"C-008", "C-009", "C-010"})
        self.assertEqual([c.claim_id for c in self.report.context_findings], ["C-007"])
        self.assertNotIn("T1078", self.report.summary)

    def test_every_finding_is_tied_to_a_query_and_window(self):
        for c in self.report.findings:
            qs = self.report.claim_queries[c.claim_id]
            self.assertTrue(qs, c.claim_id)
            self.assertTrue(all(q["call_id"] and q["index"] and q["time_from"] and q["time_to"] for q in qs))
            self.assertTrue(c.event_ids and all("/" in e for e in c.event_ids))
        self.assertEqual(self.report.claim_queries["C-008"], [])   # forged evidence: no audited query
        md = render_markdown(self.report)
        self.assertIn("query: `hunt-lsass-001-0006` aggregate on `logs-firewall-fw-edge`", md)

    def test_deterministic(self):
        again = build_report(build_confirmed(), FakeGateway(MiniES()))
        self.assertEqual(canonical_report_json(self.report), canonical_report_json(again))

    def test_html_escapes(self):
        b = build_confirmed()
        b.plan.hypothesis = "<script>alert(1)</script>"
        html = render_html(build_report(b, FakeGateway(MiniES())))
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_summary_rephrase_guard(self):
        b = build_confirmed()
        bad = build_report(b, FakeGateway(MiniES()), rephrase=lambda base, facts: "Attacker 10.9.9.9 stole 500 files.")
        self.assertEqual(bad.summary_source, "rules")
        good = build_report(b, FakeGateway(MiniES()), rephrase=lambda base, facts: "The attack happened as suspected; review it.")
        self.assertEqual(good.summary_source, "llm")


class TestCli(unittest.TestCase):
    def test_report_command(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as out:
            code = cli_main(["report", "--bundle", str(FIXTURE_DIR / "hunt_bundle_confirmed.json"), "--out-dir", tmp])
            self.assertEqual(code, 0)
            self.assertIn("Verdict: Inconclusive", out.getvalue())          # offline: nothing re-verified
            self.assertEqual(len(list(Path(tmp).iterdir())), 3)

    def test_invalid_bundle(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            bad = Path(tmp) / "bad.json"
            bad.write_text("{}")
            self.assertEqual(cli_main(["report", "--bundle", str(bad), "--out-dir", tmp]), 2)


if __name__ == "__main__":
    unittest.main()
