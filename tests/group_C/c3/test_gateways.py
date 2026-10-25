"""C3 - gateways: read-only Elasticsearch replay and an independent MCP connection."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path

from group_C.threat_hunting.evidence import ESGateway, MCPGateway, build_report_async, run_with_gateway
from group_C.threat_hunting.evidence.audit import response_hash
from group_C.threat_hunting.evidence.gateways import ReadOnlyES

from .fake_tools import FakeGateway
from .fixture_builder import build_confirmed
from .mini_es import MiniES
from .servers import MockES


class TestESGateway(unittest.TestCase):
    def test_replay_matches_recorded_hashes(self):
        b = build_confirmed()
        with MockES() as es:
            gw = ESGateway(ReadOnlyES(url=es.url))
            for rec in b.audit:
                if rec.tool in ("search", "aggregate", "count", "coverage_check"):
                    r = asyncio.run(gw.rerun(rec))
                    self.assertEqual(response_hash(rec.tool, r), rec.result_hash, rec.call_id)
                    self.assertEqual(r["total"], rec.total)

    def test_full_report_over_es(self):
        with MockES() as es:
            r = asyncio.run(run_with_gateway(build_confirmed(), ESGateway(ReadOnlyES(url=es.url))))
            methods = {m for m, _ in es.requests}
        self.assertEqual(r.verification_mode, "elasticsearch")
        self.assertEqual((r.decision.verdict, r.decision.confidence), ("Confirmed", "high"))
        self.assertEqual(r.verification["replay"]["identical"], r.verification["replay"]["replayed"])
        self.assertLessEqual(methods, {"GET", "POST"})
        fake = asyncio.run(build_report_async(build_confirmed(), FakeGateway(MiniES())))
        self.assertEqual((r.decision.verdict, sorted(c.claim_id for c in r.findings)),
                         (fake.decision.verdict, sorted(c.claim_id for c in fake.findings)))

    def test_read_only_and_no_scripts(self):
        c = ReadOnlyES(url="http://127.0.0.1:9")
        for method, path in (("DELETE", "/idx"), ("POST", "/_bulk"), ("POST", "/idx/_update/1"),
                             ("POST", "/idx/_delete_by_query"), ("PUT", "/idx/_doc/1")):
            with self.assertRaises(PermissionError):
                c._request(method, path)
        with self.assertRaises(PermissionError):
            c.post("idx", "_search", {"query": {"script": {"script": "1"}}})


@unittest.skipUnless(importlib.util.find_spec("mcp"), "mcp SDK not installed")
class TestMCPGateway(unittest.TestCase):
    def test_full_report_over_mcp(self):
        server = Path(__file__).with_name("fake_mcp_server.py")
        gw = MCPGateway(sys.executable, [str(server)], run_id="hunt-lsass-001-verify")
        r = asyncio.run(run_with_gateway(build_confirmed(), gw))
        self.assertEqual(r.verification_mode, "mcp")
        self.assertEqual(r.decision.verdict, "Confirmed")
        self.assertEqual(r.verification["verified"], 7)
        self.assertEqual(r.verification["replay"]["identical"], r.verification["replay"]["replayed"])


if __name__ == "__main__":
    unittest.main()


class TestEnvExample(unittest.TestCase):
    def test_every_setting_the_code_reads_is_in_env_example(self):
        import re
        from pathlib import Path
        root = Path(__file__).resolve().parents[3]
        pkg = root / "group_C" / "threat_hunting" / "evidence"
        used = set()
        for f in pkg.glob("*.py"):
            used |= set(re.findall(r'getenv\("([A-Z][A-Z0-9_]*)"', f.read_text(encoding="utf-8")))
        example = (root / ".env.example").read_text(encoding="utf-8")
        declared = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]*)=", example, re.M))
        self.assertEqual(sorted(used - declared), [])
        for line in example.splitlines():                      # names only: no secret values
            if line.startswith(("ES_API_KEY=", "ES_PASSWORD=", "ES_USERNAME=")):
                self.assertEqual(line.split("=", 1)[1], "")
