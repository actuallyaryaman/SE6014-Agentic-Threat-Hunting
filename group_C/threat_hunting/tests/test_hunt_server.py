"""C2's own MCP server: its tools, run-id checks and the checked follow-up answer."""
import asyncio

import pytest

from hunt_server import server
from threat_hunting import llm

RESULT = {"run_id": "r1", "hypothesis": "h", "verdict": {"label": "SUPPORTED", "confidence": "high"},
          "claims": [{"claim_id": "C-001", "technique": "T1110", "origin": "playbook", "status": "self_checked",
                      "text": "Source 203.0.113.99 produced 30 failed SSH logins", "facts": {"bucket_key": "203.0.113.99", "count": "30"}}]}


def test_tools_are_listed():
    tools = asyncio.run(server.build().list_tools())
    assert {t.name for t in tools} == {"run_hunt", "get_hunt", "list_hunts", "follow_up"}


@pytest.mark.parametrize("run_id", ["../../etc", "a/b", "", "no-such-run"])
def test_get_hunt_only_reads_existing_runs(run_id):
    with pytest.raises(ValueError):
        server._load(run_id)


def test_answers_must_stay_within_the_cited_findings(fake_llm):
    fake_llm({"chat": [{"answer": "Source 203.0.113.99 failed 30 times (C-001).", "cited": ["C-001"]},
                       {"answer": "It also reached 10.9.9.9 on 445.", "cited": ["C-001"]},
                       {"answer": "It failed 30 times.", "cited": []}]})
    llm.start_trace(None)
    ok = asyncio.run(server.answer("what did it do?", RESULT))
    assert ok["answer_check"] == "ok" and ok["cited"] == ["C-001"]
    for _ in range(2):
        bad = asyncio.run(server.answer("what did it do?", RESULT))
        assert bad["answer"] is None and bad["answer_check"].startswith("answer withheld")


def test_without_an_llm_there_is_no_answer():
    llm.start_trace(None)
    assert asyncio.run(server.answer("q", RESULT)) == {"answer": None, "answer_check": "no LLM configured"}
