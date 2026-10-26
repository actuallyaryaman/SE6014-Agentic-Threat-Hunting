"""LLM layer: per-run trace and budget, scripted override, rules fallback, and what is sent to an OpenAI-compatible server."""
import asyncio
import json

import httpx

from threat_hunting import llm


def test_ask_json_records_every_call_and_falls_back_when_the_budget_is_spent(fake_llm, tmp_path):
    fake_llm({"intake": [{"techniques": ["T1110"]}, {"techniques": ["T1078"]}]})
    t = llm.start_trace(tmp_path / "llm.jsonl", max_calls=1)
    notes: list[str] = []
    assert asyncio.run(llm.ask_json("intake", "system", "user", notes)) == {"techniques": ["T1110"]}
    assert asyncio.run(llm.ask_json("intake", "system", "user", notes)) is None       # budget of 1 spent: rules take over
    assert t.seq == 1 and "budget" in notes[0]
    rec = json.loads((tmp_path / "llm.jsonl").read_text())
    assert rec["role"] == "intake" and rec["prompt_sha256"] and rec["messages"][0]["content"] == "user"


def test_without_an_llm_ask_json_returns_none(tmp_path):
    llm.start_trace(None)
    assert llm.get_llm("intake") is None                       # conftest sets HUNT_FORCE_RULES=1
    assert asyncio.run(llm.ask_json("intake", "s", "u", [])) is None


def test_openai_body_uses_run_temperature_and_json_mode(monkeypatch, tmp_path):
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 7, "completion_tokens": 3}})
    s = llm.LLMSettings(provider="openai", base_url="http://llm.test/v1", api_key="test-only", model="m", json_mode=True)
    client = llm.LLM(s, role="skeptic")
    client._transport = httpx.MockTransport(handler)
    t = llm.start_trace(tmp_path / "llm.jsonl", temperature=0.0)
    assert client.complete_json("sys", "user") == {"ok": True}
    assert sent[0]["temperature"] == 0.0 and sent[0]["response_format"] == {"type": "json_object"}
    assert t.tokens_in == 7 and t.tokens_out == 3
    assert json.loads((tmp_path / "llm.jsonl").read_text())["role"] == "skeptic"
