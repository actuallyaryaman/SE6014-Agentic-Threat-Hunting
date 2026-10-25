"""Scripted stand-in for threat_hunting.llm.LLM, so agent tests run without a model or a key.

script: {role: [answer, ...]} consumed in order, or {role: fn(system, user) -> answer}. A role with no answer left raises,
which the agent treats like a failed LLM call (it falls back to rules)."""
from __future__ import annotations
import json
from collections import defaultdict
from threat_hunting import llm


class FakeLLM:
    def __init__(self, script: dict):
        self.script = {k: (list(v) if isinstance(v, list) else v) for k, v in script.items()}
        self.prompts: dict[str, list[tuple[str, str]]] = defaultdict(list)

    def bind(self, role):
        return _Bound(self, role)


class _Bound:
    def __init__(self, fake: FakeLLM, role):
        self.fake, self.role, self.model, self.calls = fake, role, "fake-model", []

    def describe(self) -> str:
        return "fake:scripted"

    def complete_json(self, system: str, user: str, max_tokens: int = 2000, model: str | None = None) -> dict:
        llm.check_budget()
        self.fake.prompts[self.role].append((system, user))
        s = self.fake.script.get(self.role)
        if callable(s):
            out = s(system, user)
        elif s:
            out = s.pop(0)
        else:
            raise ValueError(f"no scripted answer for role {self.role!r}")
        llm.record(self.role, self.model, system, [{"role": "user", "content": user}], json.dumps(out), 0, 0, 0)
        return out
