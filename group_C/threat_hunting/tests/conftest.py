import os

import pytest

os.environ["HUNT_FORCE_RULES"] = "1"      # deterministic rule backends in tests


@pytest.fixture
def fake_llm():
    """install(script) puts a scripted LLM behind get_llm() for one test (see tests/fake_llm.py)."""
    from tests.fake_llm import FakeLLM
    from threat_hunting import llm

    def install(script: dict) -> FakeLLM:
        fake = FakeLLM(script)
        llm.set_override(fake)
        return fake
    yield install
    llm.set_override(None)
