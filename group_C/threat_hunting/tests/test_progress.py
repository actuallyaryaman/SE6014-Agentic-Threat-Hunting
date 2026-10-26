"""Progress on stderr: phases with durations, labelled MCP calls, LLM calls and the phase table; silent unless switched on."""
from threat_hunting import progress


def test_progress_prints_phases_calls_and_a_timing_table(capsys):
    progress.start(True)
    with progress.phase("playbooks", "2 step(s)"):
        with progress.step("T1110-a", "Sources with many failed SSH logins"):
            progress.mcp_call(7, "es", "aggregate", {"agg": "terms", "field": "source.ip",
                                                     "filters": [{"field": "event.dataset", "op": "in", "value": ["linux.auth"]}]},
                              {"total": 60, "result": [{"key": "203.0.113.99", "count": 30}]}, 0.12)
        progress.llm_call("investigator", "deepseek-flash", 1200, 300, 2400)
    times = progress.summary()
    err = capsys.readouterr().err
    assert "▶ playbooks: 2 step(s)" in err and "✔ playbooks done in" in err and "(1 MCP call(s), 1 LLM call(s))" in err
    assert "#7   es.aggregate     [T1110-a] terms source.ip dataset=linux.auth 1 filter(s) → 60 hit(s), 1 bucket(s)  (120 ms)" in err
    assert "llm investigator" in err and "2.4 s" in err and "Phase timings:" in err
    assert set(times) == {"playbooks", "total"}


def test_progress_is_silent_when_off(capsys):
    progress.start(False)
    with progress.phase("planning"):
        progress.log("hidden")
    assert capsys.readouterr().err == "" and "planning" in progress.summary()
