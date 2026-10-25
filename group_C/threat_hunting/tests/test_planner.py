"""Intake (hypothesis -> techniques, entities, window) and the bounded hunt window."""
import asyncio
import json
from datetime import datetime, timezone

from threat_hunting import config, llm, planner

KB = json.loads((config.KNOWLEDGE_DIR / "attack_subset.json").read_text())
SRC = [{"dataset": "linux.auth", "docs": 10, "first_event": "2026-09-20T03:10:00Z", "last_event": "2026-10-25T17:40:00Z"}]


def notes():
    return {"llm_notes": []}


def test_rules_intake_without_an_llm():
    it = asyncio.run(planner.intake("An external IP brute-forced SSH on DEMO-SSH and then logged in successfully.", KB, "", notes()))
    assert it["planner"] == "rules" and it["required"] == ["T1110", "T1078"] and it["hosts"] == ["DEMO-SSH"] and it["window"] is None


def test_llm_entities_must_be_in_the_text_and_techniques_in_the_catalogue(fake_llm):
    fake_llm({"intake": [{"techniques": ["T1110", "T9999"], "hosts": ["demo-ssh", "DC-01"], "ips": ["203.0.113.99", "10.0.0.999x"],
                          "users": ["admin"], "window": {"from": "2026-10-25T10:00:00Z", "to": "2026-10-25T12:00:00Z"},
                          "assumptions": ["morning means 10:00-12:00"]}]})
    llm.start_trace(None)
    h = "Someone brute-forced admin on demo-ssh from 203.0.113.99 this morning."
    it = asyncio.run(planner.intake(h, KB, "2026-10-25T17:40:00Z", notes()))
    assert it["hosts"] == ["demo-ssh"] and it["ips"] == ["203.0.113.99"] and it["users"] == ["admin"]
    assert any("DC-01" in d for d in it["dropped"]) and any("T9999" in d for d in it["dropped"])
    assert it["required"] == ["T1110"] and it["planner"] == "llm"          # keyword match stays required; LLM agreed
    assert it["window"][0] == datetime(2026, 10, 25, 10, tzinfo=timezone.utc)


def test_llm_may_only_add_context_when_the_text_names_a_technique(fake_llm):
    fake_llm({"intake": [{"techniques": ["T1048", "T1071"]}]})
    llm.start_trace(None)
    it = asyncio.run(planner.intake("Data was exfiltrated to the internet.", KB, "", notes()))
    assert it["required"] == ["T1048"] and it["context"] == ["T1071"]


def test_window_from_a_written_date_is_clipped_to_the_needed_data():
    tf, tt, w = planner.hunt_window("brute force on 2026-10-25", SRC, None)
    assert (tf, tt) == ("2026-10-25T00:00:00Z", "2026-10-25T18:00:00Z") and w["basis"] == "date written in the hypothesis"


def test_no_time_means_the_last_24h_of_the_needed_data():
    tf, tt, w = planner.hunt_window("brute force", SRC, None)
    assert (tf, tt) == ("2026-10-24T18:00:00Z", "2026-10-25T18:00:00Z") and "24 h" in w["basis"]


def test_llm_window_must_lie_inside_a_written_date():
    inside = (datetime(2026, 10, 25, 10, tzinfo=timezone.utc), datetime(2026, 10, 25, 12, tzinfo=timezone.utc))
    assert planner.hunt_window("on 2026-10-25", SRC, inside)[:2] == ("2026-10-25T10:00:00Z", "2026-10-25T12:00:00Z")
    outside = (datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 10, 2, tzinfo=timezone.utc))
    assert planner.hunt_window("on 2026-10-25", SRC, outside)[2]["basis"] == "date written in the hypothesis"


def test_long_windows_are_cut_to_31_days_and_empty_days_kept_as_requested():
    year = (datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 10, 25, 18, tzinfo=timezone.utc))
    tf, tt, w = planner.hunt_window("this year", SRC, year)
    assert (tf, tt) == ("2026-09-24T18:00:00Z", "2026-10-25T18:00:00Z") and "31 days" in w["basis"]
    assert planner.hunt_window("on 2030-01-01", SRC, None)[:2] == ("2030-01-01T00:00:00Z", "2030-01-02T00:00:00Z")


def test_check_kind_needs_the_category_and_the_fields():
    vpn = {"categories": ["authentication"], "fields": ["source.ip", "event.outcome", "user.name", "host.name"]}
    assert planner.check_kind("auth", vpn) is None
    assert "do not include 'web'" in planner.check_kind("web", vpn)
    assert "lack ['user.name']" in planner.check_kind("auth", {**vpn, "fields": ["source.ip", "event.outcome"]})
    assert "not one of the kinds" in planner.check_kind("firewall", vpn)
