"""Every playbook step must compile against the fields B1's pipelines (plus the C2 Windows extension) produce."""
import pytest
from threat_hunting import config, playbooks
from threat_hunting.query import build_query

T0, T1 = "2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z"
KW = "keyword"
KNOWN = {f: KW for f in (
    "event.dataset", "event.code", "event.action", "event.outcome", "host.name", "user.name", "process.name", "process.executable",
    "process.command_line", "process.parent.name", "winlog.event_data.TargetImage", "winlog.event_data.GrantedAccess", "file.name",
    "file.path", "url.path", "url.original", "url.query", "http.request.method")}
KNOWN.update({"source.ip": "ip", "destination.ip": "ip", "destination.port": "long", "http.response.status_code": "long", "@timestamp": "date"})


@pytest.mark.parametrize("technique", sorted(playbooks.SOURCES))
def test_steps_compile_and_are_scoped(technique):
    steps = playbooks.steps_for(technique, T0, T1, {"hosts": ["WS-01"]})
    assert steps
    for s in steps:
        p = s.params
        assert p["index"] == config.HUNT_INDEX and p["time_from"] == T0 and p["time_to"] == T1
        assert any(f["field"] == "event.dataset" for f in p["filters"]), s.step_id
        build_query(p["time_from"], p["time_to"], p.get("filters"), p.get("must_not"), p.get("any_of"), known=KNOWN)
        for k in ("field", "distinct_field"):
            if p.get(k):
                assert p[k] in KNOWN, (s.step_id, p[k])


def test_tables_are_consistent():
    assert set(playbooks.REQUIRED_FIELDS) == set(playbooks.SOURCES)
    for t, per in playbooks.REQUIRED_FIELDS.items():
        assert set(per) <= set(playbooks.SOURCES[t]) <= set(playbooks.DATASETS), t


def test_dataset_aliases():
    assert playbooks.log_type_of("firewall") == playbooks.log_type_of("firewall.log") == "firewall"
    assert playbooks.log_type_of("Microsoft-Windows-Sysmon/Operational") == "sysmon"
    assert playbooks.log_type_of("aws.s3") is None
