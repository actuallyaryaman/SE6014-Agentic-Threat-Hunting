import pytest
from threat_hunting import query
from threat_hunting.query import ToolError

T0, T1 = "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"


def test_time_range_required_and_bounded():
    with pytest.raises(ToolError): query.check_range("garbage", T1)
    with pytest.raises(ToolError): query.check_range(T1, T0)
    with pytest.raises(ToolError): query.check_range("2020-01-01T00:00:00Z", "2024-01-01T00:00:00Z")


def test_index_must_have_the_hunt_prefix():
    for bad in (".security", "security-events-*,.kibana", "*", "_all", "logs-*", "security-events-x/../.security", "security-events-..x"):
        with pytest.raises(ToolError): query.check_index(bad, prefix="security-events-")
    assert query.check_index("security-events-*", prefix="security-events-")
    assert query.check_index("security-events-c2test*,security-events-2026.10.01", prefix="security-events-")


def test_forbidden_script_keys_and_unknown_ops():
    with pytest.raises(ToolError): query.build_query(T0, T1, [{"field": "a", "op": "script", "value": "x"}])
    with pytest.raises(ToolError): query._no_forbidden({"query": {"script": {"source": "1"}}})


def test_unknown_field_suggests_correction():
    with pytest.raises(ToolError, match="did you mean"):
        query.build_query(T0, T1, [{"field": "proces.name", "op": "eq", "value": "x"}], known={"process.name": "keyword"})


def test_size_is_capped():
    assert query.cap_size(10_000) == 200


def test_ip_field_never_gets_case_insensitive_or_wildcard():
    q = query.build_query(T0, T1, [{"field": "destination.ip", "op": "eq", "value": "10.0.0.0/8"}], known={"destination.ip": "ip"})
    assert "case_insensitive" not in str(q)
    with pytest.raises(ToolError): query.build_query(T0, T1, [{"field": "destination.ip", "op": "wildcard", "value": "10.*"}], known={"destination.ip": "ip"})


def test_cidr_on_a_non_ip_field_fails_loudly():
    """Dynamic mapping stores IPs as text+keyword; a CIDR there would silently match nothing."""
    known = {"source.ip": "text", "source.ip.keyword": "keyword"}
    with pytest.raises(ToolError, match="ip-typed"):
        query.build_query(T0, T1, must_not=[{"field": "source.ip", "op": "eq", "value": "10.0.0.0/8"}], known=known)


def test_text_fields_use_their_keyword_subfield():
    known = {"user.name": "text", "user.name.keyword": "keyword", "message": "text"}
    q = query.build_query(T0, T1, [{"field": "user.name", "op": "eq", "value": "root"}], known=known)
    assert "user.name.keyword" in str(q)
    assert query.exact_field("user.name", known) == "user.name.keyword"
    with pytest.raises(ToolError): query.build_query(T0, T1, [{"field": "message", "op": "wildcard", "value": "a*"}], known=known)


def test_contains_on_keyword_is_a_substring_wildcard():
    q = query.build_query(T0, T1, [{"field": "process.command_line", "op": "contains", "value": "MiniDump"}], known={"process.command_line": "keyword"})
    assert q["bool"]["filter"][1] == {"wildcard": {"process.command_line": {"value": "*MiniDump*", "case_insensitive": True}}}
    q = query.build_query(T0, T1, [{"field": "message", "op": "contains", "value": "MiniDump"}], known={"message": "text"})
    assert q["bool"]["filter"][1] == {"match_phrase": {"message": "MiniDump"}}


def test_interval_parsing():
    assert query.interval_seconds("60m") == 3600 and query.interval_seconds("1d") == 86400
    for bad in ("", "1w", "0h", "h1"):
        with pytest.raises(ToolError): query.interval_seconds(bad)


def test_tiebreak_sort_field():
    assert query.tiebreak_field({"event.original": "keyword"}) == "event.original"
    assert query.tiebreak_field({"event.original": "text", "event.original.keyword": "keyword"}) == "event.original.keyword"
    assert query.tiebreak_field({}) is None
