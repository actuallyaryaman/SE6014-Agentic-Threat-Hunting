"""Technique playbooks: vetted query templates the Planner selects and parameterises.
The LLM (when present) chooses which playbooks apply; it does not invent query DSL.
Ported from the prototype's src/hunt/playbooks.py, adapted to the team index (security-events-*), event.dataset and B1's ECS fields."""
from __future__ import annotations
from contextvars import ContextVar
import yaml
from . import config
from .models import PlanStep

BASE = yaml.safe_load((config.KNOWLEDGE_DIR / "baselines.yml").read_text())

# log type -> event.dataset values (both spellings used by the team's pipelines and parsers)
DATASETS = {
    "sysmon": ["Microsoft-Windows-Sysmon/Operational", "windows.sysmon"],
    "web": ["apache.access", "nginx.access"],
    "firewall": ["firewall", "firewall.log"],
    "auth": ["linux.auth"],
}
SOURCES = {"T1003.001": ["sysmon"], "T1059.001": ["sysmon"], "T1021.002": ["sysmon"], "T1071": ["firewall", "sysmon"],
           "T1190": ["web"], "T1048": ["firewall"], "T1110": ["auth"], "T1078": ["auth"], "T1046": ["firewall"]}
# fields a technique cannot be tested without, per log type (checked per dataset by the Planner)
REQUIRED_FIELDS = {
    "T1003.001": {"sysmon": ["event.code", "host.name", "process.executable", "winlog.event_data.TargetImage", "process.command_line"]},
    "T1059.001": {"sysmon": ["event.code", "process.name", "process.parent.name", "process.command_line"]},
    "T1021.002": {"sysmon": ["event.code", "process.name", "destination.ip", "destination.port"]},
    "T1071": {"firewall": ["destination.ip", "event.action"], "sysmon": ["event.code", "destination.ip"]},
    "T1190": {"web": ["source.ip", "url.path", "url.original", "http.request.method", "http.response.status_code"]},
    "T1048": {"firewall": ["destination.ip", "network.bytes"]},
    "T1110": {"auth": ["source.ip", "event.action", "event.outcome"]},
    "T1078": {"auth": ["source.ip", "event.action", "event.outcome", "user.name"]},
    "T1046": {"firewall": ["source.ip", "destination.ip"]},
}
INTERNAL_DST = [{"field": "destination.ip", "op": "eq", "value": r} for r in BASE["internal_ranges"]]
INTERNAL_SRC = [{"field": "source.ip", "op": "eq", "value": r} for r in BASE["internal_ranges"]]
EID = lambda n: {"field": "event.code", "op": "eq", "value": str(n)}
# What each known kind's events must look like for an unknown dataset to join it (DESIGN.md 5.5): its event.category, and
# fields it must have. Firewall is left out: its playbooks depend on B1's event.action values.
KIND_CATEGORY = {"auth": "authentication", "web": "web", "sysmon": "process"}
KIND_FIELDS = {"auth": ["source.ip", "event.outcome", "user.name"], "web": ["source.ip", "url.path", "http.response.status_code"],
               "sysmon": ["event.code", "host.name", "process.name"]}
# datasets matched to a kind during this run (planner.match_unknown); a ContextVar, so concurrent hunts stay apart
_EXTRA: ContextVar[dict] = ContextVar("dataset_matches", default={})


def set_matches(matches: dict[str, list[str]]):
    _EXTRA.set({k: list(v) for k, v in matches.items()})


def matched(log_type: str) -> list[str]:
    return _EXTRA.get().get(log_type, [])


def ds(log_type: str) -> dict:
    return {"field": "event.dataset", "op": "in", "value": DATASETS[log_type] + matched(log_type)}


def native(log_type: str) -> dict:
    """Only the dataset names the playbook was written for (their event.action values are known)."""
    return {"field": "event.dataset", "op": "in", "value": DATASETS[log_type]}


def log_type_of(dataset: str) -> str | None:
    return next((t for t, v in DATASETS.items() if dataset in v + matched(t)), None)


def _s(tid, technique, tool, params, purpose, role="indicator", claim="", analysis=None, must=False):
    return PlanStep(step_id=tid, technique=technique, tool=tool, params={"index": config.HUNT_INDEX, **params}, purpose=purpose,
                    role=role, claim_template=claim, analysis=analysis or {}, must_have=must)


# ---- playbooks promoted from LLM drafts (python -m threat_hunting.promote); loaded at plan time. A promoted playbook either
# covers a technique no built-in playbook has, or adds a data source to one that has (e.g. DNS for exfiltration).
YAML: dict[str, list[dict]] = {}


def refresh() -> dict[str, list[dict]]:
    """Load knowledge/playbooks/*.yml (HUNT_PLAYBOOK_DIR) into SOURCES, REQUIRED_FIELDS and DATASETS. Returns them by technique."""
    for table, builtin in ((DATASETS, _BUILTIN_DATASETS), (SOURCES, _BUILTIN_SOURCES), (REQUIRED_FIELDS, _BUILTIN_FIELDS)):
        table.clear()                                   # start from the built-in tables, so a removed file stops applying
        table.update({k: (list(v) if isinstance(v, list) else dict(v)) for k, v in builtin.items()})
    YAML.clear()
    d = config.PLAYBOOK_DIR
    for f in sorted(d.glob("*.yml")) if d.exists() else []:
        pb = yaml.safe_load(f.read_text())
        if not isinstance(pb, dict) or pb.get("status") != "approved":
            continue
        t, kind = pb["technique"], pb["kind"]
        DATASETS[kind] = sorted(set(DATASETS.get(kind, [])) | set(pb["datasets"]))
        SOURCES[t] = SOURCES.get(t, []) + ([kind] if kind not in SOURCES.get(t, []) else [])
        REQUIRED_FIELDS.setdefault(t, {})[kind] = pb.get("required_fields", [])
        YAML.setdefault(t, []).append({**pb, "file": f.name})
    return YAML


def builtin_datasets(technique: str) -> set[str]:
    """The datasets the built-in playbook of a technique already hunts (empty if it has none)."""
    return {d for k in _BUILTIN_SOURCES.get(technique, []) for d in _BUILTIN_DATASETS.get(k, []) + matched(k)}


def steps_from_yaml(pb: dict, tf: str, tt: str) -> list[PlanStep]:
    """A promoted (or candidate) playbook's steps over a window, scoped to its own datasets."""
    scope = {"field": "event.dataset", "op": "in", "value": pb["datasets"]}
    return [_s(st["id"], pb["technique"], st["tool"], {"time_from": tf, "time_to": tt, **st["params"],
                                                        "filters": [scope] + st["params"].get("filters", [])},
               st["purpose"], claim=st.get("claim_template", ""), analysis=st.get("analysis", {}), must=True)
            for st in pb["steps"]]


def _auth_variants(technique: str, T: dict, host: list) -> list[PlanStep]:
    """Auth datasets matched by their ECS fields: generic filters (event.category/outcome) instead of SSH's event.action."""
    out = []
    for d in matched("auth"):
        fail = [{"field": "event.dataset", "op": "eq", "value": d}, {"field": "event.category", "op": "eq", "value": "authentication"},
                {"field": "event.outcome", "op": "eq", "value": "failure"}]
        if technique == "T1110":
            out.append(_s(f"T1110-a@{d}", technique, "aggregate", {**T, "agg": "terms", "field": "source.ip", "size": 20, "filters": fail + host},
                          f"Sources with many failed logins in {d} (dataset matched to auth by its ECS fields)",
                          claim=f"Source {{bucket_key}} produced {{count}} failed logins in {d}",
                          analysis={"bucket_min_count": BASE["bruteforce_min_failures"], "drilldown": "source.ip"}, must=True))
        if technique == "T1078":
            out.append(_s(f"T1078-a@{d}", technique, "aggregate", {**T, "agg": "terms", "field": "source.ip", "size": 20, "filters": fail + host},
                          f"Brute-force candidates in {d}; the Hunter then searches for successful logins after them",
                          analysis={"bucket_min_count": BASE["bruteforce_min_failures"]}))
    return out


def steps_for(technique: str, tf: str, tt: str, scope: dict) -> list[PlanStep]:
    """The built-in steps of a technique (if any), then the steps of its promoted playbooks."""
    promoted = [s for pb in YAML.get(technique, []) for s in steps_from_yaml(pb, tf, tt)]
    return (_builtin_steps(technique, tf, tt, scope) if technique in _BUILTIN_SOURCES else []) + promoted


def _builtin_steps(technique: str, tf: str, tt: str, scope: dict) -> list[PlanStep]:
    """scope: {'hosts': [...]} narrows host-scoped steps when the hypothesis names a host."""
    T = {"time_from": tf, "time_to": tt}
    host = [{"field": "host.name", "op": "in", "value": scope["hosts"]}] if scope.get("hosts") else []
    SYS, WEB, FW = ds("sysmon"), ds("web"), ds("firewall")
    if technique == "T1003.001":
        lsass = {"field": "winlog.event_data.TargetImage", "op": "wildcard", "value": "*\\lsass.exe"}
        return [
            _s("T1003.001-a", technique, "aggregate", {**T, "agg": "terms", "field": "process.executable",
               "filters": [SYS, EID(10), lsass] + host, "size": 20},
               "Baseline: which processes open lsass.exe (all, before filtering benign ones)", role="context"),
            _s("T1003.001-b", technique, "search", {**T, "filters": [SYS, EID(10), lsass] + host, "size": 100,
               "must_not": [{"field": "process.executable", "op": "in", "value": BASE["lsass_access_allowlist"]}],
               "fields": ["@timestamp", "host.name", "process.executable", "winlog.event_data.TargetImage", "winlog.event_data.GrantedAccess"]},
               "Process-access events on lsass.exe from processes outside the allowlist", must=True,
               claim="A non-baseline process ({process.executable}) opened lsass.exe on {host.name} with access mask {winlog.event_data.GrantedAccess}",
               analysis={"group_by": ["host.name", "process.executable", "winlog.event_data.GrantedAccess"]}),
            _s("T1003.001-c", technique, "search", {**T, "filters": [SYS, EID(1)] + host, "size": 100,
               "any_of": [{"field": "process.command_line", "op": "contains", "value": v} for v in ("MiniDump", "sekurlsa", "lsass")],
               "fields": ["@timestamp", "host.name", "process.name", "process.command_line", "user.name"]},
               "Process creations whose command line matches known LSASS-dump tooling (MiniDump, sekurlsa, lsass)", must=True,
               claim="A process command line on {host.name} matches LSASS-dump tooling: {process.command_line}",
               analysis={"group_by": ["host.name", "process.command_line"]}),
            _s("T1003.001-d", technique, "search", {**T, "filters": [SYS, EID(11), {"field": "file.name", "op": "wildcard", "value": "*.dmp"}] + host,
               "size": 100, "fields": ["@timestamp", "host.name", "file.path", "process.name"]},
               "Creation of memory-dump files (*.dmp)",
               claim="A memory dump file {file.path} was created on {host.name} by {process.name}",
               analysis={"group_by": ["host.name", "file.path", "process.name"]}),
        ]
    if technique == "T1059.001":
        return [
            _s("T1059.001-a", technique, "search", {**T, "size": 100, "filters": [SYS, EID(1), {"field": "process.name", "op": "eq", "value": "powershell.exe"}] + host,
               "any_of": [{"field": "process.command_line", "op": "contains", "value": v} for v in ("enc", "encodedcommand", "hidden")],
               "fields": ["@timestamp", "host.name", "process.name", "process.parent.name", "user.name"]},
               "PowerShell started with encoded or hidden-window arguments",
               claim="PowerShell with encoded/hidden arguments ran on {host.name} (parent process {process.parent.name})",
               analysis={"group_by": ["host.name", "process.parent.name"]}),
            _s("T1059.001-b", technique, "search", {**T, "size": 100, "filters": [SYS, EID(1),
               {"field": "process.name", "op": "in", "value": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]},
               {"field": "process.parent.name", "op": "in", "value": ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"]}] + host,
               "fields": ["@timestamp", "host.name", "process.name", "process.parent.name"]},
               "Script interpreters spawned by Office applications",
               claim="Office application {process.parent.name} spawned {process.name} on {host.name}",
               analysis={"group_by": ["host.name", "process.parent.name", "process.name"]}),
        ]
    if technique == "T1021.002":
        return [
            _s("T1021.002-a", technique, "search", {**T, "size": 100, "filters": [SYS, EID(1),
               {"field": "process.name", "op": "in", "value": ["PSEXESVC.exe", "psexec.exe", "psexec64.exe", "paexec.exe", "winexesvc.exe"]}],
               "fields": ["@timestamp", "host.name", "process.name", "process.parent.name", "user.name"]},
               "Remote-service execution binaries (PsExec-style) started on any host",
               claim="Remote-service execution binary {process.name} ran on {host.name} (parent {process.parent.name})",
               analysis={"group_by": ["host.name", "process.name"]}, must=True),
            # b (network pivot over Sysmon EID 3) is generated dynamically by the Hunter once seed hosts are known
        ]
    if technique == "T1071":
        return [
            _s("T1071-a", technique, "aggregate", {**T, "agg": "terms", "field": "destination.ip", "size": 10,
               "filters": [FW, {"field": "event.action", "op": "eq", "value": "allowed"}], "must_not": INTERNAL_DST},
               "Most-contacted external destinations through the firewall (beaconing candidates; the firewall log has no ports)",
               claim="External destination {bucket_key} was contacted {count} times through the firewall (possible beaconing)",
               analysis={"bucket_min_count": BASE["beacon_min_connections"], "ioc_enrich": True, "drilldown": "destination.ip"}),
            _s("T1071-b", technique, "search", {**T, "size": 100, "filters": [SYS, EID(3),
               {"field": "process.name", "op": "in", "value": ["powershell.exe", "cmd.exe", "rundll32.exe", "wscript.exe", "mshta.exe", "regsvr32.exe"]}] + host,
               "must_not": INTERNAL_DST, "fields": ["@timestamp", "host.name", "process.name", "destination.ip", "destination.port"]},
               "Script/living-off-the-land binaries making external network connections",
               claim="{process.name} on {host.name} connected to external {destination.ip}:{destination.port}",
               analysis={"group_by": ["host.name", "process.name", "destination.ip", "destination.port"]}),
        ]
    if technique == "T1190":
        return [
            _s("T1190-a", technique, "search", {**T, "size": 100, "must_not": INTERNAL_SRC, "filters": [WEB,
               {"field": "http.request.method", "op": "eq", "value": "POST"}, {"field": "url.path", "op": "wildcard", "value": "*upload*"},
               {"field": "http.response.status_code", "op": "eq", "value": 200}], "fields": ["@timestamp", "source.ip", "url.path", "http.response.status_code"]},
               "Successful file-upload POSTs from external addresses",
               claim="External address {source.ip} uploaded to {url.path} (HTTP {http.response.status_code})",
               analysis={"group_by": ["source.ip", "url.path", "http.response.status_code"]}),
            _s("T1190-b", technique, "search", {**T, "size": 100, "must_not": INTERNAL_SRC, "filters": [WEB,
               {"field": "url.path", "op": "wildcard", "value": "*/uploads/*.php"}], "fields": ["@timestamp", "source.ip", "url.path", "url.query"]},
               "Requests to executable scripts inside upload directories (web shell use)",
               claim="External address {source.ip} requested {url.path} inside an upload directory (possible web shell)",
               analysis={"group_by": ["source.ip", "url.path"], "min_count": 2}),
            _s("T1190-c", technique, "search", {**T, "size": 100, "must_not": INTERNAL_SRC, "filters": [WEB],
               "any_of": [{"field": "url.original", "op": "wildcard", "value": v} for v in ("*union%20select*", "*drop%20table*", "*'%20or%20'*", "*'")],
               "fields": ["@timestamp", "source.ip", "url.path", "http.response.status_code"]},
               "SQL-injection signatures in request URLs",
               claim="External address {source.ip} sent SQL-injection style requests to {url.path}",
               analysis={"group_by": ["source.ip", "url.path"]}),
            _s("T1190-d", technique, "aggregate", {**T, "agg": "terms", "field": "source.ip", "size": 10, "must_not": INTERNAL_SRC,
               "filters": [WEB, {"field": "http.response.status_code", "op": "in", "value": [404, 500]}]},
               "External addresses producing many 404/500 responses (scanning)",
               claim="External address {bucket_key} produced {count} error responses (404/500), consistent with scanning",
               analysis={"bucket_min_count": BASE["scan_min_errors"], "drilldown": "source.ip"}),
        ]
    if technique == "T1048":
        thr = scope.get("exfil_bytes", BASE["exfil_default_bytes"])
        return [
            _s("T1048-a", technique, "aggregate", {**T, "agg": "terms", "field": "destination.ip", "size": 5, "sum_field": "network.bytes",
               "filters": [FW, {"field": "event.action", "op": "eq", "value": "allowed"}], "must_not": INTERNAL_DST},
               f"External destinations ranked by total bytes received (threshold {thr} bytes)",
               claim="External destination {bucket_key} received {sum} bytes over {count} connections",
               analysis={"bucket_min_sum": thr, "drilldown": "destination.ip"}, must=True),
        ]
    fail = [native("auth"), {"field": "event.action", "op": "eq", "value": "ssh_login"}, {"field": "event.outcome", "op": "eq", "value": "failure"}]
    if technique == "T1110":
        return [
            _s("T1110-a", technique, "aggregate", {**T, "agg": "terms", "field": "source.ip", "size": 20, "filters": fail + host},
               "Sources with many failed SSH logins",
               claim="Source {bucket_key} produced {count} failed SSH logins",
               analysis={"bucket_min_count": BASE["bruteforce_min_failures"], "drilldown": "source.ip"}, must=True),
        ] + _auth_variants(technique, T, host)
    if technique == "T1078":
        return [
            _s("T1078-a", technique, "aggregate", {**T, "agg": "terms", "field": "source.ip", "size": 20, "filters": fail + host},
               "Brute-force candidates (sources with many failed SSH logins). The Hunter then searches for successful logins after them; "
               "no candidate means no login after a brute force can exist, so this step is what tests T1078 when nothing is found",
               analysis={"bucket_min_count": BASE["bruteforce_min_failures"]}),
        ] + _auth_variants(technique, T, host)
    if technique == "T1046":
        return [
            # internal destinations only: ordinary browsing reaches hundreds of distinct external addresses
            _s("T1046-a", technique, "aggregate", {**T, "agg": "terms", "field": "source.ip", "distinct_field": "destination.ip", "size": 10,
               "filters": [FW], "any_of": INTERNAL_DST},
               "Sources contacting many distinct internal destinations through the firewall (host scanning; no ports in the firewall log)",
               claim="Source {bucket_key} contacted {distinct} distinct internal destinations in {count} connection attempts",
               analysis={"bucket_min_distinct": BASE["scan_min_distinct"], "drilldown": "source.ip"}, must=True),
        ]
    raise KeyError(technique)


_BUILTIN_DATASETS = {k: list(v) for k, v in DATASETS.items()}
_BUILTIN_SOURCES = {k: list(v) for k, v in SOURCES.items()}
_BUILTIN_FIELDS = {k: {kk: list(vv) for kk, vv in v.items()} for k, v in REQUIRED_FIELDS.items()}
