"""Report pipeline: verify, decide, summarise, then render as JSON, Markdown, HTML or PDF.

Tables, numbers and queries come straight from the data. Only the summary
sentence may come from an LLM, and only if it adds no unverified values.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Iterable, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from .contracts import SCHEMA_VERSION, AuditRecord, Claim, HuntBundle, HuntPlan
from .gateways import Gateway, OfflineGateway
from .summary import Rephraser, summary_text
from .util import fence, md_cell, md_inline, to_utc_iso, utc_now
from .verdict import Decision, decide, indicator_step_ids
from .verifier import VerificationOutcome, verify_bundle

GENERATOR = "se6014-c3-evidence 1.0.0"
TEMPLATE_DIR = Path(__file__).parent / "templates"

DEFAULT_LIMITATIONS = [
    "Findings depend on the playbooks used; techniques without a playbook are not tested.",
    "A Refuted verdict means there was no evidence in the covered sources and time window. It does not prove the activity did not happen.",
    "The verifier checks that cited events exist and contain the quoted values. It cannot check that the playbook read them correctly.",
]


class HuntReport(BaseModel):
    """The finished report: decision, findings, verification results and the data behind them."""

    schema_version: str = SCHEMA_VERSION
    report_id: str
    generated_at: str
    generator: str = GENERATOR
    run_id: str
    hypothesis: str
    plan: HuntPlan
    decision: Decision
    summary: str
    summary_source: str
    findings: list[Claim]
    context_findings: list[Claim]
    rejected: list[Claim]
    unverified: list[Claim]
    verification: dict[str, Any]
    verification_mode: str
    flags: list[dict[str, Any]] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    data_sources: dict[str, Any] = Field(default_factory=dict)
    selected_sources: list[str] = Field(default_factory=list)
    entity_missing: list[str] = Field(default_factory=list)
    dated: bool = True
    baselines: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    audit: list[AuditRecord] = Field(default_factory=list)
    steps_ok: dict[str, str] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)
    claim_queries: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)  # claim_id -> audited calls behind the claim


def _claim_queries(bundle: HuntBundle) -> dict[str, list[dict[str, Any]]]:
    """Map each claim id to the audited tool calls behind its evidence, with index and time window."""
    evidence = {e.evidence_id: e for e in bundle.evidence}
    audit = bundle.audit_by_id()
    out: dict[str, list[dict[str, Any]]] = {}
    for claim in bundle.claims:
        rows = []
        for evidence_id in claim.evidence_ids:
            item = evidence.get(evidence_id)
            record = audit.get(item.call_id) if item else None
            if record is None:
                continue
            params = record.params
            rows.append({"call_id": record.call_id, "tool": record.tool,
                         "index": params.get("index") or params.get("index_pattern") or item.index,
                         "time_from": params.get("time_from", ""), "time_to": params.get("time_to", "")})
        out[claim.claim_id] = rows
    return out


def _limitations(bundle: HuntBundle, outcome: VerificationOutcome) -> list[str]:
    """Collect the limitations to print: C2's, the defaults, and any caused by this verification run."""
    out = list(dict.fromkeys(list(bundle.limitations) + DEFAULT_LIMITATIONS))
    out += [f"data gap: {g}" for g in bundle.notes.gaps if f"data gap: {g}" not in out]
    if outcome.mode == "offline":
        out.append("Claims were not re-verified against the log store (offline); none of them counts as evidence.")
    replay = outcome.summary["replay"]
    if replay["mismatches"]:
        out.append(f"{len(replay['mismatches'])} replayed quer(ies) returned different results. The data may have changed since the hunt.")
    if replay.get("skipped"):
        out.append(f"{len(replay['skipped'])} recorded call(s) could not be replayed in {outcome.mode} mode.")
    if any(f["code"] == "hostile_event_text" for f in outcome.flags):
        out.append("Some cited events contain text aimed at an AI. C3 treated it as data, and an analyst should still review those events.")
    if any(f["code"] == "c2_prompt_injection" for f in outcome.flags):
        out.append("C2 found log events with text aimed at an AI in the hunt window. C3 treated them as data, "
                   "and an analyst should review them.")
    if outcome.summary.get("narrative_flags"):
        out.append("Some free text written by C2 names IPs, hosts or accounts that appear in no evidence. The verification "
                   "summary lists them, and an analyst should review them.")
    llm_findings = [c for c in outcome.claims if c.origin == "llm" and c.status == "verified"]
    if llm_findings:
        out.append(f"{len(llm_findings)} finding(s) come from LLM-proposed queries. They were verified like every claim, but they are leads only.")
    return out


def _steps_ok(bundle: HuntBundle, decision: Decision, claims: list[Claim]) -> dict[str, str]:
    """For each technique, count the indicator steps that finished OK, as "done/total"."""
    out = {}
    for row in decision.rows:
        ids = indicator_step_ids(bundle, row.technique, claims)
        done = sum(bundle.step_results.get(sid, {}).get("status") == "ok" for sid in ids)
        out[row.technique] = f"{done}/{len(ids)}"
    return out


def build_report_from_outcome(bundle: HuntBundle, outcome: VerificationOutcome,
                              rephrase: Optional[Rephraser] = None) -> HuntReport:
    """Turn a verification outcome into a report: decide the verdict, sort the claims, write the summary."""
    claims = outcome.claims
    decision = decide(bundle, claims, outcome.flags, offline=outcome.mode == "offline")
    verified = [c for c in claims if c.status == "verified"]
    findings = [c for c in verified if not c.context_only]
    context = [c for c in verified if c.context_only]
    summary, source = summary_text(bundle.plan.hypothesis, decision, findings, rephrase)

    return HuntReport(
        report_id=f"rpt-{bundle.run_id}",
        generated_at=to_utc_iso(utc_now()),
        run_id=bundle.run_id,
        hypothesis=bundle.plan.hypothesis,
        plan=bundle.plan,
        decision=decision,
        summary=summary,
        summary_source=source,
        findings=findings,
        context_findings=context,
        rejected=[c for c in claims if c.status in ("unsupported", "contradicted")],
        unverified=[c for c in claims if c.status == "unverified"],
        verification=outcome.summary,
        verification_mode=outcome.mode,
        flags=outcome.flags,
        coverage={k: v.model_dump() for k, v in bundle.notes.coverage.items()},
        data_sources=bundle.notes.data_sources,
        selected_sources=bundle.notes.selected_sources,
        entity_missing=bundle.notes.entity_missing,
        dated=bundle.notes.dated,
        baselines=bundle.baselines,
        limitations=_limitations(bundle, outcome),
        audit=bundle.audit,
        steps_ok=_steps_ok(bundle, decision, claims),
        claim_queries=_claim_queries(bundle),
        meta={**bundle.meta, "verification_errors": outcome.errors},
    )


async def build_report_async(bundle: HuntBundle, gateway: Optional[Gateway] = None,
                             rephrase: Optional[Rephraser] = None) -> HuntReport:
    """Verify the bundle with the given gateway (offline if none) and build the report."""
    gateway = gateway or OfflineGateway()
    outcome = await verify_bundle(bundle, gateway)
    return build_report_from_outcome(bundle, outcome, rephrase)


def build_report(bundle: HuntBundle, gateway: Optional[Gateway] = None, rephrase: Optional[Rephraser] = None) -> HuntReport:
    """Synchronous entry point. Gateways that must be opened first (MCP, Elasticsearch) need ``run_with_gateway``."""
    return asyncio.run(build_report_async(bundle, gateway, rephrase))


async def run_with_gateway(bundle: HuntBundle, gateway: Any, rephrase: Optional[Rephraser] = None) -> HuntReport:
    """Open the gateway if it needs opening, build the report, then close it."""
    if hasattr(gateway, "__aenter__"):
        async with gateway as opened:
            return await build_report_async(bundle, opened, rephrase)
    return await build_report_async(bundle, gateway, rephrase)


# Rendering


def _env(autoescape: bool) -> Environment:
    """Create the Jinja environment. Only the HTML templates are auto-escaped."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)),
                      autoescape=select_autoescape(["html", "html.j2"]) if autoescape else False,
                      trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    env.filters.update(md_cell=md_cell, md=md_inline, fence=fence,
                       tojson_pretty=lambda v: json.dumps(v, indent=2, sort_keys=True, default=str))
    return env


def _context(report: HuntReport) -> dict[str, Any]:
    """Variables for the templates. ``r`` is the report and ``d`` is its decision."""
    by_technique: dict[str, list[Claim]] = {}
    for claim in report.findings:
        by_technique.setdefault(claim.technique, []).append(claim)
    return {"r": report, "d": report.decision, "findings_by_technique": by_technique,
            "names": report.plan.entities.get("technique_names", {}) or {}}


def render_markdown(report: HuntReport) -> str:
    """Render the report as Markdown."""
    return _env(False).get_template("report.md.j2").render(**_context(report))


def render_html(report: HuntReport) -> str:
    """Render the report as HTML."""
    return _env(True).get_template("report.html.j2").render(**_context(report))


class PdfUnavailable(RuntimeError):
    """No PDF engine is installed."""


def render_pdf(report: HuntReport, path: str | Path) -> Path:
    """Write the HTML report as a PDF.

    WeasyPrint is used if it is installed. Otherwise headless Chromium runs through Playwright.
    Neither is required. Install one with ``pip install weasyprint``, or with
    ``pip install playwright`` followed by ``playwright install chromium``.
    """
    html = render_html(report)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except (ImportError, OSError):
        HTML = None
    if HTML is not None:
        HTML(string=html).write_pdf(str(out))
        return out
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise PdfUnavailable("PDF output needs WeasyPrint (pip install weasyprint) or Playwright "
                             "(pip install playwright; playwright install chromium)") from exc
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page()
                page.set_content(html, wait_until="load")
                page.pdf(path=str(out), format="A4", print_background=True,
                         margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"})
            finally:
                browser.close()
    except Exception as exc:  # the browser is missing, the sandbox blocks it, and so on
        raise PdfUnavailable(f"Chromium could not render the PDF: {type(exc).__name__}: {str(exc)[:200]}") from exc
    return out


def render_json(report: HuntReport) -> str:
    """Render the report as indented JSON."""
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def write_report(report: HuntReport, out_dir: str | Path, formats: Iterable[str] = ("json", "md", "html")) -> list[Path]:
    """Write the report in each requested format and return the file paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    renderers = {"json": render_json, "md": render_markdown, "html": render_html}
    paths = []
    for fmt in formats:
        path = out / f"hunt_report_{report.run_id}.{fmt}"
        if fmt == "pdf":
            render_pdf(report, path)
        else:
            path.write_text(renderers[fmt](report), encoding="utf-8")
        paths.append(path)
    return paths


def canonical_report_json(report: HuntReport) -> str:
    """Serialise the report the same way every time, without the timestamp, so two runs can be compared."""
    data = report.model_dump(mode="json")
    data.pop("generated_at", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
