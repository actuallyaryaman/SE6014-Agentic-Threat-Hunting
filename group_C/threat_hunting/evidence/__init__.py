"""C3: evidence verification, verdict and report for the C2 playbook hunter.

    from group_C.threat_hunting.evidence import HuntBundle, build_report, ESGateway, MCPGateway
"""

__version__ = "1.0.0"

from .contracts import AuditRecord, Claim, Evidence, HuntBundle, HuntNotes, HuntPlan, PlanStep  # noqa: E402
from .gateways import ESGateway, MCPGateway, OfflineGateway  # noqa: E402
from .report import (  # noqa: E402
    HuntReport,
    build_report,
    build_report_async,
    PdfUnavailable,
    render_html,
    render_pdf,
    render_json,
    render_markdown,
    run_with_gateway,
    write_report,
)
from .verdict import Decision, decide  # noqa: E402
from .verifier import lint_text, verify_bundle  # noqa: E402

__all__ = [
    "__version__", "AuditRecord", "Claim", "Evidence", "HuntBundle", "HuntNotes", "HuntPlan", "PlanStep",
    "ESGateway", "MCPGateway", "OfflineGateway", "HuntReport", "build_report", "build_report_async",
    "PdfUnavailable", "render_pdf", "render_html", "render_json", "render_markdown", "run_with_gateway", "write_report",
    "Decision", "decide", "lint_text", "verify_bundle",
]
