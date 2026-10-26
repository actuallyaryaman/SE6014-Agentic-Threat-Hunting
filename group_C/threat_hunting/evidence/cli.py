"""Command line for C3. Run it from the repository root.

    python -m group_C.threat_hunting.evidence.cli report --bundle hunt_bundle.json --verify es
    python -m group_C.threat_hunting.evidence.cli from-run --plan runs/<id>/plan.json \
        --result runs/<id>/result.json --audit audit/<id>.jsonl --out hunt_bundle.json
    python -m group_C.threat_hunting.evidence.cli export-schemas
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .contracts import AuditRecord, Claim, HuntBundle, bundle_from_run_dir
from .gateways import GatewayUnavailable, OfflineGateway, gateway_from_name
from .report import PdfUnavailable, run_with_gateway, write_report

SCHEMA_DIR = Path(__file__).parent / "schemas"


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def cmd_report(args: argparse.Namespace) -> int:
    try:
        bundle = HuntBundle.model_validate_json(Path(args.bundle).read_text(encoding="utf-8"))
    except (ValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"Invalid hunt bundle: {exc}", file=sys.stderr)
        return 2
    gateway = gateway_from_name(args.verify, run_id=f"{bundle.run_id}-verify")
    try:
        report = asyncio.run(run_with_gateway(bundle, gateway))
    except GatewayUnavailable as exc:
        print(f"Cannot verify in '{args.verify}' mode ({exc}). Falling back to offline.", file=sys.stderr)
        report = asyncio.run(run_with_gateway(bundle, OfflineGateway()))
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    unknown = [f for f in formats if f not in ("json", "md", "html", "pdf")]
    if unknown:
        print(f"Unknown format(s): {unknown}. Use json, md, html or pdf.", file=sys.stderr)
        return 2
    try:
        paths = write_report(report, args.out_dir, formats)
    except PdfUnavailable as exc:
        print(f"PDF not written: {exc}", file=sys.stderr)
        paths = write_report(report, args.out_dir, [f for f in formats if f != "pdf"])
    decision, checks = report.decision, report.verification
    print(f"Verdict: {decision.verdict} (confidence {decision.confidence}){' - analyst review required' if decision.analyst_review else ''}")
    print(f"Claims: {checks['verified']} verified, {checks['unsupported']} unsupported, {checks['contradicted']} contradicted, "
          f"{checks['unverified']} not re-verified; replay {checks['replay']['identical']}/{checks['replay']['replayed']} identical")
    print(f"Verification mode: {report.verification_mode}")
    for p in paths:
        print(f"Wrote {p}")
    return 0


def cmd_from_run(args: argparse.Namespace) -> int:
    bundle = bundle_from_run_dir(args.plan, args.result, args.audit, analytics_audit_jsonl=args.analytics_audit)
    Path(args.out).write_text(bundle.model_dump_json(indent=1), encoding="utf-8")
    print(f"Wrote {args.out}: {len(bundle.claims)} claims, {len(bundle.evidence)} evidence, {len(bundle.audit)} audit records")
    return 0


def cmd_export_schemas(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, model in {"hunt_bundle": HuntBundle, "claim": Claim, "audit_record": AuditRecord}.items():
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"se6014/group_C/{name}.schema.json"
        (out / f"{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {out / (name + '.schema.json')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _load_env()
    parser = argparse.ArgumentParser(prog="c3-evidence", description="C3: verify a hunt bundle and write the report")
    sub = parser.add_subparsers(dest="cmd", required=True)
    report_cmd = sub.add_parser("report", help="verify claims, decide the verdict, write the report")
    report_cmd.add_argument("--bundle", required=True)
    report_cmd.add_argument("--verify", default="offline", choices=["offline", "es", "elasticsearch", "mcp"])
    report_cmd.add_argument("--out-dir", default="group_C/experiments/reports")
    report_cmd.add_argument("--formats", default="json,md,html", help="comma list of json, md, html, pdf (pdf needs WeasyPrint or Playwright)")
    report_cmd.set_defaults(func=cmd_report)
    from_run_cmd = sub.add_parser("from-run", help="build a bundle from a hunter run folder")
    from_run_cmd.add_argument("--plan", required=True)
    from_run_cmd.add_argument("--result", required=True)
    from_run_cmd.add_argument("--audit", required=True)
    from_run_cmd.add_argument("--analytics-audit", default=None, help="default: <audit file name>-analytics.jsonl next to --audit")
    from_run_cmd.add_argument("--out", default="hunt_bundle.json")
    from_run_cmd.set_defaults(func=cmd_from_run)
    schemas_cmd = sub.add_parser("export-schemas")
    schemas_cmd.add_argument("--out", default=str(SCHEMA_DIR))
    schemas_cmd.set_defaults(func=cmd_export_schemas)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
