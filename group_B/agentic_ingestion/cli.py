"""Inspect, plan, onboard with explicit execution, or verify existing events."""

import argparse
import json
import os
import sys

from pydantic import ValidationError

from group_B.common.errors import GroupBError
from group_B.common.recognizer import load_b1_recognizer
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.llm import OpenRouterCandidateProvider

from .inspect import inspect_source
from .llm import OpenRouterRouteAdvisor
from .models import ExecutionConfig, InspectionPolicy, SourceSpec
from .execution import onboard
from .planner import plan_source


def build_parser():
    parser = argparse.ArgumentParser(description="B3 source onboarding; dry-run by default")
    parser.add_argument("command", choices=["inspect", "plan", "onboard", "verify"])
    parser.add_argument("location")
    parser.add_argument("--kind", choices=["file", "http", "stream"], required=True)
    parser.add_argument("--dataset")
    parser.add_argument("--timezone")
    parser.add_argument("--host-name")
    parser.add_argument("--format", choices=["auto", "json", "csv", "kv", "line"], default="auto")
    parser.add_argument("--mode", choices=["auto", "pull", "push", "stream", "direct_es"], default="auto")
    parser.add_argument("--b1", default=os.environ.get("B1_RECOGNIZER"))
    parser.add_argument("--known-pipelines", help="JSON mapping of approved B1 format IDs to pipeline IDs")
    parser.add_argument("--registry")
    parser.add_argument("--llm-route", action="store_true", help="request optional OpenRouter transport advice")
    parser.add_argument("--llm-schema", action="store_true", help="allow OpenRouter schema generation")
    execution = parser.add_mutually_exclusive_group()
    execution.add_argument("--execute", action="store_true", help="permit onboard writes and ingestion")
    execution.add_argument("--dry-run", action="store_true", help="plan without output or ES writes (default)")
    parser.add_argument("--json", action="store_true", help="JSON output (also the default)")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.execute and args.command != "onboard":
        parser.error("--execute is supported only for onboard")
    try:
        source = SourceSpec(
            kind=args.kind, location=args.location, dataset_hint=args.dataset,
            timezone=args.timezone, host_name=args.host_name,
            format_hint=args.format, ingest_mode=args.mode,
            dry_run=not args.execute,
        )
        policy = InspectionPolicy.from_env()
        if args.command == "inspect":
            result = inspect_source(source, policy)
            code = 0
        else:
            mapping = json.loads(args.known_pipelines) if args.known_pipelines else {}
            if not isinstance(mapping, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in mapping.items()
            ):
                raise ValueError("known pipelines must be a string-to-string JSON mapping")
            options = dict(
                recognizer=load_b1_recognizer(args.b1) if args.b1 else None,
                registry=SchemaRegistry(args.registry), known_pipelines=mapping,
                route_advisor=OpenRouterRouteAdvisor.from_env() if args.llm_route else None,
                schema_provider=OpenRouterCandidateProvider.from_env() if args.llm_schema else None,
            )
            if args.command == "plan":
                result = plan_source(source, policy, **options)
                code = 0 if result.status == "planned" else 2
            else:
                result = onboard(source, policy, ExecutionConfig.from_env(),
                                 verify_only=args.command == "verify", **options)
                code = {"verified": 0, "dry_run": 0, "blocked": 2,
                        "failed": 1, "unverified": 3}[result.status]
        print(result.model_dump_json(indent=2))
        return code
    except GroupBError as error:
        payload = error.to_dict()
    except (OSError, ValueError, ValidationError):
        payload = {"ok": False, "error": {"code": "INVALID_ONBOARDING_INPUT",
                                        "message": "Invalid source, policy or planning configuration"}}
    print(json.dumps(payload), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
