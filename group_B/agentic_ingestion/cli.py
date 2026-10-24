"""Inspect a source or print a plan; Batch 5 never executes ingestion."""

import argparse
import json
import os
import sys

from pydantic import ValidationError

from group_B.common.errors import GroupBError
from group_B.common.recognizer import load_b1_recognizer
from group_B.schema_generation.registry import SchemaRegistry

from .inspect import inspect_source
from .llm import OpenRouterRouteAdvisor
from .models import InspectionPolicy, SourceSpec
from .planner import plan_source


def build_parser():
    parser = argparse.ArgumentParser(description="B3 source inspection and planning only")
    parser.add_argument("command", choices=["inspect", "plan"])
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
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        source = SourceSpec(
            kind=args.kind, location=args.location, dataset_hint=args.dataset,
            timezone=args.timezone, host_name=args.host_name,
            format_hint=args.format, ingest_mode=args.mode,
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
            result = plan_source(
                source, policy,
                recognizer=load_b1_recognizer(args.b1) if args.b1 else None,
                registry=SchemaRegistry(args.registry, read_only=True),
                known_pipelines=mapping,
                route_advisor=OpenRouterRouteAdvisor.from_env() if args.llm_route else None,
            )
            code = 0 if result.status == "planned" else 2
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
