"""Batch 4 CLI for the B2 unknown-schema lifecycle.

Subcommands:

* ``detect``   — build a structural signature and look it up in the registry
* ``generate`` — propose, compile and validate a schema for unknown samples,
  optionally registering the entry and optionally using an OpenRouter
  provider configured through environment variables
* ``validate`` — re-run the Batch 2 validator for a ``SchemaSpec`` JSON file
  against a sample file
* ``register`` — register a previously generated and validated entry bundle
  (produced by ``generate --emit``)
* ``list``     — list registry entries
* ``resolve``  — the end-to-end entry point: reuse when the signature is
  known, otherwise generate and register

Every command prints one JSON document to stdout. Failures print a
``GroupBError.to_dict()`` document to stderr and exit with the error's
process exit code. Raw sample text is never echoed back into the output; the
registry and bundles store hashes and metadata only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from group_B.common.errors import GroupBError, SchemaGenerationError
from group_B.schema_generation.compile_es import compile_pipeline
from group_B.schema_generation.detect import SchemaDetector
from group_B.schema_generation.generate import (
    GenerationResult,
    SchemaResolution,
    generate_schema,
    resolve_or_generate,
)
from group_B.schema_generation.llm import OpenRouterCandidateProvider
from group_B.schema_generation.models import (
    Provenance,
    SchemaSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import (
    RegistryEntry,
    RegistryError,
    SchemaRegistry,
    default_registry_root,
)
from group_B.schema_generation.signature import SourceSignature
from group_B.schema_generation.validate import validate_pipeline

MAX_INPUT_LINES = 200


def _read_sample_lines(path: Path) -> list[str]:
    if str(path) == "-":
        raw = sys.stdin.read().splitlines()
    else:
        resolved = path.expanduser()
        if not resolved.is_file():
            raise SchemaGenerationError(f"sample file not found: {path}")
        raw = resolved.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    lines = [line.strip("\r") for line in raw]
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        raise SchemaGenerationError(f"no usable sample lines in: {path}")
    if len(non_empty) > MAX_INPUT_LINES:
        raise SchemaGenerationError(
            f"{len(non_empty)} sample lines exceeds the "
            f"{MAX_INPUT_LINES}-line input bound"
        )
    return lines


def _registry(args: argparse.Namespace) -> SchemaRegistry:
    root = getattr(args, "registry", None)
    return SchemaRegistry(root) if root else SchemaRegistry(default_registry_root())


def _payload(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, default=str)


def _print(data: Any) -> None:
    sys.stdout.write(_payload(data) + "\n")


def _fail(error: GroupBError) -> int:
    sys.stderr.write(_payload(error.to_dict()) + "\n")
    return error.exit_code


def _provider(args: argparse.Namespace) -> OpenRouterCandidateProvider | None:
    if getattr(args, "llm", False):
        return OpenRouterCandidateProvider.from_env()
    return None


# --- output shaping -----------------------------------------------------------


def _registered_payload(entry: RegistryEntry) -> dict[str, Any]:
    return {
        "schema_id": entry.schema_spec.schema_id,
        "version": entry.schema_spec.version,
        "pipeline_id": entry.pipeline_id,
    }


def _generate_payload(
    result: GenerationResult,
    *,
    registered: RegistryEntry | None = None,
    reused: bool | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "reused": reused if reused is not None else False,
        "accepted": result.accepted,
        "errors": list(result.errors),
        "signature_hash": result.signature.hash,
        "attempt_count": len(result.attempts),
    }
    if result.schema_spec is not None:
        payload["schema"] = result.schema_spec.model_dump(
            mode="json", by_alias=True
        )
    if result.pipeline is not None:
        payload["pipeline"] = result.pipeline
    if result.validation is not None:
        payload["validation"] = result.validation.model_dump(mode="json")
    if result.provenance is not None:
        payload["provenance"] = result.provenance.model_dump(mode="json")
    if registered is not None:
        payload["registered"] = _registered_payload(registered)
    return payload


def _resolution_payload(
    resolution: SchemaResolution,
    *,
    registered: RegistryEntry | None = None,
) -> dict[str, Any]:
    entry = resolution.entry
    generation = resolution.generation
    if resolution.reused and entry is not None:
        return {
            "ok": True,
            "reused": True,
            "accepted": True,
            "errors": [],
            "signature_hash": resolution.signature.hash,
            "schema": entry.schema_spec.model_dump(
                mode="json", by_alias=True
            ),
            "pipeline": entry.pipeline,
            "pipeline_id": entry.pipeline_id,
            "validation": entry.validation.model_dump(mode="json"),
            "registered": _registered_payload(entry),
        }
    payload = _generate_payload(
        generation or GenerationResult(
            signature=resolution.signature, errors=["no generation result"]
        ),
        reused=False,
        registered=registered,
    )
    return payload


class _Bundle(BaseModel):
    """A validated entry bundle, as written by ``generate --emit``."""

    model_config = ConfigDict(extra="forbid")

    schema_spec: SchemaSpec
    signature: SourceSignature
    pipeline: dict[str, Any]
    validation: ValidationReport
    provenance: Provenance


def _bundle_path(
    result: GenerationResult,
) -> dict[str, Any]:
    if (
        result.schema_spec is None
        or result.pipeline is None
        or result.validation is None
        or result.provenance is None
    ):
        raise SchemaGenerationError(
            "cannot emit a bundle from a rejected candidate"
        )
    return _Bundle(
        schema_spec=result.schema_spec.model_dump(mode="json", by_alias=True),
        signature=result.signature.model_dump(mode="json"),
        pipeline=result.pipeline,
        validation=result.validation.model_dump(mode="json"),
        provenance=result.provenance.model_dump(mode="json"),
    ).model_dump(mode="json", by_alias=True)


# --- register helper ----------------------------------------------------------


def _registered_entry(
    registry: SchemaRegistry,
    result: GenerationResult,
    samples: list[str],
) -> RegistryEntry:
    if not result.accepted:
        raise RegistryError(
            "refusing to register a candidate whose validation "
            "report is not accepted"
        )
    return registry.register(
        schema=result.schema_spec,
        signature=result.signature,
        pipeline=result.pipeline,
        validation=result.validation,
        provenance=result.provenance,
        samples=samples,
    )


# --- commands -----------------------------------------------------------------


def _cmd_detect(args: argparse.Namespace) -> int:
    lines = _read_sample_lines(Path(args.samples))
    detection = SchemaDetector(_registry(args)).detect(lines)
    entry = detection.entry
    _print(
        {
            "ok": True,
            "known": detection.known,
            "signature_hash": detection.signature.hash,
            "entry": entry.model_dump(mode="json", by_alias=True)
            if entry is not None
            else None,
            "pipeline_id": detection.pipeline_id,
        }
    )
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    lines = _read_sample_lines(Path(args.samples))
    registry = _registry(args)
    result = generate_schema(
        lines,
        args.dataset,
        provider=_provider(args),
        registry=registry,
    )
    registered = None
    if result.accepted and getattr(args, "register", False):
        registered = _registered_entry(registry, result, lines)
    emit = getattr(args, "emit", None)
    if emit and result.accepted:
        Path(emit).expanduser().write_text(
            _payload(_bundle_path(result)) + "\n", encoding="utf-8"
        )
    _print(_generate_payload(result, registered=registered))
    return 0 if result.accepted else 1


def _cmd_validate(args: argparse.Namespace) -> int:
    lines = _read_sample_lines(Path(args.samples))
    schema_path = Path(args.schema).expanduser()
    if not schema_path.is_file():
        raise SchemaGenerationError(f"schema file not found: {args.schema}")
    try:
        raw = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SchemaGenerationError(
            f"schema file is not valid JSON: {error}"
        ) from error
    spec = SchemaSpec.model_validate(raw)
    pipeline = compile_pipeline(spec, samples=lines)
    report = validate_pipeline(spec, pipeline, lines)
    _print(
        {
            "ok": True,
            "accepted": report.accepted,
            "pipeline_id": spec.pipeline_id,
            "pipeline": pipeline,
            "validation": report.model_dump(mode="json"),
        }
    )
    return 0 if report.accepted else 1


def _cmd_register(args: argparse.Namespace) -> int:
    registry = _registry(args)
    lines = _read_sample_lines(Path(args.samples))
    bundle_path = Path(args.bundle).expanduser()
    if not bundle_path.is_file():
        raise SchemaGenerationError(f"bundle file not found: {args.bundle}")
    try:
        bundle = _Bundle.model_validate(
            json.loads(bundle_path.read_text(encoding="utf-8"))
        )
    except json.JSONDecodeError as error:
        raise SchemaGenerationError(
            f"bundle file is not valid JSON: {error}"
        ) from error
    entry = registry.register(
        schema=bundle.schema_spec,
        signature=bundle.signature,
        pipeline=bundle.pipeline,
        validation=bundle.validation,
        provenance=bundle.provenance,
        samples=lines,
    )
    _print(
        {
            "ok": True,
            "registered": _registered_payload(entry),
            "entry_path": str(
                registry.entry_path(
                    entry.schema_spec.schema_id,
                    entry.schema_spec.version,
                )
            ),
        }
    )
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    entries = _registry(args).list_entries()
    _print(
        {
            "ok": True,
            "count": len(entries),
            "entries": [
                {
                    "schema_id": entry.schema_spec.schema_id,
                    "version": entry.schema_spec.version,
                    "dataset": entry.schema_spec.dataset,
                    "pipeline_id": entry.pipeline_id,
                    "accepted": entry.validation.accepted,
                    "parser": entry.schema_spec.parser.kind,
                }
                for entry in entries
            ],
        }
    )
    return 0


def _cmd_resolve(args: argparse.Namespace) -> int:
    lines = _read_sample_lines(Path(args.samples))
    registry = _registry(args)
    resolution = resolve_or_generate(
        lines,
        args.dataset,
        registry=registry,
        provider=_provider(args),
    )
    registered = None
    if not resolution.reused and resolution.generation is not None:
        if getattr(args, "register", False):
            registered = _registered_entry(registry, resolution.generation, lines)
    payload = _resolution_payload(resolution, registered=registered)
    _print(payload)
    exit_code = 0 if payload.get("accepted") else 1
    return exit_code


# --- argparse -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="group-B-b2",
        description=(
            "B2 unknown-schema lifecycle: detect, generate, validate, "
            "register, list, resolve"
        ),
    )
    parser.add_argument(
        "--registry",
        default=None,
        help="optional registry root (defaults to the package registry dir)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser(
        "detect", help="signature lookup for a sample file"
    )
    detect.add_argument("samples", help="sample file path, or - for stdin")
    detect.set_defaults(func=_cmd_detect)

    generate = sub.add_parser(
        "generate", help="generate and validate a schema for unknown samples"
    )
    generate.add_argument("samples", help="sample file path, or - for stdin")
    generate.add_argument("--dataset", default=None)
    generate.add_argument(
        "--register",
        action="store_true",
        help="register the entry when validation accepts it",
    )
    generate.add_argument(
        "--emit",
        default=None,
        metavar="PATH",
        help="write a validated entry bundle JSON file for later --register",
    )
    generate.add_argument(
        "--llm",
        action="store_true",
        help="enable the OpenRouter provider via OPENROUTER_* env vars",
    )
    generate.set_defaults(func=_cmd_generate)

    validate = sub.add_parser(
        "validate",
        help="compile and validate a SchemaSpec JSON file against samples",
    )
    validate.add_argument("schema", help="SchemaSpec JSON file")
    validate.add_argument("samples", help="sample file path, or - for stdin")
    validate.set_defaults(func=_cmd_validate)

    register = sub.add_parser(
        "register", help="register a validated entry bundle"
    )
    register.add_argument("bundle", help="entry bundle JSON file (--emit)")
    register.add_argument(
        "samples", help="original sample file path, or - for stdin"
    )
    register.set_defaults(func=_cmd_register)

    sub.add_parser("list", help="list registry entries").set_defaults(
        func=_cmd_list
    )

    resolve = sub.add_parser(
        "resolve",
        help="end-to-end: reuse a registered schema or generate one",
    )
    resolve.add_argument("samples", help="sample file path, or - for stdin")
    resolve.add_argument("--dataset", default=None)
    resolve.add_argument(
        "--register",
        action="store_true",
        help="register a newly generated entry when validation accepts it",
    )
    resolve.add_argument(
        "--llm",
        action="store_true",
        help="enable the OpenRouter provider via OPENROUTER_* env vars",
    )
    resolve.set_defaults(func=_cmd_resolve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GroupBError as error:
        return _fail(error)
    except ValidationError as error:
        return _fail(
            SchemaGenerationError(
                "invalid input model",
                errors=error.errors(
                    include_input=False, include_context=False, include_url=False
                ),
            )
        )
    except (OSError, UnicodeError):
        return _fail(
            SchemaGenerationError("could not read or write a requested file")
        )


if __name__ == "__main__":
    sys.exit(main())
