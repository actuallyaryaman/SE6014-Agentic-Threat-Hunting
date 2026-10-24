"""Batch 4 tests for the B2 lifecycle CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from group_B.schema_generation import cli


JSON_SAMPLES = '\n'.join(
    f'{{"timestamp": "2025-03-18T02:{minute:02d}:01.56Z", '
    f'"src_ip": "10.0.0.{index}", "user": "user-{index}", '
    f'"message": "login ok"}}'
    for index, minute in enumerate((34, 35, 36, 37, 38), start=1)
) + "\n"

SYSLINE_SAMPLES = '\n'.join(
    f"Mar 18 02:{minute:02d}:01 host sshd: login by user-{index}"
    for index, minute in enumerate((34, 35, 36, 37, 38), start=1)
) + "\n"


@pytest.fixture
def json_samples(tmp_path: Path) -> Path:
    path = tmp_path / "samples.jsonl"
    path.write_text(JSON_SAMPLES, encoding="utf-8")
    return path


@pytest.fixture
def sysline_samples(tmp_path: Path) -> Path:
    path = tmp_path / "samples.txt"
    path.write_text(SYSLINE_SAMPLES, encoding="utf-8")
    return path


@pytest.fixture
def registry_root(tmp_path: Path) -> str:
    return str(tmp_path / "registry")


@pytest.fixture
def registry_args(registry_root: str) -> list[str]:
    return ["--registry", registry_root]


def _last_json(capsys: pytest.CaptureFixture[str]) -> dict:
    recorded = capsys.readouterr()
    return json.loads(recorded.out)


def test_generate_then_detect_and_list(
    registry_args: list[str], json_samples: Path, capsys
) -> None:
    exit_code = cli.main(
        registry_args + ["generate", str(json_samples), "--dataset", "demo"]
    )
    assert exit_code == 0
    payload = _last_json(capsys)
    assert payload["accepted"] is True
    assert payload["reused"] is False
    assert payload["schema"]["dataset"] == "demo"
    assert "registered" not in payload

    # without --register nothing was registered: detect stays unknown
    exit_code = cli.main(
        registry_args + ["detect", str(json_samples)]
    )
    assert exit_code == 0
    detection = _last_json(capsys)
    assert detection["known"] is False
    assert detection["pipeline_id"] is None

    exit_code = cli.main(registry_args + ["list"])
    listing = _last_json(capsys)
    assert listing["count"] == 0


def test_generate_register_then_reuse(
    registry_args: list[str], json_samples: Path, capsys
) -> None:
    exit_code = cli.main(
        registry_args + ["generate", str(json_samples), "--register"]
    )
    assert exit_code == 0
    payload = _last_json(capsys)
    assert payload["registered"]["version"] == 1
    registered_pipeline = payload["registered"]["pipeline_id"]

    exit_code = cli.main(registry_args + ["detect", str(json_samples)])
    assert exit_code == 0
    detection = _last_json(capsys)
    assert detection["known"] is True
    assert detection["pipeline_id"] == registered_pipeline

    exit_code = cli.main(registry_args + ["list"])
    listing = _last_json(capsys)
    assert listing["count"] == 1
    assert listing["entries"][0]["pipeline_id"] == registered_pipeline


def test_resolve_end_to_end_reuse(
    registry_args: list[str], json_samples: Path, capsys
) -> None:
    exit_code = cli.main(
        registry_args
        + ["resolve", str(json_samples), "--dataset", "demo", "--register"]
    )
    assert exit_code == 0
    first = _last_json(capsys)
    assert first["reused"] is False
    assert first["accepted"] is True
    assert first["provenance"]["generator"] == "heuristic"
    prefix = "" if first["schema"]["schema_id"].startswith("b2-") else "b2-"
    generated_pipeline = (
        f"{prefix}{first['schema']['schema_id']}-v{first['schema']['version']}"
    )

    exit_code = cli.main(registry_args + ["resolve", str(json_samples)])
    assert exit_code == 0
    second = _last_json(capsys)
    assert second["reused"] is True
    assert second["pipeline_id"] == generated_pipeline


def test_emit_and_register_bundle(
    registry_args: list[str], tmp_path: Path, json_samples: Path, capsys
) -> None:
    bundle = tmp_path / "bundle.json"
    exit_code = cli.main(
        registry_args + ["generate", str(json_samples), "--emit", str(bundle)]
    )
    assert exit_code == 0
    _last_json(capsys)
    assert bundle.is_file()

    exit_code = cli.main(registry_args + ["register", str(bundle)])
    assert exit_code == 0
    registered = _last_json(capsys)
    assert registered["registered"]["version"] == 1
    assert "registry" in registered["entry_path"]

    # the original signatures and pipeline are stored, not the raw samples
    stored = Path(registered["entry_path"]).read_text(encoding="utf-8")
    assert "login ok" not in stored


def test_validate_command(
    registry_args: list[str], tmp_path: Path, json_samples: Path, capsys
) -> None:
    exit_code = cli.main(
        registry_args + ["generate", str(json_samples), "--dataset", "demo"]
    )
    schema = _last_json(capsys)["schema"]
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(schema), encoding="utf-8")

    exit_code = cli.main(
        registry_args + ["validate", str(schema_file), str(json_samples)]
    )
    assert exit_code == 0
    report = _last_json(capsys)
    assert report["accepted"] is True
    assert report["validation"]["type_error_count"] == 0


def test_rejected_samples_exit_nonzero(
    registry_args: list[str], sysline_samples: Path, capsys
) -> None:
    exit_code = cli.main(
        registry_args + ["generate", str(sysline_samples)]
    )
    assert exit_code == 1
    recorded = capsys.readouterr()
    payload = json.loads(recorded.out)
    assert payload["accepted"] is False
    assert payload["errors"]


def test_missing_sample_file_reports_error(
    registry_args: list[str], tmp_path: Path, capsys
) -> None:
    exit_code = cli.main(
        registry_args + ["generate", str(tmp_path / "missing.txt")]
    )
    assert exit_code == 1
    recorded = capsys.readouterr()
    error = json.loads(recorded.err)
    assert error["error"]["code"] == "SCHEMA_GENERATION_FAILED"


def test_llm_flag_without_api_key_reports_error(
    registry_args: list[str], json_samples: Path, capsys, monkeypatch
) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    exit_code = cli.main(
        registry_args + ["generate", str(json_samples), "--llm"]
    )
    assert exit_code == 1
    recorded = capsys.readouterr()
    error = json.loads(recorded.err)
    assert "OPENROUTER_API_KEY" in error["error"]["message"]


def test_input_line_bound_is_enforced(
    registry_args: list[str], sysline_samples: Path, tmp_path: Path, capsys
) -> None:
    # one line over the input bound is rejected before any generation
    blob = tmp_path / "big.txt"
    lines = SYSLINE_SAMPLES.splitlines() * 41  # 205 lines > 200 bound
    blob.write_text("\n".join(lines) + "\n")
    exit_code = cli.main(registry_args + ["generate", str(blob)])
    assert exit_code == 1
    error = json.loads(capsys.readouterr().err)
    assert "exceeds the" in error["error"]["message"]

    # samples inside the bound still reach generation and simply fail it
    exit_code = cli.main(registry_args + ["generate", str(sysline_samples)])
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["accepted"] is False
