#!/usr/bin/env python3
"""Download and verify the OTRF fixtures used by Group B tests.

The fixtures are committed to the repository, so this script is only needed
to refresh them or to prove their provenance. It uses the Python standard
library only.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

FIXTURE_DIR = (
    Path(__file__).resolve().parent.parent
    / "tests"
    / "fixtures"
    / "otrf"
)

# Pin provenance to a commit rather than the mutable master branch.
SOURCE_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
SOURCE_BASE = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
    f"{SOURCE_COMMIT}"
)

DATASETS = [
    {
        "id": "SDAWS-2202181000",
        "title": "AWS S3 Honey Bucket Logs",
        "url": (
            f"{SOURCE_BASE}/datasets/atomic/aws/discovery/"
            "aws_s3_honeybucketlogs.zip"
        ),
        "member": "AWS_S3_HoneyBucketLogs.csv",
        "output": "AWS_S3_HoneyBucketLogs.csv",
        "sha256": (
            "193fbd2fd13ae35f32ac9dfe3f79bc42166b734adf63f827addf872c8352229e"
        ),
    },
    {
        "id": "SDLIN-201110074812",
        "title": "Arp Cache Discovery",
        "url": (
            f"{SOURCE_BASE}/datasets/atomic/linux/discovery/host/"
            "sh_arp_cache.zip"
        ),
        "member": "sh_arp_cache_2020-11-10074812.log",
        "output": "sh_arp_cache_2020-11-10074812.auditd",
        "sha256": (
            "6a938e0a94f2f26c153e4c8a37ef0df960b2cb46147407fda00d0344e8f375fc"
        ),
    },
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "smtd-proj-group-b-fixture-fetch/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def extract_member(archive: bytes, member: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        try:
            return bundle.read(member)
        except KeyError as error:
            names = ", ".join(bundle.namelist())
            raise SystemExit(
                f"Archive does not contain {member!r}. Members: {names}"
            ) from error


def verify_file(path: Path, expected: str) -> bool:
    if not path.is_file():
        print(f"MISSING {path}")
        return False

    actual = sha256_bytes(path.read_bytes())
    if actual != expected:
        print(f"MISMATCH {path}\n  expected {expected}\n  actual   {actual}")
        return False

    print(f"OK {path}")
    return True


def fetch(dataset: dict, force: bool) -> bool:
    destination = FIXTURE_DIR / dataset["output"]

    if destination.exists() and not force:
        return verify_file(destination, dataset["sha256"])

    print(f"Downloading {dataset['id']} — {dataset['title']}")
    archive = download_bytes(dataset["url"])
    content = extract_member(archive, dataset["member"])

    actual = sha256_bytes(content)
    if actual != dataset["sha256"]:
        print(
            f"Refusing to write {destination}: extracted content does not "
            f"match the recorded SHA-256.\n  expected {dataset['sha256']}"
            f"\n  actual   {actual}"
        )
        return False

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    print(f"WROTE {destination}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify existing fixtures without downloading",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="download and replace existing fixtures",
    )
    args = parser.parse_args()

    if args.check and args.force:
        parser.error("--check and --force are mutually exclusive")

    results = []
    for dataset in DATASETS:
        if args.check:
            results.append(
                verify_file(
                    FIXTURE_DIR / dataset["output"],
                    dataset["sha256"],
                )
            )
        else:
            results.append(fetch(dataset, force=args.force))

    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
