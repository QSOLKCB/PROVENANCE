#!/usr/bin/env python3
"""Emit a canonical attestation for a successful Phase 18 proof check."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TAG = "v1.0.0"
EXPECTED_COMMIT = "0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742"
EXPECTED_DOI = "10.5281/zenodo.23043860"
EXPECTED_TOOLCHAIN = "leanprover/lean4:v4.34.1"
EXPECTED_BUNDLE_SHA256 = (
    "47bf4bbd78f70c2e9670598ab7124d92b6efb7330ff33e5fbb4030f6fd72e4e4"
)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "git command failed: "
            + " ".join(args)
            + "\n"
            + completed.stderr.strip()
        )
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _evidence_file(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise SystemExit(f"verification evidence file is missing: {path}")
    return {
        "byte_count": path.stat().st_size,
        "name": path.name,
        "sha256": _sha256(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--lean-build-log", required=True)
    parser.add_argument("--leanchecker-log", required=True)
    parser.add_argument("--lean-version-file", required=True)
    parser.add_argument("--lake-version-file", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    proof_commit = _git("rev-parse", "HEAD")
    frozen = _git("rev-parse", f"{EXPECTED_TAG}^{{commit}}")
    if frozen != EXPECTED_COMMIT:
        raise SystemExit(
            f"{EXPECTED_TAG} resolves to {frozen}, expected {EXPECTED_COMMIT}"
        )

    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha and github_sha != proof_commit:
        raise SystemExit(
            f"GITHUB_SHA {github_sha} does not match checked-out HEAD {proof_commit}"
        )

    lean_build_log = Path(args.lean_build_log)
    leanchecker_log = Path(args.leanchecker_log)
    lean_version_file = Path(args.lean_version_file)
    lake_version_file = Path(args.lake_version_file)

    lean_version = lean_version_file.read_text(encoding="utf-8").strip()
    lake_version = lake_version_file.read_text(encoding="utf-8").strip()
    if "4.34.1" not in lean_version:
        raise SystemExit(f"unexpected Lean version: {lean_version}")
    if "Lean version 4.34.1" not in lake_version:
        raise SystemExit(f"unexpected Lake version: {lake_version}")

    attestation = {
        "checks": [
            {
                "command": "lake build",
                "evidence": _evidence_file(lean_build_log),
                "status": "PASSED",
            },
            {
                "command": "lake env leanchecker ProvenanceFormal",
                "evidence": _evidence_file(leanchecker_log),
                "status": "PASSED",
            },
        ],
        "doi": EXPECTED_DOI,
        "frozen_commit": EXPECTED_COMMIT,
        "frozen_tag": EXPECTED_TAG,
        "github": {
            "event_name": os.environ.get("GITHUB_EVENT_NAME"),
            "ref": os.environ.get("GITHUB_REF"),
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_url": (
                f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
                f"{os.environ.get('GITHUB_RUN_ID', '')}"
            ),
        },
        "lean_bundle_sha256": "sha256:" + EXPECTED_BUNDLE_SHA256,
        "lean_toolchain": EXPECTED_TOOLCHAIN,
        "proof_commit": proof_commit,
        "runner": {
            "arch": os.environ.get("RUNNER_ARCH"),
            "os": os.environ.get("RUNNER_OS"),
        },
        "schema": "provenance.phase18-verification-attestation.v1",
        "status": "PASSED",
        "versions": {
            "lake": lake_version,
            "lean": lean_version,
        },
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical_json(attestation))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
