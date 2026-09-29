#!/usr/bin/env python3
"""Generate deterministic Phase 18 formal-verification archive evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET_PATH = ROOT / "formal" / "TARGET.json"

EXPECTED_TAG = "v1.0.0"
EXPECTED_COMMIT = "0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742"
EXPECTED_DOI = "10.5281/zenodo.23043860"
EXPECTED_TOOLCHAIN = "leanprover/lean4:v4.34.1"

ARCHIVE_FILES = (
    "formal/TARGET.json",
    "formal/lean-toolchain",
    "formal/lakefile.toml",
    "formal/ProvenanceFormal.lean",
    "docs/FORMAL_VERIFICATION.md",
    "docs/ARCHIVAL_RELEASE.md",
    "CITATION.cff",
    "scripts/phase18_manifest.py",
    ".github/workflows/formal.yml",
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


def _load_json(path: Path) -> object:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if raw != _canonical_json(value):
        raise SystemExit(f"{path.relative_to(ROOT)} must be canonical JSON")
    return value


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


def _validate_target(target: object) -> dict[str, object]:
    if not isinstance(target, dict):
        raise SystemExit("formal/TARGET.json must contain an object")
    required = {
        "schema",
        "frozen_tag",
        "frozen_commit",
        "doi",
        "lean_toolchain",
        "formal_claims",
    }
    if set(target) != required:
        raise SystemExit("formal/TARGET.json keys changed")
    if target["schema"] != "provenance.formal-target.v1":
        raise SystemExit("formal target schema changed")
    if target["frozen_tag"] != EXPECTED_TAG:
        raise SystemExit("formal target tag changed")
    if target["frozen_commit"] != EXPECTED_COMMIT:
        raise SystemExit("formal target commit changed")
    if target["doi"] != EXPECTED_DOI:
        raise SystemExit("formal target DOI changed")
    if target["lean_toolchain"] != EXPECTED_TOOLCHAIN:
        raise SystemExit("formal target Lean toolchain changed")
    claims = target["formal_claims"]
    if not isinstance(claims, list) or not claims:
        raise SystemExit("formal target must identify at least one claim")
    return target


def _validate_frozen_ref() -> None:
    actual = _git("rev-parse", f"{EXPECTED_TAG}^{{commit}}")
    if actual != EXPECTED_COMMIT:
        raise SystemExit(
            f"{EXPECTED_TAG} resolves to {actual}, expected {EXPECTED_COMMIT}"
        )
    _git("cat-file", "-e", f"{EXPECTED_COMMIT}^{{commit}}")


def _validate_toolchain() -> None:
    value = (ROOT / "formal" / "lean-toolchain").read_text(
        encoding="utf-8"
    ).strip()
    if value != EXPECTED_TOOLCHAIN:
        raise SystemExit(
            f"formal/lean-toolchain is {value!r}, expected {EXPECTED_TOOLCHAIN!r}"
        )


def _reject_placeholders() -> None:
    proof = (ROOT / "formal" / "ProvenanceFormal.lean").read_text(
        encoding="utf-8"
    )
    for token in ("sorry", "admit", "axiom "):
        if token in proof:
            raise SystemExit(
                f"formal proof source contains forbidden placeholder/token: {token!r}"
            )


def build_manifest() -> dict[str, object]:
    target = _validate_target(_load_json(TARGET_PATH))
    _validate_frozen_ref()
    _validate_toolchain()
    _reject_placeholders()

    proof_commit = _git("rev-parse", "HEAD")
    files: list[dict[str, object]] = []
    for relative in ARCHIVE_FILES:
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"required Phase 18 archive file is missing: {relative}")
        files.append(
            {
                "byte_count": path.stat().st_size,
                "path": relative,
                "sha256": _sha256(path),
            }
        )

    return {
        "doi": target["doi"],
        "formal_claims": target["formal_claims"],
        "frozen_commit": target["frozen_commit"],
        "frozen_tag": target["frozen_tag"],
        "lean_toolchain": target["lean_toolchain"],
        "proof_commit": proof_commit,
        "proof_files": files,
        "schema": "provenance.phase18-formal-evidence.v1",
        "verification_contract": {
            "build": "lake build",
            "leanchecker": True,
            "placeholder_scan": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    manifest = build_manifest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical_json(manifest))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
