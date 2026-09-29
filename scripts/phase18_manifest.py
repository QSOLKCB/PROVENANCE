#!/usr/bin/env python3
"""Generate deterministic Phase 18 formal-verification archive evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TAG = "v1.0.0"
EXPECTED_COMMIT = "0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742"
EXPECTED_DOI = "10.5281/zenodo.23043860"
EXPECTED_TOOLCHAIN = "leanprover/lean4:v4.34.1"

ARCHIVE_FILES = (
    "formal/.gitignore",
    "formal/TARGET.json",
    "formal/lean-toolchain",
    "formal/lakefile.toml",
    "formal/ProvenanceFormal.lean",
    "docs/FORMAL_VERIFICATION.md",
    "docs/ARCHIVAL_RELEASE.md",
    "CITATION.cff",
    "scripts/phase18_attestation.py",
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


def _git_bytes(*args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "git command failed: "
            + " ".join(args)
            + "\n"
            + completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.stdout


def _git_text(*args: str) -> str:
    return _git_bytes(*args).decode("utf-8").strip()


def _blob_bytes(commit: str, relative: str) -> bytes:
    return _git_bytes("show", f"{commit}:{relative}")


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _load_canonical_json_bytes(raw: bytes, *, label: str) -> object:
    value = json.loads(raw.decode("utf-8"))
    if raw != _canonical_json(value):
        raise SystemExit(f"{label} must be canonical JSON")
    return value


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
    actual = _git_text("rev-parse", f"{EXPECTED_TAG}^{{commit}}")
    if actual != EXPECTED_COMMIT:
        raise SystemExit(
            f"{EXPECTED_TAG} resolves to {actual}, expected {EXPECTED_COMMIT}"
        )
    _git_text("cat-file", "-e", f"{EXPECTED_COMMIT}^{{commit}}")


def _validate_toolchain(proof_commit: str) -> None:
    value = _blob_bytes(
        proof_commit,
        "formal/lean-toolchain",
    ).decode("utf-8").strip()
    if value != EXPECTED_TOOLCHAIN:
        raise SystemExit(
            f"formal/lean-toolchain is {value!r}, expected {EXPECTED_TOOLCHAIN!r}"
        )


_PLACEHOLDER_PATTERN = re.compile(r"\b(sorry|admit|axiom)\b")


def _lean_sources(proof_commit: str) -> list[str]:
    listing = _git_text(
        "ls-tree", "-r", "--name-only", proof_commit, "formal"
    )
    paths = [line for line in listing.splitlines() if line.endswith(".lean")]
    if "formal/ProvenanceFormal.lean" not in paths:
        raise SystemExit(
            "formal/ProvenanceFormal.lean is missing from the proof commit"
        )
    return paths


def _reject_placeholders(proof_commit: str) -> None:
    for relative in _lean_sources(proof_commit):
        proof = _blob_bytes(proof_commit, relative).decode("utf-8")
        match = _PLACEHOLDER_PATTERN.search(proof)
        if match:
            raise SystemExit(
                f"{relative} contains forbidden placeholder/token: "
                f"{match.group(0)!r}"
            )


def _validate_attestation(
    path: Path,
    *,
    proof_commit: str,
) -> dict[str, object]:
    raw = path.read_bytes()
    value = _load_canonical_json_bytes(
        raw,
        label=path.name,
    )
    if not isinstance(value, dict):
        raise SystemExit("verification attestation must contain an object")
    if value.get("schema") != "provenance.phase18-verification-attestation.v1":
        raise SystemExit("verification attestation schema changed")
    if value.get("status") != "PASSED":
        raise SystemExit("verification attestation did not report PASSED")
    if value.get("proof_commit") != proof_commit:
        raise SystemExit("verification attestation proof commit changed")
    if value.get("frozen_tag") != EXPECTED_TAG:
        raise SystemExit("verification attestation frozen tag changed")
    if value.get("frozen_commit") != EXPECTED_COMMIT:
        raise SystemExit("verification attestation frozen commit changed")
    if value.get("doi") != EXPECTED_DOI:
        raise SystemExit("verification attestation DOI changed")
    return value


def build_manifest(
    verification_evidence: tuple[Path, ...],
) -> dict[str, object]:
    proof_commit = _git_text("rev-parse", "HEAD")
    target = _validate_target(
        _load_canonical_json_bytes(
            _blob_bytes(proof_commit, "formal/TARGET.json"),
            label="formal/TARGET.json at proof_commit",
        )
    )
    _validate_frozen_ref()
    _validate_toolchain(proof_commit)
    _reject_placeholders(proof_commit)

    files: list[dict[str, object]] = []
    for relative in ARCHIVE_FILES:
        raw = _blob_bytes(proof_commit, relative)
        files.append(
            {
                "byte_count": len(raw),
                "path": relative,
                "sha256": _sha256_bytes(raw),
            }
        )

    evidence: list[dict[str, object]] = []
    attestation_seen = False
    for path in verification_evidence:
        if not path.is_file():
            raise SystemExit(
                f"verification evidence file is missing: {path}"
            )
        if path.name == "verification-attestation.json":
            _validate_attestation(path, proof_commit=proof_commit)
            attestation_seen = True
        evidence.append(
            {
                "byte_count": path.stat().st_size,
                "name": path.name,
                "sha256": _sha256_file(path),
            }
        )
    if not attestation_seen:
        raise SystemExit(
            "verification-attestation.json is required as executed proof evidence"
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
        "verification_evidence": evidence,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--verification-evidence",
        action="append",
        default=[],
        help="Executed verification evidence file to bind into the manifest.",
    )
    args = parser.parse_args()

    output = Path(args.output)
    manifest = build_manifest(
        tuple(Path(item) for item in args.verification_evidence)
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical_json(manifest))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
