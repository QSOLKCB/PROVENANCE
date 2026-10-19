"""Verify fixed retained evidence without executing its build recipe."""
from pathlib import Path

from provenance_core import canonical_json_bytes, parse_canonical_json_bytes, sha256_identity
from provenance_research import verify_research_check_receipt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# Trusted example paths, never paths supplied by a receipt.
ARTIFACT_PATHS = {
    "canonical-source": ROOT / "provenance_core/canonical.py",
    "build-recipe": HERE / "build.py",
    "output": HERE / "output.json",
    "expected": HERE / "expected.json",
    "derivation": HERE / "expectation-basis.md",
}


def verify() -> dict:
    data = (HERE / "check-receipt.json").read_bytes()
    # Validate each fixed file before deduplicating by digest. Matching expected
    # bytes must not conceal a missing or changed retained output file.
    artifacts = parse_canonical_json_bytes(data)["core"]["artifacts"]
    by_key = {artifact["key"]: artifact for artifact in artifacts}
    if set(by_key) != set(ARTIFACT_PATHS):
        raise ValueError("example artifact keys changed")
    contents = {}
    for key, path in ARTIFACT_PATHS.items():
        raw = path.read_bytes()
        artifact = by_key[key]
        digest = sha256_identity(raw)
        if digest != artifact["content_identity"] or len(raw) != artifact["byte_count"]:
            raise ValueError(f"example file binding mismatch: {key}")
        contents[digest] = raw
    return verify_research_check_receipt(data, contents)


if __name__ == "__main__":
    import sys
    report = verify()
    sys.stdout.buffer.write(canonical_json_bytes(report))
    raise SystemExit(0 if report["comparisons_verified"] else 1)
