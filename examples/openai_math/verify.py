"""Verify the checked-in OpenAI Math fixture without network or Lean."""
from pathlib import Path

from provenance_core import canonical_json_bytes, sha256_identity
from provenance_research import verify_research_manifest


def main() -> int:
    root = Path(__file__).resolve().parent
    contents = {}
    for name in ("LICENSE", "scope.md", "Heisenberg.lean", "Heisenberg.json", "citation.md"):
        raw = (root / "upstream" / name).read_bytes()
        contents[sha256_identity(raw)] = raw
    report = verify_research_manifest((root / "research-manifest.json").read_bytes(), contents)
    print(canonical_json_bytes(report).decode(), end="")
    return 0 if report["byte_integrity_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
