"""External research declarations with independently checked byte bindings."""

from .manifest import ResearchError, seal_research_manifest, verify_research_manifest

__all__ = ["ResearchError", "seal_research_manifest", "verify_research_manifest"]

from .receipt import (
    research_check_receipt_identity, seal_research_check_receipt,
    verify_research_check_receipt,
)

__all__ += [
    "research_check_receipt_identity", "seal_research_check_receipt",
    "verify_research_check_receipt",
]
