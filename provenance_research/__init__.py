"""External research declarations with independently checked byte bindings."""

from .manifest import ResearchError, seal_research_manifest, verify_research_manifest

__all__ = ["ResearchError", "seal_research_manifest", "verify_research_manifest"]
