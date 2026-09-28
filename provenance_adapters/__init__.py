"""PROVENANCE framework-specific adapters."""

from .ollama import (
    ADAPTER_ID,
    OllamaAdapter,
    OllamaAdapterError,
    OllamaObservation,
)

__all__ = [
    "ADAPTER_ID",
    "OllamaAdapter",
    "OllamaAdapterError",
    "OllamaObservation",
]
