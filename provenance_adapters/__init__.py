"""PROVENANCE framework-specific and provider-neutral adapters."""

from .base import (
    ADAPTER_METADATA_SCHEMA,
    AdapterContract,
    AdapterContractError,
    AdapterExecutionError,
    AdapterFailure,
    AdapterObservation,
    CapturedArtifact,
    PersistedAdapterObservation,
    build_observation,
    persist_observation,
)
from .http import (
    HTTP_ADAPTER_CONTRACT,
    GenericHTTPAdapter,
    GenericHTTPAdapterError,
)
from .ollama import (
    ADAPTER_ID,
    OllamaAdapter,
    OllamaAdapterError,
    OllamaObservation,
)
from .process import (
    PROCESS_ADAPTER_CONTRACT,
    ProcessAdapter,
    ProcessAdapterError,
)

__all__ = [
    "ADAPTER_ID",
    "ADAPTER_METADATA_SCHEMA",
    "HTTP_ADAPTER_CONTRACT",
    "PROCESS_ADAPTER_CONTRACT",
    "AdapterContract",
    "AdapterContractError",
    "AdapterExecutionError",
    "AdapterFailure",
    "AdapterObservation",
    "CapturedArtifact",
    "GenericHTTPAdapter",
    "GenericHTTPAdapterError",
    "OllamaAdapter",
    "OllamaAdapterError",
    "OllamaObservation",
    "PersistedAdapterObservation",
    "ProcessAdapter",
    "ProcessAdapterError",
    "build_observation",
    "persist_observation",
]
