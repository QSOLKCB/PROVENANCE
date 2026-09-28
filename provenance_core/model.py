"""Minimal framework-neutral PROVENANCE evidence records."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import CANONICALIZATION_ID
from .identity import (
    event_identity,
    manifest_identity,
    require_sha256_identity,
    sha256_identity,
)

ARTIFACT_SCHEMA = "provenance.artifact.v1"
EVENT_SCHEMA = "provenance.event.v1"
MANIFEST_SCHEMA = "provenance.manifest.v1"


class EvidenceClass(str, Enum):
    OBSERVED = "OBSERVED"
    DECLARED = "DECLARED"
    DERIVED = "DERIVED"


class CollectionStatus(str, Enum):
    RECORDED = "RECORDED"
    PARTIALLY_RECORDED = "PARTIALLY_RECORDED"
    COLLECTION_FAILED = "COLLECTION_FAILED"
    EVIDENCE_GAP_OPENED = "EVIDENCE_GAP_OPENED"


class RetentionState(str, Enum):
    CONTENT_RETAINED = "CONTENT_RETAINED"
    DIGEST_ONLY = "DIGEST_ONLY"


@dataclass(frozen=True, slots=True)
class Relationship:
    kind: str
    target: str

    def __post_init__(self) -> None:
        if not self.kind or not isinstance(self.kind, str):
            raise ValueError("relationship kind must be a non-empty string")
        require_sha256_identity(self.target, label="relationship target")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "target": self.target}


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    content_identity: str
    byte_count: int
    media_type: str
    retention: RetentionState = RetentionState.CONTENT_RETAINED

    def __post_init__(self) -> None:
        require_sha256_identity(self.content_identity, label="artifact content identity")
        if type(self.byte_count) is not int or self.byte_count < 0:
            raise ValueError("artifact byte_count must be a non-negative integer")
        if not isinstance(self.media_type, str) or not self.media_type:
            raise ValueError("artifact media_type must be a non-empty string")

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        retention: RetentionState = RetentionState.CONTENT_RETAINED,
    ) -> "ArtifactRecord":
        return cls(
            content_identity=sha256_identity(data),
            byte_count=len(data),
            media_type=media_type,
            retention=retention,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": ARTIFACT_SCHEMA,
            "canonicalization": CANONICALIZATION_ID,
            "content_identity": self.content_identity,
            "byte_count": self.byte_count,
            "media_type": self.media_type,
            "retention": self.retention.value,
        }


@dataclass(frozen=True, slots=True)
class EventCore:
    evidence_class: EvidenceClass
    actor: str
    operation: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    collection_status: CollectionStatus = CollectionStatus.RECORDED

    def __post_init__(self) -> None:
        if not isinstance(self.actor, str) or not self.actor:
            raise ValueError("event actor must be a non-empty string")
        if not isinstance(self.operation, str) or not self.operation:
            raise ValueError("event operation must be a non-empty string")
        for index, value in enumerate(self.inputs):
            require_sha256_identity(value, label=f"event input[{index}]")
        for index, value in enumerate(self.outputs):
            require_sha256_identity(value, label=f"event output[{index}]")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": EVENT_SCHEMA,
            "canonicalization": CANONICALIZATION_ID,
            "evidence_class": self.evidence_class.value,
            "actor": self.actor,
            "operation": self.operation,
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "relationships": [item.to_dict() for item in self.relationships],
            "collection_status": self.collection_status.value,
        }


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    core: EventCore
    event_identity: str

    @classmethod
    def seal(cls, core: EventCore) -> "EventEnvelope":
        return cls(core=core, event_identity=event_identity(core.to_dict()))

    def __post_init__(self) -> None:
        require_sha256_identity(self.event_identity, label="event identity")
        expected = event_identity(self.core.to_dict())
        if self.event_identity != expected:
            raise ValueError("event identity does not match event core")

    def to_dict(self) -> dict[str, object]:
        return {
            "core": self.core.to_dict(),
            "event_identity": self.event_identity,
            "self_hash_exclusion": "event_identity",
        }


@dataclass(frozen=True, slots=True)
class ManifestCore:
    artifacts: tuple[str, ...]
    events: tuple[str, ...]
    scope: str = "closed"

    def __post_init__(self) -> None:
        if self.scope not in {"open", "closed"}:
            raise ValueError("manifest scope must be 'open' or 'closed'")
        if tuple(sorted(set(self.artifacts))) != self.artifacts:
            raise ValueError("manifest artifacts must be sorted and unique")
        if tuple(sorted(set(self.events))) != self.events:
            raise ValueError("manifest events must be sorted and unique")
        for index, value in enumerate(self.artifacts):
            require_sha256_identity(value, label=f"manifest artifact[{index}]")
        for index, value in enumerate(self.events):
            require_sha256_identity(value, label=f"manifest event[{index}]")

    @classmethod
    def build(
        cls,
        *,
        artifacts: Iterable[str] = (),
        events: Iterable[str] = (),
        scope: str = "closed",
    ) -> "ManifestCore":
        return cls(
            artifacts=tuple(sorted(set(artifacts))),
            events=tuple(sorted(set(events))),
            scope=scope,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": MANIFEST_SCHEMA,
            "canonicalization": CANONICALIZATION_ID,
            "artifacts": list(self.artifacts),
            "events": list(self.events),
            "scope": self.scope,
        }


@dataclass(frozen=True, slots=True)
class ManifestEnvelope:
    core: ManifestCore
    manifest_identity: str

    @classmethod
    def seal(cls, core: ManifestCore) -> "ManifestEnvelope":
        return cls(core=core, manifest_identity=manifest_identity(core.to_dict()))

    def __post_init__(self) -> None:
        require_sha256_identity(self.manifest_identity, label="manifest identity")
        expected = manifest_identity(self.core.to_dict())
        if self.manifest_identity != expected:
            raise ValueError("manifest identity does not match manifest core")

    def to_dict(self) -> dict[str, object]:
        return {
            "core": self.core.to_dict(),
            "manifest_identity": self.manifest_identity,
            "self_hash_exclusion": "manifest_identity",
        }
