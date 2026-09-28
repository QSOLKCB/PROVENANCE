"""Minimal framework-neutral PROVENANCE evidence records."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Iterable

from .canonical import CANONICALIZATION_ID, MAX_SAFE_INTEGER
from .identity import (
    artifact_record_identity,
    custody_identity,
    event_identity,
    manifest_identity,
    require_sha256_identity,
    sha256_identity,
)

ARTIFACT_SCHEMA = "provenance.artifact.v1"
CUSTODY_SCHEMA = "provenance.custody.v1"
EVENT_SCHEMA = "provenance.event.v1"
MANIFEST_SCHEMA = "provenance.manifest.v1"

_CUSTODY_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


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
    MISSING = "MISSING"


class ClockAssurance(str, Enum):
    LOCAL = "LOCAL"
    NETWORK = "NETWORK"
    AUTHENTICATED_NETWORK = "AUTHENTICATED_NETWORK"
    SIGNED_ATTESTATION = "SIGNED_ATTESTATION"


class ClockAssurance(str, Enum):
    LOCAL = "LOCAL"
    NETWORK = "NETWORK"
    AUTHENTICATED_NETWORK = "AUTHENTICATED_NETWORK"
    SIGNED_ATTESTATION = "SIGNED_ATTESTATION"


class CustodyAction(str, Enum):
    CAPTURED = "CAPTURED"
    STORED = "STORED"
    VERIFIED = "VERIFIED"
    EXPORTED = "EXPORTED"
    TRANSFERRED = "TRANSFERRED"
    SUPERSEDED = "SUPERSEDED"


def _validate_custody_time(value: str) -> None:
    if not isinstance(value, str) or _CUSTODY_TIME_RE.fullmatch(value) is None:
        raise ValueError(
            "custody recorded_at must be canonical UTC RFC3339 "
            "YYYY-MM-DDTHH:MM:SS[.ffffff]Z"
        )
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("custody recorded_at is not a valid UTC timestamp") from exc


@dataclass(frozen=True, slots=True)
class CustodyCore:
    subject_identity: str
    action: CustodyAction
    recorded_at: str
    clock_source: str
    clock_assurance: ClockAssurance
    actor: str | None = None
    source: str | None = None
    previous_custody: str | None = None
    related_identity: str | None = None

    def __post_init__(self) -> None:
        require_sha256_identity(
            self.subject_identity,
            label="custody subject identity",
        )
        if not isinstance(self.action, CustodyAction):
            raise TypeError("custody action must be a CustodyAction")
        _validate_custody_time(self.recorded_at)
        if not isinstance(self.clock_source, str) or not self.clock_source:
            raise ValueError("custody clock_source must be a non-empty string")
        if not isinstance(self.clock_assurance, ClockAssurance):
            raise TypeError(
                "custody clock_assurance must be a ClockAssurance"
            )
        for label, value in (("actor", self.actor), ("source", self.source)):
            if value is not None and (
                not isinstance(value, str) or not value
            ):
                raise ValueError(
                    f"custody {label} must be null or a non-empty string"
                )
        if self.previous_custody is not None:
            require_sha256_identity(
                self.previous_custody,
                label="previous custody identity",
            )
        if self.related_identity is not None:
            require_sha256_identity(
                self.related_identity,
                label="custody related identity",
            )
        if (
            self.action is CustodyAction.SUPERSEDED
            and self.related_identity is None
        ):
            raise ValueError(
                "SUPERSEDED custody requires related_identity"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": CUSTODY_SCHEMA,
            "canonicalization": CANONICALIZATION_ID,
            "subject_identity": self.subject_identity,
            "action": self.action.value,
            "recorded_at": self.recorded_at,
            "clock_source": self.clock_source,
            "clock_assurance": self.clock_assurance.value,
            "actor": self.actor,
            "source": self.source,
            "previous_custody": self.previous_custody,
            "related_identity": self.related_identity,
        }


@dataclass(frozen=True, slots=True)
class CustodyEnvelope:
    core: CustodyCore
    custody_identity: str

    @classmethod
    def seal(cls, core: CustodyCore) -> "CustodyEnvelope":
        return cls(
            core=core,
            custody_identity=custody_identity(core.to_dict()),
        )

    def __post_init__(self) -> None:
        if not isinstance(self.core, CustodyCore):
            raise TypeError("custody envelope core must be a CustodyCore")
        require_sha256_identity(
            self.custody_identity,
            label="custody identity",
        )
        expected = custody_identity(self.core.to_dict())
        if self.custody_identity != expected:
            raise ValueError("custody identity does not match custody core")

    def to_dict(self) -> dict[str, object]:
        return {
            "core": self.core.to_dict(),
            "custody_identity": self.custody_identity,
            "self_hash_exclusion": "custody_identity",
        }


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
    retention: RetentionState = RetentionState.DIGEST_ONLY

    def __post_init__(self) -> None:
        if not isinstance(self.retention, RetentionState):
            raise TypeError("artifact retention must be a RetentionState")
        if self.retention is RetentionState.MISSING:
            raise ValueError("MISSING is a manifest gap state, not an ArtifactRecord retention")
        require_sha256_identity(self.content_identity, label="artifact content identity")
        if (
            type(self.byte_count) is not int
            or self.byte_count < 0
            or self.byte_count > MAX_SAFE_INTEGER
        ):
            raise ValueError(
                "artifact byte_count must be a non-negative canonical safe integer"
            )
        if not isinstance(self.media_type, str) or not self.media_type:
            raise ValueError("artifact media_type must be a non-empty string")

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        retention: RetentionState = RetentionState.DIGEST_ONLY,
    ) -> "ArtifactRecord":
        return cls(
            content_identity=sha256_identity(data),
            byte_count=len(data),
            media_type=media_type,
            retention=retention,
        )

    @property
    def record_identity(self) -> str:
        return artifact_record_identity(self.to_dict())

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
class ManifestArtifact:
    content_identity: str
    retention: RetentionState
    record_identity: str | None

    def __post_init__(self) -> None:
        require_sha256_identity(self.content_identity, label="manifest artifact content identity")
        if not isinstance(self.retention, RetentionState):
            raise TypeError("manifest artifact retention must be a RetentionState")
        if self.retention is RetentionState.MISSING:
            if self.record_identity is not None:
                raise ValueError("missing artifact must not claim an ArtifactRecord identity")
        else:
            if self.record_identity is None:
                raise ValueError("non-missing artifact must bind an ArtifactRecord identity")
            require_sha256_identity(
                self.record_identity, label="manifest artifact record identity"
            )

    @classmethod
    def from_record(cls, record: ArtifactRecord) -> "ManifestArtifact":
        if not isinstance(record, ArtifactRecord):
            raise TypeError("manifest artifact source must be an ArtifactRecord")
        return cls(
            content_identity=record.content_identity,
            retention=record.retention,
            record_identity=record.record_identity,
        )

    @classmethod
    def missing(cls, content_identity: str) -> "ManifestArtifact":
        return cls(
            content_identity=content_identity,
            retention=RetentionState.MISSING,
            record_identity=None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "content_identity": self.content_identity,
            "record_identity": self.record_identity,
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
        if not isinstance(self.evidence_class, EvidenceClass):
            raise TypeError("event evidence_class must be an EvidenceClass")
        if not isinstance(self.collection_status, CollectionStatus):
            raise TypeError("event collection_status must be a CollectionStatus")
        if not isinstance(self.inputs, tuple) or not isinstance(self.outputs, tuple):
            raise TypeError("event inputs and outputs must be tuples")
        if not isinstance(self.relationships, tuple):
            raise TypeError("event relationships must be a tuple")
        if not all(isinstance(item, Relationship) for item in self.relationships):
            raise TypeError("event relationships must contain Relationship values")
        if not isinstance(self.actor, str) or not self.actor:
            raise ValueError("event actor must be a non-empty string")
        if not isinstance(self.operation, str) or not self.operation:
            raise ValueError("event operation must be a non-empty string")
        for index, value in enumerate(self.inputs):
            require_sha256_identity(value, label=f"event input[{index}]")
        for index, value in enumerate(self.outputs):
            require_sha256_identity(value, label=f"event output[{index}]")
        if self.evidence_class is EvidenceClass.DERIVED:
            has_derived_source = bool(self.inputs) or any(
                item.kind == "derived_from" for item in self.relationships
            )
            if not has_derived_source:
                raise ValueError(
                    "DERIVED event must identify at least one source input or derived_from relationship"
                )

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
        if not isinstance(self.core, EventCore):
            raise TypeError("event envelope core must be an EventCore")
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
    artifacts: tuple[ManifestArtifact, ...]
    events: tuple[str, ...]
    scope: str = "closed"

    def __post_init__(self) -> None:
        if not isinstance(self.artifacts, tuple) or not isinstance(self.events, tuple):
            raise TypeError("manifest artifacts and events must be tuples")
        if not all(isinstance(item, ManifestArtifact) for item in self.artifacts):
            raise TypeError("manifest artifacts must contain ManifestArtifact values")
        if self.scope not in {"open", "closed"}:
            raise ValueError("manifest scope must be 'open' or 'closed'")
        keys = tuple(item.content_identity for item in self.artifacts)
        if tuple(sorted(keys)) != keys or len(set(keys)) != len(keys):
            raise ValueError("manifest artifacts must be sorted and unique by content identity")
        if self.scope == "closed" and any(
            item.retention is RetentionState.MISSING for item in self.artifacts
        ):
            raise ValueError("closed manifest cannot contain missing artifacts")
        if tuple(sorted(set(self.events))) != self.events:
            raise ValueError("manifest events must be sorted and unique")
        for index, value in enumerate(self.events):
            require_sha256_identity(value, label=f"manifest event[{index}]")

    @classmethod
    def build(
        cls,
        *,
        artifacts: Iterable[ArtifactRecord | ManifestArtifact] = (),
        events: Iterable[str] = (),
        scope: str = "closed",
    ) -> "ManifestCore":
        normalized: dict[str, ManifestArtifact] = {}
        for item in artifacts:
            if isinstance(item, ArtifactRecord):
                entry = ManifestArtifact.from_record(item)
            elif isinstance(item, ManifestArtifact):
                entry = item
            else:
                raise TypeError(
                    "manifest artifacts must be ArtifactRecord or ManifestArtifact values"
                )
            prior = normalized.get(entry.content_identity)
            if prior is not None and prior != entry:
                raise ValueError(
                    "manifest contains conflicting metadata for one artifact content identity"
                )
            normalized[entry.content_identity] = entry
        return cls(
            artifacts=tuple(normalized[key] for key in sorted(normalized)),
            events=tuple(sorted(set(events))),
            scope=scope,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": MANIFEST_SCHEMA,
            "canonicalization": CANONICALIZATION_ID,
            "artifacts": [item.to_dict() for item in self.artifacts],
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
        if not isinstance(self.core, ManifestCore):
            raise TypeError("manifest envelope core must be a ManifestCore")
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
