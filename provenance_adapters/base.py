"""Provider-neutral adapter contract and evidence translation for PROVENANCE Phase 10."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from provenance_core import (
    ArtifactRecord,
    CollectionStatus,
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    Relationship,
    RetentionState,
    canonical_json_bytes,
)
from provenance_custody import ClockObservation, LocalCustodyLedger, observe_clock
from provenance_store import LocalEvidenceStore, StoredSnapshot


ADAPTER_METADATA_SCHEMA = "provenance.adapter-metadata.v1"
ADAPTER_ARTIFACT_MEDIA_TYPE = "application/octet-stream"


class AdapterContractError(ValueError):
    """Raised when an adapter violates the provider-neutral Phase 10 contract."""


class AdapterExecutionError(RuntimeError):
    """Raised when an observed operation failed after evidence was captured."""

    def __init__(
        self,
        message: str,
        *,
        observation: "AdapterObservation",
    ):
        super().__init__(message)
        self.observation = observation


def _nonempty(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdapterContractError(f"{label} must be a non-empty string")
    return value


def _label(value: object, *, label: str) -> str:
    text = _nonempty(value, label=label)
    if any(char.isspace() for char in text):
        raise AdapterContractError(f"{label} must not contain whitespace")
    return text


def _plain_json(value: Any, *, label: str) -> Any:
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise AdapterContractError(
            f"{label} must be canonical-JSON-compatible: {exc}"
        ) from exc
    return value


@dataclass(frozen=True, slots=True)
class AdapterContract:
    """Minimal declaration of an adapter's observation boundary."""

    adapter_id: str
    source_kind: str
    observation_boundary: str
    extension_namespace: str

    def __post_init__(self) -> None:
        _nonempty(self.adapter_id, label="adapter_id")
        _label(self.source_kind, label="source_kind")
        _nonempty(self.observation_boundary, label="observation_boundary")
        namespace = _label(
            self.extension_namespace,
            label="extension_namespace",
        )
        if not namespace.startswith("provenance.adapter."):
            raise AdapterContractError(
                "extension_namespace must begin with 'provenance.adapter.'"
            )


@dataclass(frozen=True, slots=True)
class CapturedArtifact:
    """Bytes retained by an adapter, with their explicit evidence classification."""

    label: str
    data: bytes
    media_type: str = ADAPTER_ARTIFACT_MEDIA_TYPE
    evidence_class: EvidenceClass = EvidenceClass.OBSERVED
    retain_content: bool = True

    def __post_init__(self) -> None:
        _label(self.label, label="capture label")
        if not isinstance(self.data, bytes):
            raise AdapterContractError("captured artifact data must be bytes")
        _nonempty(self.media_type, label="captured artifact media_type")
        if not isinstance(self.evidence_class, EvidenceClass):
            raise AdapterContractError(
                "captured artifact evidence_class must be an EvidenceClass"
            )
        if type(self.retain_content) is not bool:
            raise AdapterContractError("retain_content must be a boolean")

    @property
    def record(self) -> ArtifactRecord:
        return ArtifactRecord.from_bytes(
            self.data,
            media_type=self.media_type,
            retention=(
                RetentionState.CONTENT_RETAINED
                if self.retain_content
                else RetentionState.DIGEST_ONLY
            ),
        )


@dataclass(frozen=True, slots=True)
class AdapterFailure:
    category: str
    detail: str
    code: int | None = None

    def __post_init__(self) -> None:
        _label(self.category, label="failure category")
        _nonempty(self.detail, label="failure detail")
        if self.code is not None and type(self.code) is not int:
            raise AdapterContractError("failure code must be an integer or null")

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "code": self.code,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class AdapterObservation:
    """Provider-neutral evidence emitted by one adapter operation."""

    contract: AdapterContract
    source_actor: str
    operation: str
    inputs: tuple[CapturedArtifact, ...]
    outputs: tuple[CapturedArtifact, ...]
    metadata: CapturedArtifact
    input_events: tuple[EventEnvelope, ...]
    output_events: tuple[EventEnvelope, ...]
    metadata_event: EventEnvelope
    completion_event: EventEnvelope
    failure: AdapterFailure | None = None

    def __post_init__(self) -> None:
        _nonempty(self.source_actor, label="source_actor")
        _label(self.operation, label="operation")
        if not isinstance(self.inputs, tuple) or not all(
            isinstance(item, CapturedArtifact) for item in self.inputs
        ):
            raise AdapterContractError("inputs must be captured artifacts")
        if not isinstance(self.outputs, tuple) or not all(
            isinstance(item, CapturedArtifact) for item in self.outputs
        ):
            raise AdapterContractError("outputs must be captured artifacts")
        if not isinstance(self.metadata, CapturedArtifact):
            raise AdapterContractError("metadata must be a captured artifact")
        if not isinstance(self.input_events, tuple) or not all(
            isinstance(item, EventEnvelope) for item in self.input_events
        ):
            raise AdapterContractError("input_events must be EventEnvelope values")
        if not isinstance(self.output_events, tuple) or not all(
            isinstance(item, EventEnvelope) for item in self.output_events
        ):
            raise AdapterContractError("output_events must be EventEnvelope values")
        if not isinstance(self.metadata_event, EventEnvelope):
            raise AdapterContractError("metadata_event must be an EventEnvelope")
        if not isinstance(self.completion_event, EventEnvelope):
            raise AdapterContractError("completion_event must be an EventEnvelope")
        if self.failure is not None and not isinstance(self.failure, AdapterFailure):
            raise AdapterContractError("failure must be AdapterFailure or null")

    @property
    def artifacts(self) -> tuple[CapturedArtifact, ...]:
        return self.inputs + self.outputs + (self.metadata,)

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return (
            self.input_events
            + self.output_events
            + (self.metadata_event, self.completion_event)
        )

    @property
    def succeeded(self) -> bool:
        return self.failure is None


@dataclass(frozen=True, slots=True)
class PersistedAdapterObservation:
    observation: AdapterObservation
    snapshot: StoredSnapshot


def _capture_event(
    *,
    evidence_class: EvidenceClass,
    actor: str,
    operation: str,
    artifact: CapturedArtifact,
    inputs: tuple[str, ...] = (),
    relationships: tuple[Relationship, ...] = (),
    collection_status: CollectionStatus = CollectionStatus.RECORDED,
) -> EventEnvelope:
    return EventEnvelope.seal(
        EventCore(
            evidence_class=evidence_class,
            actor=actor,
            operation=operation,
            inputs=inputs,
            outputs=(artifact.record.content_identity,),
            relationships=relationships,
            collection_status=collection_status,
        )
    )


def build_observation(
    contract: AdapterContract,
    *,
    source_actor: str,
    operation: str,
    inputs: Iterable[CapturedArtifact],
    outputs: Iterable[CapturedArtifact],
    declared_metadata: Mapping[str, Any] | None = None,
    extensions: Mapping[str, Any] | None = None,
    failure: AdapterFailure | None = None,
) -> AdapterObservation:
    """Translate one adapter-specific operation into core evidence records."""
    if not isinstance(contract, AdapterContract):
        raise AdapterContractError("contract must be an AdapterContract")
    source_actor = _nonempty(source_actor, label="source_actor")
    operation = _label(operation, label="operation")
    input_items = tuple(inputs)
    output_items = tuple(outputs)
    if len({item.label for item in input_items}) != len(input_items):
        raise AdapterContractError("input capture labels must be unique")
    if len({item.label for item in output_items}) != len(output_items):
        raise AdapterContractError("output capture labels must be unique")

    declared = dict(declared_metadata or {})
    extension_values = dict(extensions or {})
    _plain_json(declared, label="declared_metadata")
    _plain_json(extension_values, label="extensions")

    input_events = tuple(
        _capture_event(
            evidence_class=item.evidence_class,
            actor=contract.adapter_id,
            operation=f"{operation}.input.{item.label}",
            artifact=item,
        )
        for item in input_items
    )
    input_identities = tuple(
        item.record.content_identity for item in input_items
    )

    output_events = tuple(
        _capture_event(
            evidence_class=item.evidence_class,
            actor=source_actor,
            operation=f"{operation}.output.{item.label}",
            artifact=item,
            inputs=input_identities,
            relationships=tuple(
                Relationship(
                    kind="observed_after",
                    target=event.event_identity,
                )
                for event in input_events
            ),
        )
        for item in output_items
    )

    metadata_payload = {
        "schema": ADAPTER_METADATA_SCHEMA,
        "adapter_id": contract.adapter_id,
        "source_kind": contract.source_kind,
        "observation_boundary": contract.observation_boundary,
        "operation": operation,
        "source_actor": source_actor,
        "declared_metadata": declared,
        "extensions": {
            contract.extension_namespace: extension_values,
        },
        "failure": None if failure is None else failure.to_dict(),
    }
    metadata = CapturedArtifact(
        label="metadata",
        data=canonical_json_bytes(metadata_payload),
        media_type=ADAPTER_ARTIFACT_MEDIA_TYPE,
        evidence_class=EvidenceClass.DECLARED,
        retain_content=True,
    )
    related_events = input_events + output_events
    metadata_event = _capture_event(
        evidence_class=EvidenceClass.DECLARED,
        actor=contract.adapter_id,
        operation=f"{operation}.metadata",
        artifact=metadata,
        relationships=tuple(
            Relationship(kind="describes", target=item.event_identity)
            for item in related_events
        ),
    )

    completion_sources = related_events + (metadata_event,)
    completion_relationships = tuple(
        Relationship(kind="includes", target=item.event_identity)
        for item in completion_sources
    ) + tuple(
        Relationship(kind="derived_from", target=item.event_identity)
        for item in completion_sources
    )
    completion_event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.DERIVED,
            actor=contract.adapter_id,
            operation=(
                f"{operation}.completed"
                if failure is None
                else f"{operation}.failed"
            ),
            inputs=input_identities,
            outputs=tuple(
                item.record.content_identity for item in output_items
            ),
            relationships=completion_relationships,
            collection_status=(
                CollectionStatus.RECORDED
                if failure is None
                else CollectionStatus.COLLECTION_FAILED
            ),
        )
    )

    return AdapterObservation(
        contract=contract,
        source_actor=source_actor,
        operation=operation,
        inputs=input_items,
        outputs=output_items,
        metadata=metadata,
        input_events=input_events,
        output_events=output_events,
        metadata_event=metadata_event,
        completion_event=completion_event,
        failure=failure,
    )


def persist_observation(
    observation: AdapterObservation,
    store: LocalEvidenceStore,
    custody: LocalCustodyLedger,
    *,
    clock: ClockObservation | None = None,
    scope: str = "closed",
) -> PersistedAdapterObservation:
    """Persist provider-neutral adapter evidence through existing store/custody APIs."""
    if not isinstance(observation, AdapterObservation):
        raise AdapterContractError("observation must be an AdapterObservation")
    if not isinstance(store, LocalEvidenceStore):
        raise AdapterContractError("store must be a LocalEvidenceStore")
    if not isinstance(custody, LocalCustodyLedger):
        raise AdapterContractError("custody must be a LocalCustodyLedger")
    if clock is not None and not isinstance(clock, ClockObservation):
        raise AdapterContractError("clock must be a ClockObservation or null")

    effective_clock = clock or observe_clock()
    artifact_identities: list[str] = []
    event_identities: list[str] = []

    for capture in observation.artifacts:
        expected = capture.record
        stored = store.put_artifact(
            capture.data,
            media_type=capture.media_type,
            retain_content=capture.retain_content,
        )
        if stored != expected:
            raise AdapterContractError(
                f"store changed adapter artifact semantics for {capture.label}"
            )
        artifact_identities.append(stored.content_identity)
        if capture.evidence_class is EvidenceClass.OBSERVED:
            custody.append(
                stored.content_identity,
                CustodyAction.CAPTURED,
                actor=observation.contract.adapter_id,
                source=observation.source_actor,
                clock=effective_clock,
            )
        custody.append(
            stored.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local/v1",
            source=observation.contract.adapter_id,
            clock=effective_clock,
        )

    for event in observation.events:
        identity = store.put_event(event)
        event_identities.append(identity)
        custody.append(
            identity,
            CustodyAction.STORED,
            actor="provenance-store:local/v1",
            source=observation.contract.adapter_id,
            clock=effective_clock,
        )

    snapshot = store.finalize(scope=scope)
    if not snapshot.verification.integrity_verified:
        raise AdapterContractError(
            "adapter persistence produced a snapshot that failed verification"
        )

    for identity in artifact_identities + event_identities:
        custody.append(
            identity,
            CustodyAction.VERIFIED,
            actor="provenance-verify:v1",
            source=observation.contract.adapter_id,
            related_identity=snapshot.manifest_identity,
            clock=effective_clock,
        )
    custody.append(
        snapshot.manifest_identity,
        CustodyAction.VERIFIED,
        actor="provenance-verify:v1",
        source=observation.contract.adapter_id,
        clock=effective_clock,
    )
    report = custody.verify()
    if not report.integrity_verified:
        raise AdapterContractError(
            "adapter persistence produced invalid custody: "
            + "; ".join(report.errors)
        )
    return PersistedAdapterObservation(
        observation=observation,
        snapshot=snapshot,
    )
