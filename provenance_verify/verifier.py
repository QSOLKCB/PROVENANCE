"""Independent, read-only verification for PROVENANCE evidence bundles."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from provenance_core import (
    ARTIFACT_SCHEMA,
    CANONICALIZATION_ID,
    EVENT_SCHEMA,
    MANIFEST_SCHEMA,
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    CollectionStatus,
    EvidenceClass,
    RetentionState,
    artifact_record_identity,
    event_identity,
    manifest_identity,
    parse_canonical_json_bytes,
    require_sha256_identity,
    sha256_identity,
)

VERIFICATION_REPORT_SCHEMA = "provenance.verification-report.v1"


class VerificationError(ValueError):
    """Raised internally when evidence violates the published bundle contract."""


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Read-only integrity result for one evidence bundle."""

    integrity_verified: bool
    manifest_identity: str | None
    manifest_scope: str | None
    known_missing_artifacts: int
    checks: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": VERIFICATION_REPORT_SCHEMA,
            "integrity_verified": self.integrity_verified,
            "manifest_identity": self.manifest_identity,
            "manifest_scope": self.manifest_scope,
            "known_missing_artifacts": self.known_missing_artifacts,
            "checks": list(self.checks),
            "errors": list(self.errors),
        }


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail: list[str] = []
        if missing:
            detail.append(f"missing={','.join(missing)}")
        if extra:
            detail.append(f"extra={','.join(extra)}")
        raise VerificationError(f"{label} keys changed: {'; '.join(detail)}")


def _identity_digest(value: Any, *, label: str) -> str:
    try:
        require_sha256_identity(value, label=label)
    except (TypeError, ValueError) as exc:
        raise VerificationError(str(exc)) from exc
    return str(value).split(":", 1)[1]


def _event_relative(identity: str) -> str:
    return f"events/sha256/{_identity_digest(identity, label='event identity')}.json"


def _artifact_record_relative(identity: str) -> str:
    return (
        f"artifact_records/sha256/"
        f"{_identity_digest(identity, label='artifact record identity')}.json"
    )


def _artifact_content_relative(identity: str) -> str:
    return f"artifacts/sha256/{_identity_digest(identity, label='artifact content identity')}"


def _read_canonical_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"{label} cannot be read: {exc}") from exc
    try:
        value = parse_canonical_json_bytes(data)
    except CanonicalizationError as exc:
        raise VerificationError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value


def _verify_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], str, str, int]:
    envelope = _read_canonical_object(manifest_path, label="manifest.json")
    _exact_keys(
        envelope,
        {"core", "manifest_identity", "self_hash_exclusion"},
        "manifest envelope",
    )
    if envelope.get("self_hash_exclusion") != "manifest_identity":
        raise VerificationError("manifest self_hash_exclusion must be manifest_identity")

    claimed_identity = envelope.get("manifest_identity")
    _identity_digest(claimed_identity, label="manifest identity")

    core = envelope.get("core")
    if not isinstance(core, dict):
        raise VerificationError("manifest core must be an object")
    _exact_keys(
        core,
        {"schema", "canonicalization", "artifacts", "events", "scope"},
        "manifest core",
    )
    if core.get("schema") != MANIFEST_SCHEMA:
        raise VerificationError("manifest schema changed")
    if core.get("canonicalization") != CANONICALIZATION_ID:
        raise VerificationError("manifest canonicalization changed")

    scope = core.get("scope")
    if scope not in {"open", "closed"}:
        raise VerificationError("manifest scope must be open or closed")

    artifacts = core.get("artifacts")
    events = core.get("events")
    if not isinstance(artifacts, list):
        raise VerificationError("manifest artifacts must be a list")
    if not isinstance(events, list):
        raise VerificationError("manifest events must be a list")

    normalized_artifacts: list[dict[str, Any]] = []
    artifact_keys: list[str] = []
    known_missing = 0
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            raise VerificationError(f"manifest artifact[{index}] must be an object")
        _exact_keys(
            entry,
            {"content_identity", "record_identity", "retention"},
            f"manifest artifact[{index}]",
        )
        content_identity = entry.get("content_identity")
        _identity_digest(
            content_identity, label=f"manifest artifact[{index}] content identity"
        )
        retention = entry.get("retention")
        if retention not in {item.value for item in RetentionState}:
            raise VerificationError(f"manifest artifact[{index}] retention is invalid")

        record_identity = entry.get("record_identity")
        if retention == RetentionState.MISSING.value:
            known_missing += 1
            if record_identity is not None:
                raise VerificationError(
                    f"manifest artifact[{index}] missing evidence must not claim a record identity"
                )
        else:
            _identity_digest(
                record_identity, label=f"manifest artifact[{index}] record identity"
            )

        artifact_keys.append(str(content_identity))
        normalized_artifacts.append(entry)

    if artifact_keys != sorted(artifact_keys) or len(set(artifact_keys)) != len(
        artifact_keys
    ):
        raise VerificationError(
            "manifest artifacts must be sorted and unique by content identity"
        )
    if scope == "closed" and known_missing:
        raise VerificationError("closed manifest cannot contain missing artifacts")

    normalized_events: list[str] = []
    for index, value in enumerate(events):
        _identity_digest(value, label=f"manifest event[{index}]")
        normalized_events.append(str(value))
    if normalized_events != sorted(normalized_events) or len(
        set(normalized_events)
    ) != len(normalized_events):
        raise VerificationError("manifest events must be sorted and unique")

    expected_identity = manifest_identity(core)
    if claimed_identity != expected_identity:
        raise VerificationError("manifest identity does not match canonical manifest core")

    return (
        core,
        normalized_artifacts,
        normalized_events,
        str(scope),
        str(claimed_identity),
        known_missing,
    )


def _verify_artifact_record(
    path: Path,
    *,
    manifest_entry: dict[str, Any],
    bundle_dir: Path,
) -> None:
    record = _read_canonical_object(path, label=path.as_posix())
    _exact_keys(
        record,
        {
            "schema",
            "canonicalization",
            "content_identity",
            "byte_count",
            "media_type",
            "retention",
        },
        "artifact record",
    )
    if record.get("schema") != ARTIFACT_SCHEMA:
        raise VerificationError("artifact record schema changed")
    if record.get("canonicalization") != CANONICALIZATION_ID:
        raise VerificationError("artifact record canonicalization changed")

    content_identity = record.get("content_identity")
    _identity_digest(content_identity, label="artifact content identity")
    if content_identity != manifest_entry["content_identity"]:
        raise VerificationError("artifact record content identity differs from manifest")

    byte_count = record.get("byte_count")
    if (
        type(byte_count) is not int
        or byte_count < 0
        or byte_count > MAX_SAFE_INTEGER
    ):
        raise VerificationError(
            "artifact byte_count must be a non-negative canonical safe integer"
        )

    media_type = record.get("media_type")
    if not isinstance(media_type, str) or not media_type:
        raise VerificationError("artifact media_type must be a non-empty string")

    retention = record.get("retention")
    if retention not in {
        RetentionState.CONTENT_RETAINED.value,
        RetentionState.DIGEST_ONLY.value,
    }:
        raise VerificationError("artifact record retention is invalid")
    if retention != manifest_entry["retention"]:
        raise VerificationError("artifact record retention differs from manifest")

    if retention == RetentionState.CONTENT_RETAINED.value:
        content_path = bundle_dir / _artifact_content_relative(str(content_identity))
        if content_path.is_symlink() or not content_path.is_file():
            raise VerificationError("retained artifact content is missing or unsafe")
        try:
            data = content_path.read_bytes()
        except OSError as exc:
            raise VerificationError(f"retained artifact cannot be read: {exc}") from exc
        if len(data) != byte_count:
            raise VerificationError("retained artifact byte-count mismatch")
        if sha256_identity(data) != content_identity:
            raise VerificationError("retained artifact SHA-256 mismatch")

    expected_record_identity = artifact_record_identity(record)
    if manifest_entry["record_identity"] != expected_record_identity:
        raise VerificationError(
            "artifact record identity does not match canonical metadata"
        )


def _verify_event(
    path: Path,
    *,
    expected_identity: str,
) -> tuple[list[str], list[str], list[str]]:
    envelope = _read_canonical_object(path, label=path.as_posix())
    _exact_keys(
        envelope,
        {"core", "event_identity", "self_hash_exclusion"},
        "event envelope",
    )
    if envelope.get("self_hash_exclusion") != "event_identity":
        raise VerificationError("event self_hash_exclusion must be event_identity")
    if envelope.get("event_identity") != expected_identity:
        raise VerificationError("event envelope identity differs from manifest")

    core = envelope.get("core")
    if not isinstance(core, dict):
        raise VerificationError("event core must be an object")
    _exact_keys(
        core,
        {
            "schema",
            "canonicalization",
            "evidence_class",
            "actor",
            "operation",
            "inputs",
            "outputs",
            "relationships",
            "collection_status",
        },
        "event core",
    )
    if core.get("schema") != EVENT_SCHEMA:
        raise VerificationError("event schema changed")
    if core.get("canonicalization") != CANONICALIZATION_ID:
        raise VerificationError("event canonicalization changed")
    if core.get("evidence_class") not in {item.value for item in EvidenceClass}:
        raise VerificationError("event evidence_class is invalid")
    if core.get("collection_status") not in {
        item.value for item in CollectionStatus
    }:
        raise VerificationError("event collection_status is invalid")
    if not isinstance(core.get("actor"), str) or not core["actor"]:
        raise VerificationError("event actor must be a non-empty string")
    if not isinstance(core.get("operation"), str) or not core["operation"]:
        raise VerificationError("event operation must be a non-empty string")

    inputs = core.get("inputs")
    outputs = core.get("outputs")
    relationships = core.get("relationships")
    if not isinstance(inputs, list) or not isinstance(outputs, list):
        raise VerificationError("event inputs and outputs must be lists")
    if not isinstance(relationships, list):
        raise VerificationError("event relationships must be a list")

    normalized_inputs: list[str] = []
    normalized_outputs: list[str] = []
    relationship_targets: list[str] = []

    for index, value in enumerate(inputs):
        _identity_digest(value, label=f"event input[{index}]")
        normalized_inputs.append(str(value))
    for index, value in enumerate(outputs):
        _identity_digest(value, label=f"event output[{index}]")
        normalized_outputs.append(str(value))

    has_derived_from = False
    for index, relationship in enumerate(relationships):
        if not isinstance(relationship, dict):
            raise VerificationError(f"event relationship[{index}] must be an object")
        _exact_keys(
            relationship,
            {"kind", "target"},
            f"event relationship[{index}]",
        )
        kind = relationship.get("kind")
        if not isinstance(kind, str) or not kind:
            raise VerificationError(
                f"event relationship[{index}] kind must be a non-empty string"
            )
        target = relationship.get("target")
        _identity_digest(target, label=f"event relationship[{index}] target")
        relationship_targets.append(str(target))
        has_derived_from = has_derived_from or kind == "derived_from"

    if core["evidence_class"] == EvidenceClass.DERIVED.value:
        if not normalized_inputs and not has_derived_from:
            raise VerificationError("DERIVED event does not identify a source")

    if event_identity(core) != expected_identity:
        raise VerificationError("event identity does not match canonical event core")

    return normalized_inputs, normalized_outputs, relationship_targets


def _physical_files(bundle_dir: Path) -> tuple[set[str], list[str]]:
    files: set[str] = set()
    unsafe: list[str] = []
    try:
        paths = list(bundle_dir.rglob("*"))
    except OSError as exc:
        raise VerificationError(f"cannot enumerate bundle: {exc}") from exc
    for path in paths:
        relative = path.relative_to(bundle_dir).as_posix()
        if path.is_symlink():
            unsafe.append(relative)
            continue
        if path.is_file():
            files.add(relative)
    return files, unsafe


def verify_bundle(bundle_dir: Path) -> VerificationReport:
    """Verify a PROVENANCE bundle without modifying any evidence."""

    bundle_dir = Path(bundle_dir)
    checks: list[str] = []
    errors: list[str] = []
    manifest_identity_value: str | None = None
    scope: str | None = None
    known_missing = 0

    if bundle_dir.is_symlink():
        errors.append("bundle root must not be a symbolic link")
        return VerificationReport(
            False, None, None, 0, tuple(checks), tuple(errors)
        )
    if not bundle_dir.is_dir():
        errors.append("bundle path must be an existing directory")
        return VerificationReport(
            False, None, None, 0, tuple(checks), tuple(errors)
        )

    manifest_path = bundle_dir / "manifest.json"
    if manifest_path.is_symlink():
        errors.append("manifest.json must not be a symbolic link")
        return VerificationReport(
            False, None, None, 0, tuple(checks), tuple(errors)
        )
    try:
        (
            _manifest_core,
            artifacts,
            events,
            scope,
            manifest_identity_value,
            known_missing,
        ) = _verify_manifest(manifest_path)
        checks.append("manifest canonical form, schema and identity verified")
    except VerificationError as exc:
        errors.append(str(exc))
        return VerificationReport(
            False,
            manifest_identity_value,
            scope,
            known_missing,
            tuple(checks),
            tuple(errors),
        )

    expected_files: set[str] = {"manifest.json"}
    for entry in artifacts:
        if entry["retention"] == RetentionState.MISSING.value:
            continue
        expected_files.add(_artifact_record_relative(entry["record_identity"]))
        if entry["retention"] == RetentionState.CONTENT_RETAINED.value:
            expected_files.add(_artifact_content_relative(entry["content_identity"]))
    for identity in events:
        expected_files.add(_event_relative(identity))

    try:
        physical_files, unsafe_paths = _physical_files(bundle_dir)
    except VerificationError as exc:
        errors.append(str(exc))
        physical_files, unsafe_paths = set(), []

    if unsafe_paths:
        errors.append(
            "symbolic links are forbidden inside evidence bundles: "
            + ", ".join(sorted(unsafe_paths))
        )
    missing_files = sorted(expected_files - physical_files)
    extra_files = sorted(physical_files - expected_files)
    if missing_files:
        errors.append("bundle is missing declared files: " + ", ".join(missing_files))
    if extra_files:
        errors.append("bundle contains undeclared files: " + ", ".join(extra_files))
    if not unsafe_paths and not missing_files and not extra_files:
        checks.append("physical bundle membership exactly matches the manifest")

    artifact_content_ids = {str(entry["content_identity"]) for entry in artifacts}
    event_ids = set(events)

    artifact_phase_ok = True
    for entry in artifacts:
        if entry["retention"] == RetentionState.MISSING.value:
            continue
        relative = _artifact_record_relative(entry["record_identity"])
        path = bundle_dir / relative
        if path.is_symlink() or not path.is_file():
            artifact_phase_ok = False
            continue
        try:
            _verify_artifact_record(
                path,
                manifest_entry=entry,
                bundle_dir=bundle_dir,
            )
        except VerificationError as exc:
            artifact_phase_ok = False
            errors.append(f"{relative}: {exc}")
    if artifact_phase_ok:
        checks.append("artifact metadata and available content verified")

    event_phase_ok = True
    references: list[tuple[str, str, str]] = []
    for identity in events:
        relative = _event_relative(identity)
        path = bundle_dir / relative
        if path.is_symlink() or not path.is_file():
            event_phase_ok = False
            continue
        try:
            inputs, outputs, relationship_targets = _verify_event(
                path,
                expected_identity=identity,
            )
        except VerificationError as exc:
            event_phase_ok = False
            errors.append(f"{relative}: {exc}")
            continue
        references.extend((relative, "input", value) for value in inputs)
        references.extend((relative, "output", value) for value in outputs)
        references.extend(
            (relative, "relationship", value) for value in relationship_targets
        )

    resolvable_relationship_targets = artifact_content_ids | event_ids
    for relative, reference_kind, target in references:
        if reference_kind in {"input", "output"}:
            if target not in artifact_content_ids:
                event_phase_ok = False
                errors.append(
                    f"{relative}: {reference_kind} does not resolve to a manifest artifact: {target}"
                )
        elif target not in resolvable_relationship_targets:
            event_phase_ok = False
            errors.append(
                f"{relative}: relationship target does not resolve inside the manifest: {target}"
            )

    if event_phase_ok:
        checks.append("event identities and references verified")

    integrity_verified = not errors
    return VerificationReport(
        integrity_verified=integrity_verified,
        manifest_identity=manifest_identity_value,
        manifest_scope=scope,
        known_missing_artifacts=known_missing,
        checks=tuple(checks),
        errors=tuple(errors),
    )
