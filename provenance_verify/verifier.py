"""Independent, read-only verification for PROVENANCE evidence bundles."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
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
)

VERIFICATION_REPORT_SCHEMA = "provenance.verification-report.v1"
READ_CHUNK_SIZE = 1024 * 1024


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


def _require_enum_string(value: Any, allowed: set[str], *, label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise VerificationError(f"{label} is invalid")
    return value


def _event_relative(identity: str) -> str:
    return f"events/sha256/{_identity_digest(identity, label='event identity')}.json"


def _artifact_record_relative(identity: str) -> str:
    return (
        f"artifact_records/sha256/"
        f"{_identity_digest(identity, label='artifact record identity')}.json"
    )


def _artifact_content_relative(identity: str) -> str:
    return f"artifacts/sha256/{_identity_digest(identity, label='artifact content identity')}"


def _descriptor_flags(*, directory: bool) -> int:
    required = ("O_NOFOLLOW", "O_CLOEXEC")
    if directory:
        required += ("O_DIRECTORY",)
    missing = [name for name in required if not hasattr(os, name)]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if missing:
        raise VerificationError(
            "secure descriptor-relative verification is unsupported: "
            + ", ".join(missing)
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_bundle_root(bundle_dir: Path) -> int:
    flags = _descriptor_flags(directory=True)
    try:
        fd = os.open(bundle_dir, flags)
    except OSError as exc:
        raise VerificationError(f"bundle root cannot be opened safely: {exc}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise VerificationError("bundle root must be a directory")
        return fd
    except Exception:
        os.close(fd)
        raise


def _relative_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        raise VerificationError("evidence path must be a non-empty relative path")
    parts = tuple(relative.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise VerificationError(f"unsafe evidence path: {relative}")
    return parts


def _open_relative_regular(root_fd: int, relative: str, *, label: str) -> int:
    """Open a required file through trusted directory descriptors only."""

    parts = _relative_parts(relative)
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(
                    part,
                    _descriptor_flags(directory=True),
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise VerificationError(
                    f"{label} parent path is missing or unsafe: {exc}"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd

        try:
            file_fd = os.open(
                parts[-1],
                _descriptor_flags(directory=False),
                dir_fd=current_fd,
            )
        except OSError as exc:
            raise VerificationError(
                f"{label} is missing or unsafe: {exc}"
            ) from exc

        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise VerificationError(
                    f"{label} must be a regular non-symlink file"
                )
            return file_fd
        except Exception:
            os.close(file_fd)
            raise
    finally:
        os.close(current_fd)


def _read_regular_bytes(root_fd: int, relative: str, *, label: str) -> bytes:
    fd = _open_relative_regular(root_fd, relative, label=label)
    data = bytearray()
    try:
        while True:
            try:
                chunk = os.read(fd, READ_CHUNK_SIZE)
            except OSError as exc:
                raise VerificationError(f"{label} cannot be read: {exc}") from exc
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(fd)
    return bytes(data)


def _read_canonical_object(
    root_fd: int,
    relative: str,
    *,
    label: str,
) -> dict[str, Any]:
    data = _read_regular_bytes(root_fd, relative, label=label)
    try:
        value = parse_canonical_json_bytes(data)
    except RecursionError as exc:
        raise VerificationError(
            f"{label} exceeds supported JSON nesting depth"
        ) from exc
    except CanonicalizationError as exc:
        raise VerificationError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value


def _stream_content_identity(
    root_fd: int,
    relative: str,
    *,
    label: str,
) -> tuple[int, str]:
    fd = _open_relative_regular(root_fd, relative, label=label)
    digest = hashlib.sha256()
    byte_count = 0
    try:
        while True:
            try:
                chunk = os.read(fd, READ_CHUNK_SIZE)
            except OSError as exc:
                raise VerificationError(f"{label} cannot be read: {exc}") from exc
            if not chunk:
                break
            byte_count += len(chunk)
            digest.update(chunk)
    finally:
        os.close(fd)
    return byte_count, f"sha256:{digest.hexdigest()}"


def _verify_manifest(
    root_fd: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], str, str, int]:
    envelope = _read_canonical_object(
        root_fd,
        "manifest.json",
        label="manifest.json",
    )
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

    scope = _require_enum_string(
        core.get("scope"),
        {"open", "closed"},
        label="manifest scope",
    )

    artifacts = core.get("artifacts")
    events = core.get("events")
    if not isinstance(artifacts, list):
        raise VerificationError("manifest artifacts must be a list")
    if not isinstance(events, list):
        raise VerificationError("manifest events must be a list")

    normalized_artifacts: list[dict[str, Any]] = []
    artifact_keys: list[str] = []
    known_missing = 0
    retention_values = {item.value for item in RetentionState}
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
        retention = _require_enum_string(
            entry.get("retention"),
            retention_values,
            label=f"manifest artifact[{index}] retention",
        )

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
        scope,
        str(claimed_identity),
        known_missing,
    )


def _verify_artifact_record(
    root_fd: int,
    relative: str,
    *,
    manifest_entry: dict[str, Any],
) -> None:
    record = _read_canonical_object(root_fd, relative, label=relative)
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

    retention = _require_enum_string(
        record.get("retention"),
        {
            RetentionState.CONTENT_RETAINED.value,
            RetentionState.DIGEST_ONLY.value,
        },
        label="artifact record retention",
    )
    if retention != manifest_entry["retention"]:
        raise VerificationError("artifact record retention differs from manifest")

    if retention == RetentionState.CONTENT_RETAINED.value:
        content_relative = _artifact_content_relative(str(content_identity))
        observed_count, observed_identity = _stream_content_identity(
            root_fd,
            content_relative,
            label=content_relative,
        )
        if observed_count != byte_count:
            raise VerificationError("retained artifact byte-count mismatch")
        if observed_identity != content_identity:
            raise VerificationError("retained artifact SHA-256 mismatch")

    expected_record_identity = artifact_record_identity(record)
    if manifest_entry["record_identity"] != expected_record_identity:
        raise VerificationError(
            "artifact record identity does not match canonical metadata"
        )


def _verify_event(
    root_fd: int,
    relative: str,
    *,
    expected_identity: str,
) -> tuple[list[str], list[str], list[str]]:
    envelope = _read_canonical_object(root_fd, relative, label=relative)
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

    evidence_class = _require_enum_string(
        core.get("evidence_class"),
        {item.value for item in EvidenceClass},
        label="event evidence_class",
    )
    _require_enum_string(
        core.get("collection_status"),
        {item.value for item in CollectionStatus},
        label="event collection_status",
    )

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

    if evidence_class == EvidenceClass.DERIVED.value:
        if not normalized_inputs and not has_derived_from:
            raise VerificationError("DERIVED event does not identify a source")

    if event_identity(core) != expected_identity:
        raise VerificationError("event identity does not match canonical event core")

    return normalized_inputs, normalized_outputs, relationship_targets


def _physical_files(root_fd: int) -> tuple[set[str], list[str]]:
    """Enumerate all bundle entries without suppressing traversal failures."""

    if os.scandir not in os.supports_fd:
        raise VerificationError(
            "secure descriptor-relative verification requires scandir(fd) support"
        )

    files: set[str] = set()
    unsafe: list[str] = []
    stack: list[tuple[int, str]] = [(os.dup(root_fd), "")]
    try:
        while stack:
            dir_fd, prefix = stack.pop()
            try:
                with os.scandir(dir_fd) as entries:
                    for entry in entries:
                        relative = f"{prefix}/{entry.name}" if prefix else entry.name
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                        except OSError as exc:
                            raise VerificationError(
                                f"cannot inspect bundle entry {relative}: {exc}"
                            ) from exc

                        if stat.S_ISREG(mode):
                            files.add(relative)
                        elif stat.S_ISDIR(mode):
                            try:
                                child_fd = os.open(
                                    entry.name,
                                    _descriptor_flags(directory=True),
                                    dir_fd=dir_fd,
                                )
                            except OSError as exc:
                                raise VerificationError(
                                    f"cannot traverse bundle directory {relative}: {exc}"
                                ) from exc
                            stack.append((child_fd, relative))
                        else:
                            unsafe.append(relative)
            except OSError as exc:
                raise VerificationError(
                    f"cannot enumerate bundle directory {prefix or '.'}: {exc}"
                ) from exc
            finally:
                os.close(dir_fd)
    finally:
        for dir_fd, _prefix in stack:
            try:
                os.close(dir_fd)
            except OSError:
                pass

    return files, unsafe


def _artifact_task(
    args: tuple[int, dict[str, Any]],
) -> tuple[str, str | None]:
    root_fd, entry = args
    relative = _artifact_record_relative(entry["record_identity"])
    try:
        _verify_artifact_record(
            root_fd,
            relative,
            manifest_entry=entry,
        )
    except VerificationError as exc:
        return relative, str(exc)
    return relative, None


def _event_task(
    args: tuple[int, str],
) -> tuple[
    str,
    list[str] | None,
    list[str] | None,
    list[str] | None,
    str | None,
]:
    root_fd, identity = args
    relative = _event_relative(identity)
    try:
        inputs, outputs, relationship_targets = _verify_event(
            root_fd,
            relative,
            expected_identity=identity,
        )
    except VerificationError as exc:
        return relative, None, None, None, str(exc)
    return (
        relative,
        inputs,
        outputs,
        relationship_targets,
        None,
    )


def _verify_bundle_root_fd(
    root_fd: int,
    *,
    max_workers: int,
) -> VerificationReport:
    checks: list[str] = []
    errors: list[str] = []
    manifest_identity_value: str | None = None
    scope: str | None = None
    known_missing = 0
    try:
        (
            _manifest_core,
            artifacts,
            events,
            scope,
            manifest_identity_value,
            known_missing,
        ) = _verify_manifest(root_fd)
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
            expected_files.add(
                _artifact_content_relative(entry["content_identity"])
            )
    for identity in events:
        expected_files.add(_event_relative(identity))

    try:
        physical_files, unsafe_paths = _physical_files(root_fd)
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

    membership_phase_ok = True
    if unsafe_paths:
        membership_phase_ok = False
        errors.append(
            "non-regular filesystem entries are forbidden inside evidence bundles: "
            + ", ".join(sorted(unsafe_paths))
        )

    missing_files = sorted(expected_files - physical_files)
    extra_files = sorted(physical_files - expected_files)
    if missing_files:
        membership_phase_ok = False
        errors.append(
            "bundle is missing declared files: " + ", ".join(missing_files)
        )
    if extra_files:
        membership_phase_ok = False
        errors.append(
            "bundle contains undeclared files: " + ", ".join(extra_files)
        )
    if membership_phase_ok:
        checks.append("physical bundle membership exactly matches the manifest")

    # Unsafe entries can redirect or block path traversal. Do not read children
    # after discovering them even though descriptor-relative opens would reject
    # the same boundary again.
    if unsafe_paths:
        return VerificationReport(
            False,
            manifest_identity_value,
            scope,
            known_missing,
            tuple(checks),
            tuple(errors),
        )

    artifact_content_ids = {
        str(entry["content_identity"]) for entry in artifacts
    }
    event_ids = set(events)

    artifact_phase_ok = True
    artifact_entries = [
        entry
        for entry in artifacts
        if entry["retention"] != RetentionState.MISSING.value
    ]
    artifact_results = ordered_bounded_map(
        _artifact_task,
        [(root_fd, entry) for entry in artifact_entries],
        max_workers=max_workers,
    )
    for relative, error in artifact_results:
        if error is not None:
            artifact_phase_ok = False
            errors.append(f"{relative}: {error}")
    if artifact_phase_ok:
        checks.append("artifact metadata and available content verified")

    event_phase_ok = True
    references: list[tuple[str, str, str]] = []
    event_results = ordered_bounded_map(
        _event_task,
        [(root_fd, identity) for identity in events],
        max_workers=max_workers,
    )
    for (
        relative,
        inputs,
        outputs,
        relationship_targets,
        error,
    ) in event_results:
        if error is not None:
            event_phase_ok = False
            errors.append(f"{relative}: {error}")
            continue
        assert inputs is not None
        assert outputs is not None
        assert relationship_targets is not None
        references.extend((relative, "input", value) for value in inputs)
        references.extend((relative, "output", value) for value in outputs)
        references.extend(
            (relative, "relationship", value)
            for value in relationship_targets
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

    integrity_verified = (
        membership_phase_ok
        and artifact_phase_ok
        and event_phase_ok
        and not errors
    )
    return VerificationReport(
        integrity_verified=integrity_verified,
        manifest_identity=manifest_identity_value,
        manifest_scope=scope,
        known_missing_artifacts=known_missing,
        checks=tuple(checks),
        errors=tuple(errors),
    )


def verify_bundle_fd(bundle_fd: int) -> VerificationReport:
    """Verify an already-open PROVENANCE bundle directory descriptor."""

    checks: tuple[str, ...] = ()
    try:
        root_fd = os.dup(bundle_fd)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            os.close(root_fd)
            raise VerificationError("bundle descriptor must reference a directory")
    except (OSError, TypeError, VerificationError) as exc:
        return VerificationReport(
            False, None, None, 0, checks, (str(exc),)
        )
    try:
        return _verify_bundle_root_fd(
            root_fd,
            max_workers=DEFAULT_MAX_VERIFY_WORKERS,
        )
    finally:
        os.close(root_fd)


def verify_bundle_fd_reference(bundle_fd: int) -> VerificationReport:
    """Serial reference verifier for Phase 13 equivalence checks."""

    checks: tuple[str, ...] = ()
    try:
        root_fd = os.dup(bundle_fd)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            os.close(root_fd)
            raise VerificationError("bundle descriptor must reference a directory")
    except (OSError, TypeError, VerificationError) as exc:
        return VerificationReport(
            False, None, None, 0, checks, (str(exc),)
        )
    try:
        return _verify_bundle_root_fd(root_fd, max_workers=1)
    finally:
        os.close(root_fd)


def verify_bundle_reference(bundle_dir: Path) -> VerificationReport:
    """Serial reference verifier retained for exact Phase 13 parity."""

    bundle_dir = Path(bundle_dir)
    try:
        root_fd = _open_bundle_root(bundle_dir)
    except VerificationError as exc:
        return VerificationReport(
            False, None, None, 0, (), (str(exc),)
        )
    try:
        return _verify_bundle_root_fd(root_fd, max_workers=1)
    finally:
        os.close(root_fd)


def verify_bundle(bundle_dir: Path) -> VerificationReport:
    """Verify a PROVENANCE bundle without modifying any evidence."""

    bundle_dir = Path(bundle_dir)
    try:
        root_fd = _open_bundle_root(bundle_dir)
    except VerificationError as exc:
        return VerificationReport(
            False, None, None, 0, (), (str(exc),)
        )
    try:
        return _verify_bundle_root_fd(
            root_fd,
            max_workers=DEFAULT_MAX_VERIFY_WORKERS,
        )
    finally:
        os.close(root_fd)
