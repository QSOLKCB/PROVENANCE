"""Independent verification for Phase 14 selective-disclosure packages."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any

from provenance_core import (
    ARTIFACT_SCHEMA,
    CANONICALIZATION_ID,
    EVENT_SCHEMA,
    ArtifactRecord,
    EvidenceClass,
    Relationship,
    RetentionState,
    artifact_record_identity,
    canonical_json_bytes,
    event_identity,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_privacy.model import (
    DISCLOSURE_SCHEMA,
    REDACTION_ACTOR,
    REDACTION_OPERATION,
    REDACTION_SPEC_SCHEMA,
    apply_redaction,
    disclosure_identity,
    normalize_ranges,
    redaction_spec_identity,
)
from .package import verify_forensic_package_fd


DISCLOSURE_VERIFICATION_REPORT_SCHEMA = (
    "provenance.selective-disclosure-verification-report.v1"
)
_CHUNK_SIZE = 1024 * 1024
_STRUCTURED_LIMIT = 16 * 1024 * 1024
_ALLOWED_MEMBERS = {
    "source_artifact_record.json",
    "redaction_spec.json",
    "derivative.bin",
    "derivative_artifact_record.json",
    "derivation_event.json",
}


@dataclass(frozen=True, slots=True)
class DisclosureVerificationReport:
    integrity_verified: bool
    disclosure_identity: str | None
    source_content_identity: str | None
    derivative_content_identity: str | None
    lineage: str
    transformation: str
    source_package_binding: str
    source_content_disclosed: bool
    checks: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": DISCLOSURE_VERIFICATION_REPORT_SCHEMA,
            "integrity_verified": self.integrity_verified,
            "disclosure_identity": self.disclosure_identity,
            "source_content_identity": self.source_content_identity,
            "derivative_content_identity": self.derivative_content_identity,
            "lineage": self.lineage,
            "transformation": self.transformation,
            "source_package_binding": self.source_package_binding,
            "source_content_disclosed": self.source_content_disclosed,
            "checks": list(self.checks),
            "errors": list(self.errors),
        }


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required if not hasattr(os, name)]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if missing:
        raise ValueError(
            "selective-disclosure verification requires descriptor-relative "
            "filesystem support: " + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0)
    )


def _read_all(fd: int, *, limit: int | None = None) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if limit is not None and total > limit:
            raise ValueError("structured disclosure member exceeds size limit")
        chunks.append(chunk)


def _open_dir_at(root_fd: int, parts: tuple[str, ...]) -> int:
    fd = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_member(
    root_fd: int,
    relative: str,
    *,
    structured: bool = True,
) -> bytes:
    path = PurePosixPath(relative)
    parts = path.parts
    if (
        path.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"unsafe disclosure member path: {relative!r}")
    parent_fd = _open_dir_at(root_fd, tuple(parts[:-1]))
    try:
        fd = os.open(parts[-1], _file_flags(), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(
                f"disclosure member is not a regular file: {relative}"
            )
        return _read_all(
            fd,
            limit=_STRUCTURED_LIMIT if structured else None,
        )
    finally:
        os.close(fd)


def _canonical_object(root_fd: int, relative: str) -> dict[str, Any]:
    value = parse_canonical_json_bytes(_read_member(root_fd, relative))
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain a JSON object")
    return value


def _physical_files(root_fd: int) -> tuple[set[str], set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    unsafe: set[str] = set()
    stack: list[tuple[int, str]] = [(os.dup(root_fd), "")]
    try:
        while stack:
            dir_fd, prefix = stack.pop()
            try:
                with os.scandir(dir_fd) as entries:
                    for entry in entries:
                        relative = (
                            entry.name
                            if not prefix
                            else f"{prefix}/{entry.name}"
                        )
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISREG(mode):
                            files.add(relative)
                        elif stat.S_ISDIR(mode):
                            directories.add(relative)
                            child = os.open(
                                entry.name,
                                _directory_flags(),
                                dir_fd=dir_fd,
                            )
                            stack.append((child, relative))
                        else:
                            unsafe.add(relative)
            finally:
                os.close(dir_fd)
    finally:
        for fd, _prefix in stack:
            try:
                os.close(fd)
            except OSError:
                pass
    return files, directories, unsafe


def _hash_member(root_fd: int, relative: str) -> tuple[str, int]:
    raw = _read_member(root_fd, relative, structured=False)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}", len(raw)


def _artifact_record(value: dict[str, Any], *, label: str) -> ArtifactRecord:
    if set(value) != {
        "schema",
        "canonicalization",
        "content_identity",
        "byte_count",
        "media_type",
        "retention",
    }:
        raise ValueError(f"{label} keys changed")
    if value.get("schema") != ARTIFACT_SCHEMA:
        raise ValueError(f"{label} schema changed")
    if value.get("canonicalization") != CANONICALIZATION_ID:
        raise ValueError(f"{label} canonicalization changed")
    try:
        retention = RetentionState(value.get("retention"))
        return ArtifactRecord(
            content_identity=value.get("content_identity"),
            byte_count=value.get("byte_count"),
            media_type=value.get("media_type"),
            retention=retention,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _verify_source_package_binding(
    package_fd: int,
    *,
    expected_package_identity: str,
    source_content_identity: str,
    source_record: ArtifactRecord,
    redaction_ranges: tuple[tuple[int, int], ...],
    mask_byte: int,
    derivative: bytes,
) -> tuple[str, str, list[str]]:
    errors: list[str] = []
    package_report = verify_forensic_package_fd(package_fd)
    if not package_report.integrity_verified:
        return (
            "FAILED",
            "FAILED",
            [
                "source package failed verification: "
                + "; ".join(package_report.errors)
            ],
        )
    if package_report.package_identity != expected_package_identity:
        return (
            "FAILED",
            "FAILED",
            ["source package identity does not match disclosure"],
        )

    try:
        evidence_fd = _open_dir_at(package_fd, ("evidence",))
        try:
            manifest = _canonical_object(evidence_fd, "manifest.json")
            manifest_core = manifest.get("core")
            if not isinstance(manifest_core, dict):
                raise ValueError("source manifest core must be an object")
            artifacts = manifest_core.get("artifacts")
            if not isinstance(artifacts, list):
                raise ValueError("source manifest artifacts must be a list")
            matches = [
                item
                for item in artifacts
                if isinstance(item, dict)
                and item.get("content_identity") == source_content_identity
            ]
            if len(matches) != 1:
                raise ValueError(
                    "source artifact identity is not uniquely present in source manifest"
                )
            entry = matches[0]
            if entry.get("retention") != RetentionState.CONTENT_RETAINED.value:
                raise ValueError(
                    "source package does not retain source content"
                )
            if entry.get("record_identity") != source_record.record_identity:
                raise ValueError(
                    "source artifact record identity differs from disclosure witness"
                )

            record_digest = source_record.record_identity.split(":", 1)[1]
            record_raw = _read_member(
                evidence_fd,
                f"artifact_records/sha256/{record_digest}.json",
            )
            witness_raw = canonical_json_bytes(source_record.to_dict())
            if record_raw != witness_raw:
                raise ValueError(
                    "source package artifact record differs from disclosure witness"
                )

            content_digest = source_content_identity.split(":", 1)[1]
            source_bytes = _read_member(
                evidence_fd,
                f"artifacts/sha256/{content_digest}",
                structured=False,
            )
        finally:
            os.close(evidence_fd)

        if (
            len(source_bytes) != source_record.byte_count
            or f"sha256:{hashlib.sha256(source_bytes).hexdigest()}"
            != source_content_identity
        ):
            raise ValueError("source package bytes do not match source record")

        expected_derivative = apply_redaction(
            source_bytes,
            ranges=redaction_ranges,
            mask_byte=mask_byte,
        )
        if expected_derivative != derivative:
            raise ValueError(
                "disclosed derivative does not equal declared redaction transform"
            )
    except Exception as exc:
        errors.append(str(exc))
        return "FAILED", "FAILED", errors

    return "VERIFIED", "VERIFIED", []


def _verify_disclosure_root_fd(
    root_fd: int,
    *,
    source_package_fd: int | None,
) -> DisclosureVerificationReport:
    checks: list[str] = []
    errors: list[str] = []
    disclosure_identity_value: str | None = None
    source_identity: str | None = None
    derivative_identity: str | None = None
    lineage = "FAILED"
    transformation = "NOT_ATTEMPTED_SOURCE_WITHHELD"
    source_package_binding = (
        "NOT_ATTEMPTED"
        if source_package_fd is None
        else "FAILED"
    )

    try:
        envelope = _canonical_object(root_fd, "disclosure.json")
        if set(envelope) != {
            "core",
            "disclosure_identity",
            "self_hash_exclusion",
        }:
            raise ValueError("disclosure envelope keys changed")
        core = envelope.get("core")
        if not isinstance(core, dict) or set(core) != {
            "schema",
            "canonicalization",
            "disclosure_state",
            "source_package_identity",
            "source_content_identity",
            "source_record_identity",
            "source_disclosure_retention",
            "derivative_content_identity",
            "derivative_record_identity",
            "derivative_disclosure_retention",
            "derivation_event_identity",
            "redaction_spec_identity",
            "members",
        }:
            raise ValueError("disclosure core keys changed")
        if core.get("schema") != DISCLOSURE_SCHEMA:
            raise ValueError("disclosure schema changed")
        if core.get("canonicalization") != CANONICALIZATION_ID:
            raise ValueError("disclosure canonicalization changed")
        if core.get("disclosure_state") != "FINALIZED":
            raise ValueError("disclosure_state must be FINALIZED")
        if core.get("source_disclosure_retention") != "DIGEST_ONLY":
            raise ValueError(
                "source disclosure retention must be DIGEST_ONLY"
            )
        if (
            core.get("derivative_disclosure_retention")
            != "CONTENT_RETAINED"
        ):
            raise ValueError(
                "derivative disclosure retention must be CONTENT_RETAINED"
            )

        for label, key in (
            ("source package identity", "source_package_identity"),
            ("source content identity", "source_content_identity"),
            ("source record identity", "source_record_identity"),
            ("derivative content identity", "derivative_content_identity"),
            ("derivative record identity", "derivative_record_identity"),
            ("derivation event identity", "derivation_event_identity"),
            ("redaction spec identity", "redaction_spec_identity"),
        ):
            require_sha256_identity(core.get(key), label=label)
        source_identity = str(core["source_content_identity"])
        derivative_identity = str(core["derivative_content_identity"])

        members = core.get("members")
        if not isinstance(members, list) or len(members) != len(_ALLOWED_MEMBERS):
            raise ValueError("disclosure members changed")
        paths: list[str] = []
        normalized_members: list[dict[str, object]] = []
        for index, item in enumerate(members):
            if not isinstance(item, dict) or set(item) != {
                "path",
                "content_identity",
                "byte_count",
            }:
                raise ValueError(f"disclosure member[{index}] keys changed")
            path = item.get("path")
            if path not in _ALLOWED_MEMBERS:
                raise ValueError(
                    f"disclosure member path is outside v1 layout: {path}"
                )
            require_sha256_identity(
                item.get("content_identity"),
                label=f"disclosure member[{index}] identity",
            )
            if (
                type(item.get("byte_count")) is not int
                or item["byte_count"] < 0
            ):
                raise ValueError(
                    f"disclosure member[{index}] byte_count is invalid"
                )
            paths.append(str(path))
            normalized_members.append(item)
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            raise ValueError(
                "disclosure members must be sorted and unique"
            )

        claimed = envelope.get("disclosure_identity")
        require_sha256_identity(claimed, label="disclosure identity")
        if envelope.get("self_hash_exclusion") != "disclosure_identity":
            raise ValueError("disclosure self_hash_exclusion changed")
        if disclosure_identity(core) != claimed:
            raise ValueError(
                "disclosure identity does not match canonical disclosure core"
            )
        disclosure_identity_value = str(claimed)
        checks.append("disclosure envelope and identity verified")

        files, directories, unsafe = _physical_files(root_fd)
        expected_files = {"disclosure.json", *_ALLOWED_MEMBERS}
        if unsafe:
            raise ValueError(
                "non-regular entries are forbidden: "
                + ", ".join(sorted(unsafe))
            )
        if directories:
            raise ValueError(
                "directories are not permitted in disclosure v1: "
                + ", ".join(sorted(directories))
            )
        missing = sorted(expected_files - files)
        extra = sorted(files - expected_files)
        if missing or extra:
            raise ValueError(
                "disclosure physical membership mismatch: "
                + (
                    f"missing={','.join(missing)} " if missing else ""
                )
                + (f"extra={','.join(extra)}" if extra else "")
            )
        checks.append("physical disclosure membership verified")

        by_path = {
            str(item["path"]): item for item in normalized_members
        }
        for path in sorted(_ALLOWED_MEMBERS):
            identity, byte_count = _hash_member(root_fd, path)
            item = by_path[path]
            if identity != item["content_identity"]:
                raise ValueError(
                    f"{path}: member content identity mismatch"
                )
            if byte_count != item["byte_count"]:
                raise ValueError(f"{path}: member byte_count mismatch")
        checks.append("disclosure member hashes and byte counts verified")

        source_record_value = _canonical_object(
            root_fd,
            "source_artifact_record.json",
        )
        source_record = _artifact_record(
            source_record_value,
            label="source artifact record",
        )
        if source_record.retention is not RetentionState.CONTENT_RETAINED:
            raise ValueError(
                "source witness must preserve original CONTENT_RETAINED metadata"
            )
        if source_record.content_identity != source_identity:
            raise ValueError(
                "source artifact record identity differs from disclosure"
            )
        if (
            source_record.record_identity
            != core["source_record_identity"]
        ):
            raise ValueError(
                "source artifact record hash differs from disclosure"
            )

        spec = _canonical_object(root_fd, "redaction_spec.json")
        if set(spec) != {
            "core",
            "redaction_spec_identity",
            "self_hash_exclusion",
        }:
            raise ValueError("redaction spec envelope keys changed")
        spec_core = spec.get("core")
        if not isinstance(spec_core, dict):
            raise ValueError("redaction spec core must be an object")
        if spec_core.get("schema") != REDACTION_SPEC_SCHEMA:
            raise ValueError("redaction spec schema changed")
        if spec_core.get("canonicalization") != CANONICALIZATION_ID:
            raise ValueError("redaction spec canonicalization changed")
        if spec_core.get("method") != "byte-range-mask":
            raise ValueError("redaction method changed")
        if spec_core.get("source_content_identity") != source_identity:
            raise ValueError("redaction spec source identity mismatch")
        if (
            spec_core.get("source_record_identity")
            != source_record.record_identity
        ):
            raise ValueError("redaction spec source record mismatch")
        if spec_core.get("source_byte_count") != source_record.byte_count:
            raise ValueError("redaction spec source byte count mismatch")
        if spec_core.get("source_media_type") != source_record.media_type:
            raise ValueError("redaction spec source media type mismatch")
        ranges_value = spec_core.get("ranges")
        if not isinstance(ranges_value, list):
            raise ValueError("redaction ranges must be a list")
        raw_ranges: list[tuple[int, int]] = []
        for index, item in enumerate(ranges_value):
            if not isinstance(item, dict) or set(item) != {"start", "end"}:
                raise ValueError(f"redaction range[{index}] is malformed")
            raw_ranges.append((item["start"], item["end"]))
        ranges = normalize_ranges(
            raw_ranges,
            byte_count=source_record.byte_count,
        )
        mask_byte = spec_core.get("mask_byte")
        if type(mask_byte) is not int or not 0 <= mask_byte <= 255:
            raise ValueError("redaction mask_byte is invalid")
        claimed_spec = spec.get("redaction_spec_identity")
        require_sha256_identity(
            claimed_spec,
            label="redaction spec identity",
        )
        if spec.get("self_hash_exclusion") != "redaction_spec_identity":
            raise ValueError("redaction spec self_hash_exclusion changed")
        if redaction_spec_identity(spec_core) != claimed_spec:
            raise ValueError("redaction spec identity mismatch")
        if claimed_spec != core["redaction_spec_identity"]:
            raise ValueError("disclosure redaction spec identity mismatch")

        derivative_record_value = _canonical_object(
            root_fd,
            "derivative_artifact_record.json",
        )
        derivative_record = _artifact_record(
            derivative_record_value,
            label="derivative artifact record",
        )
        if (
            derivative_record.retention
            is not RetentionState.CONTENT_RETAINED
        ):
            raise ValueError(
                "derivative artifact must be CONTENT_RETAINED"
            )
        if derivative_record.content_identity != derivative_identity:
            raise ValueError(
                "derivative artifact identity differs from disclosure"
            )
        if (
            derivative_record.record_identity
            != core["derivative_record_identity"]
        ):
            raise ValueError(
                "derivative artifact record identity differs from disclosure"
            )
        derivative = _read_member(
            root_fd,
            "derivative.bin",
            structured=False,
        )
        if (
            len(derivative) != derivative_record.byte_count
            or f"sha256:{hashlib.sha256(derivative).hexdigest()}"
            != derivative_identity
        ):
            raise ValueError(
                "derivative bytes do not match derivative artifact record"
            )

        event = _canonical_object(root_fd, "derivation_event.json")
        if set(event) != {
            "core",
            "event_identity",
            "self_hash_exclusion",
        }:
            raise ValueError("derivation event envelope keys changed")
        event_core = event.get("core")
        if not isinstance(event_core, dict):
            raise ValueError("derivation event core must be an object")
        if event_core.get("schema") != EVENT_SCHEMA:
            raise ValueError("derivation event schema changed")
        if event_core.get("canonicalization") != CANONICALIZATION_ID:
            raise ValueError("derivation event canonicalization changed")
        if event_core.get("evidence_class") != EvidenceClass.DERIVED.value:
            raise ValueError("derivation event must be DERIVED")
        if event_core.get("actor") != REDACTION_ACTOR:
            raise ValueError("derivation event actor changed")
        if event_core.get("operation") != REDACTION_OPERATION:
            raise ValueError("derivation event operation changed")
        if event_core.get("inputs") != [source_identity]:
            raise ValueError("derivation event input must be source artifact")
        if event_core.get("outputs") != [derivative_identity]:
            raise ValueError(
                "derivation event output must be derivative artifact"
            )
        if event_core.get("collection_status") != "RECORDED":
            raise ValueError("derivation event collection status changed")
        relationships = event_core.get("relationships")
        if relationships != [
            {"kind": "derived_from", "target": source_identity}
        ]:
            raise ValueError(
                "derivation event must contain exactly one derived_from source relationship"
            )
        claimed_event = event.get("event_identity")
        require_sha256_identity(
            claimed_event,
            label="derivation event identity",
        )
        if event.get("self_hash_exclusion") != "event_identity":
            raise ValueError("derivation event self_hash_exclusion changed")
        if event_identity(event_core) != claimed_event:
            raise ValueError("derivation event identity mismatch")
        if claimed_event != core["derivation_event_identity"]:
            raise ValueError("disclosure derivation event identity mismatch")

        lineage = "VERIFIED"
        checks.append(
            "redacted derivative is distinct and lineage relationship verified"
        )

        if source_package_fd is not None:
            (
                source_package_binding,
                transformation,
                source_errors,
            ) = _verify_source_package_binding(
                source_package_fd,
                expected_package_identity=str(
                    core["source_package_identity"]
                ),
                source_content_identity=source_identity,
                source_record=source_record,
                redaction_ranges=tuple(
                    (item.start, item.end) for item in ranges
                ),
                mask_byte=mask_byte,
                derivative=derivative,
            )
            errors.extend(source_errors)
            if source_package_binding == "VERIFIED":
                checks.append("source package binding verified")
            if transformation == "VERIFIED":
                checks.append(
                    "redaction transformation recomputed from source bytes"
                )
    except Exception as exc:
        errors.append(str(exc))

    integrity_verified = not errors and lineage == "VERIFIED"
    return DisclosureVerificationReport(
        integrity_verified=integrity_verified,
        disclosure_identity=disclosure_identity_value,
        source_content_identity=source_identity,
        derivative_content_identity=derivative_identity,
        lineage=lineage,
        transformation=transformation,
        source_package_binding=source_package_binding,
        source_content_disclosed=False,
        checks=tuple(checks),
        errors=tuple(errors),
    )


def verify_selective_disclosure(
    disclosure_dir: Path | str,
    *,
    source_package: Path | str | None = None,
) -> DisclosureVerificationReport:
    disclosure = Path(disclosure_dir)
    try:
        root_fd = os.open(disclosure, _directory_flags())
    except OSError as exc:
        return DisclosureVerificationReport(
            False,
            None,
            None,
            None,
            "FAILED",
            "NOT_ATTEMPTED_SOURCE_WITHHELD",
            "NOT_ATTEMPTED",
            False,
            (),
            (f"disclosure root cannot be opened safely: {exc}",),
        )
    source_fd: int | None = None
    try:
        if source_package is not None:
            try:
                source_fd = os.open(
                    Path(source_package),
                    _directory_flags(),
                )
            except OSError as exc:
                return DisclosureVerificationReport(
                    False,
                    None,
                    None,
                    None,
                    "FAILED",
                    "FAILED",
                    "FAILED",
                    False,
                    (),
                    (
                        "source package root cannot be opened safely: "
                        f"{exc}",
                    ),
                )
        return _verify_disclosure_root_fd(
            root_fd,
            source_package_fd=source_fd,
        )
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(root_fd)
