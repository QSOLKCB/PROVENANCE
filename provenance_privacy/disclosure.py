"""Phase 14 selective-disclosure producer."""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import uuid
from typing import Iterable

from provenance_core import (
    ArtifactRecord,
    CollectionStatus,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    Relationship,
    RetentionState,
    artifact_record_identity,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_privacy.model import (
    DISCLOSURE_SCHEMA,
    REDACTION_ACTOR,
    REDACTION_OPERATION,
    RedactionRange,
    apply_redaction,
    build_redaction_spec_core,
    disclosure_identity,
    redaction_spec_identity,
)
from provenance_verify.package import verify_forensic_package_fd
from provenance_verify.privacy import verify_selective_disclosure_fd


_CHUNK_SIZE = 1024 * 1024
_STRUCTURED_LIMIT = 16 * 1024 * 1024
_RENAME_NOREPLACE = 1

try:
    _LIBC = ctypes.CDLL(None, use_errno=True)
    _RENAMEAT2 = _LIBC.renameat2
    _RENAMEAT2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    _RENAMEAT2.restype = ctypes.c_int
except AttributeError:
    _RENAMEAT2 = None


class PrivacyError(RuntimeError):
    """Raised when a selective disclosure cannot be created safely."""


@dataclass(frozen=True, slots=True)
class SelectiveDisclosure:
    path: Path
    disclosure_identity: str
    source_content_identity: str
    derivative_content_identity: str
    derivation_event_identity: str


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required if not hasattr(os, name)]
    for operation, label in (
        (os.open, "dir_fd support for os.open"),
        (os.unlink, "dir_fd support for os.unlink"),
    ):
        if operation not in os.supports_dir_fd:
            missing.append(label)
    if missing:
        raise PrivacyError(
            "selective disclosure requires descriptor-relative filesystem support: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _rename_noreplace_at(
    source_dir_fd: int,
    source_name: str,
    destination_dir_fd: int,
    destination_name: str,
) -> None:
    if _RENAMEAT2 is None:
        raise PrivacyError(
            "safe no-replace publication requires renameat2(RENAME_NOREPLACE)"
        )
    ctypes.set_errno(0)
    result = _RENAMEAT2(
        source_dir_fd,
        os.fsencode(source_name),
        destination_dir_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise PrivacyError(
            "disclosure destination must not already exist"
        )
    raise PrivacyError(
        "no-replace disclosure publication failed: "
        + os.strerror(error)
    )


def _file_read_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0)
    )


def _file_create_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise PrivacyError("short disclosure write")
        offset += written


def _read_all(fd: int, *, limit: int | None = None) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if limit is not None and total > limit:
            raise PrivacyError("structured source member exceeds size limit")
        chunks.append(chunk)


def _directory_identity(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise PrivacyError("expected directory descriptor")
    return info.st_dev, info.st_ino


def _path_matches(path: Path, expected: tuple[int, int]) -> bool:
    try:
        fd = os.open(path, _directory_flags())
    except OSError:
        return False
    try:
        return _directory_identity(fd) == expected
    finally:
        os.close(fd)


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
    parts: tuple[str, ...],
    *,
    structured: bool = True,
) -> bytes:
    parent_fd = _open_dir_at(root_fd, parts[:-1])
    try:
        fd = os.open(parts[-1], _file_read_flags(), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PrivacyError(
                "source package member is not a regular file: "
                + "/".join(parts)
            )
        return _read_all(
            fd,
            limit=_STRUCTURED_LIMIT if structured else None,
        )
    finally:
        os.close(fd)


def _canonical_object(
    root_fd: int,
    parts: tuple[str, ...],
) -> dict[str, object]:
    try:
        value = parse_canonical_json_bytes(_read_member(root_fd, parts))
    except Exception as exc:
        raise PrivacyError(
            f"{'/'.join(parts)} is not canonical JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise PrivacyError(f"{'/'.join(parts)} must contain an object")
    return value


def _source_material(
    package_fd: int,
    source_content_identity: str,
) -> tuple[str, ArtifactRecord, bytes]:
    try:
        require_sha256_identity(
            source_content_identity,
            label="source content identity",
        )
    except (TypeError, ValueError) as exc:
        raise PrivacyError(str(exc)) from exc

    report = verify_forensic_package_fd(package_fd)
    if not report.integrity_verified or report.package_identity is None:
        raise PrivacyError(
            "source forensic package failed independent verification: "
            + "; ".join(report.errors)
        )
    package_identity = report.package_identity

    evidence_fd = _open_dir_at(package_fd, ("evidence",))
    try:
        manifest = _canonical_object(evidence_fd, ("manifest.json",))
        core = manifest.get("core")
        if not isinstance(core, dict):
            raise PrivacyError("source manifest core must be an object")
        artifacts = core.get("artifacts")
        if not isinstance(artifacts, list):
            raise PrivacyError("source manifest artifacts must be a list")
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("content_identity") == source_content_identity
        ]
        if len(matches) != 1:
            raise PrivacyError(
                "source artifact identity must occur exactly once in source manifest"
            )
        entry = matches[0]
        if entry.get("retention") != RetentionState.CONTENT_RETAINED.value:
            raise PrivacyError(
                "redaction requires source content retained in the source package"
            )
        record_identity = entry.get("record_identity")
        try:
            require_sha256_identity(
                record_identity,
                label="source artifact record identity",
            )
        except (TypeError, ValueError) as exc:
            raise PrivacyError(str(exc)) from exc
        record_digest = str(record_identity).split(":", 1)[1]
        record_value = _canonical_object(
            evidence_fd,
            ("artifact_records", "sha256", f"{record_digest}.json"),
        )
        try:
            record = ArtifactRecord(
                content_identity=record_value.get("content_identity"),
                byte_count=record_value.get("byte_count"),
                media_type=record_value.get("media_type"),
                retention=RetentionState(record_value.get("retention")),
            )
        except (TypeError, ValueError) as exc:
            raise PrivacyError(
                f"source artifact record is invalid: {exc}"
            ) from exc
        if (
            record.record_identity != record_identity
            or record.content_identity != source_content_identity
            or record.retention is not RetentionState.CONTENT_RETAINED
        ):
            raise PrivacyError(
                "source artifact record does not match source manifest"
            )

        content_digest = source_content_identity.split(":", 1)[1]
        source = _read_member(
            evidence_fd,
            ("artifacts", "sha256", content_digest),
            structured=False,
        )
    finally:
        os.close(evidence_fd)

    if (
        len(source) != record.byte_count
        or f"sha256:{hashlib.sha256(source).hexdigest()}"
        != source_content_identity
    ):
        raise PrivacyError("source artifact bytes do not match source record")

    second = verify_forensic_package_fd(package_fd)
    if (
        not second.integrity_verified
        or second.package_identity != package_identity
    ):
        raise PrivacyError(
            "source forensic package changed during redaction capture"
        )
    return package_identity, record, source


def _write_member(
    root_fd: int,
    name: str,
    data: bytes,
    members: list[dict[str, object]],
) -> None:
    if "/" in name or name in {"", ".", ".."}:
        raise PrivacyError("unsafe disclosure member name")
    fd = os.open(
        name,
        _file_create_flags(),
        0o600,
        dir_fd=root_fd,
    )
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    members.append(
        {
            "path": name,
            "content_identity": (
                f"sha256:{hashlib.sha256(data).hexdigest()}"
            ),
            "byte_count": len(data),
        }
    )


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        try:
            for child in os.listdir(child_fd):
                _remove_tree_at(child_fd, child)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    else:
        os.unlink(name, dir_fd=parent_fd)


def create_redacted_disclosure(
    source_package: Path | str,
    source_content_identity: str,
    ranges: Iterable[RedactionRange | tuple[int, int]],
    destination: Path | str,
    *,
    mask_byte: int = 42,
) -> SelectiveDisclosure:
    package_path = Path(source_package).expanduser()
    if package_path.is_symlink():
        raise PrivacyError("source package root must not be a symlink")
    try:
        package_fd = os.open(package_path, _directory_flags())
    except OSError as exc:
        raise PrivacyError(
            f"source package cannot be opened safely: {exc}"
        ) from exc

    supplied = Path(destination).expanduser()
    parent_fd: int | None = None
    created_name: str | None = None
    staging_name = f".{supplied.name}.{uuid.uuid4().hex}.tmp"
    try:
        package_identity, source_record, source = _source_material(
            package_fd,
            source_content_identity,
        )

        spec_core = build_redaction_spec_core(
            source_content_identity=source_record.content_identity,
            source_record_identity=source_record.record_identity,
            source_byte_count=source_record.byte_count,
            source_media_type=source_record.media_type,
            ranges=ranges,
            mask_byte=mask_byte,
        )
        spec_identity = redaction_spec_identity(spec_core)
        spec_envelope = {
            "core": spec_core,
            "redaction_spec_identity": spec_identity,
            "self_hash_exclusion": "redaction_spec_identity",
        }

        normalized_ranges = tuple(
            (item["start"], item["end"])
            for item in spec_core["ranges"]
        )
        derivative = apply_redaction(
            source,
            ranges=normalized_ranges,
            mask_byte=mask_byte,
        )
        derivative_record = ArtifactRecord.from_bytes(
            derivative,
            media_type=source_record.media_type,
            retention=RetentionState.CONTENT_RETAINED,
        )
        if derivative_record.content_identity == source_record.content_identity:
            raise PrivacyError(
                "redaction produced bytes identical to the source artifact"
            )

        event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.DERIVED,
                actor=REDACTION_ACTOR,
                operation=REDACTION_OPERATION,
                inputs=(source_record.content_identity,),
                outputs=(derivative_record.content_identity,),
                relationships=(
                    Relationship(
                        kind="derived_from",
                        target=source_record.content_identity,
                    ),
                ),
                collection_status=CollectionStatus.RECORDED,
            )
        )

        if supplied.name in {"", ".", ".."}:
            raise PrivacyError("disclosure destination name is invalid")
        if supplied.exists() or supplied.is_symlink():
            raise PrivacyError(
                "disclosure destination must not already exist"
            )
        if supplied.parent.is_symlink():
            raise PrivacyError(
                "disclosure destination parent must not be a symlink"
            )
        parent = supplied.parent.resolve(strict=True)
        source_resolved = package_path.resolve(strict=True)
        if parent == source_resolved or source_resolved in parent.parents:
            raise PrivacyError(
                "disclosure destination must be outside source package"
            )

        parent_fd = os.open(parent, _directory_flags())
        parent_identity = _directory_identity(parent_fd)
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        created_name = staging_name
        staging_fd = os.open(
            staging_name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
        staging_identity = _directory_identity(staging_fd)
        members: list[dict[str, object]] = []
        try:
            _write_member(
                staging_fd,
                "source_artifact_record.json",
                canonical_json_bytes(source_record.to_dict()),
                members,
            )
            _write_member(
                staging_fd,
                "redaction_spec.json",
                canonical_json_bytes(spec_envelope),
                members,
            )
            _write_member(
                staging_fd,
                "derivative.bin",
                derivative,
                members,
            )
            _write_member(
                staging_fd,
                "derivative_artifact_record.json",
                canonical_json_bytes(derivative_record.to_dict()),
                members,
            )
            _write_member(
                staging_fd,
                "derivation_event.json",
                canonical_json_bytes(event.to_dict()),
                members,
            )
            members.sort(key=lambda item: str(item["path"]))

            disclosure_core = {
                "schema": DISCLOSURE_SCHEMA,
                "canonicalization": spec_core["canonicalization"],
                "disclosure_state": "FINALIZED",
                "source_package_identity": package_identity,
                "source_content_identity": source_record.content_identity,
                "source_record_identity": source_record.record_identity,
                "source_disclosure_retention": "DIGEST_ONLY",
                "derivative_content_identity": (
                    derivative_record.content_identity
                ),
                "derivative_record_identity": (
                    derivative_record.record_identity
                ),
                "derivative_disclosure_retention": "CONTENT_RETAINED",
                "derivation_event_identity": event.event_identity,
                "redaction_spec_identity": spec_identity,
                "members": members,
            }
            identity = disclosure_identity(disclosure_core)
            disclosure_envelope = {
                "core": disclosure_core,
                "disclosure_identity": identity,
                "self_hash_exclusion": "disclosure_identity",
            }
            fd = os.open(
                "disclosure.json",
                _file_create_flags(),
                0o600,
                dir_fd=staging_fd,
            )
            try:
                _write_all(
                    fd,
                    canonical_json_bytes(disclosure_envelope),
                )
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(staging_fd)

            verification = verify_selective_disclosure_fd(
                staging_fd,
                source_package_fd=package_fd,
            )
            if (
                not verification.integrity_verified
                or verification.lineage != "VERIFIED"
                or verification.transformation != "VERIFIED"
                or verification.source_package_binding != "VERIFIED"
                or verification.disclosure_identity != identity
            ):
                raise PrivacyError(
                    "staged selective disclosure failed independent verification: "
                    + "; ".join(verification.errors)
                )
        finally:
            os.close(staging_fd)

        if not _path_matches(parent, parent_identity):
            raise PrivacyError(
                "disclosure destination parent changed before publication"
            )
        _rename_noreplace_at(
            parent_fd,
            staging_name,
            parent_fd,
            supplied.name,
        )
        # Publication succeeded. From this point on, never recursively remove
        # the final name on failure: a hostile process could replace that name
        # after publication and cleanup must not delete unrelated data.
        created_name = None
        os.fsync(parent_fd)
        final_path = parent / supplied.name
        final_fd = os.open(
            supplied.name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
        try:
            if _directory_identity(final_fd) != staging_identity:
                raise PrivacyError(
                    "published disclosure filesystem identity changed"
                )
            verification = verify_selective_disclosure_fd(
                final_fd,
                source_package_fd=package_fd,
            )
        finally:
            os.close(final_fd)
        if (
            not verification.integrity_verified
            or verification.disclosure_identity != identity
            or verification.transformation != "VERIFIED"
        ):
            raise PrivacyError(
                "published selective disclosure failed independent verification: "
                + "; ".join(verification.errors)
            )

        created_name = None
        return SelectiveDisclosure(
            path=final_path,
            disclosure_identity=identity,
            source_content_identity=source_record.content_identity,
            derivative_content_identity=(
                derivative_record.content_identity
            ),
            derivation_event_identity=event.event_identity,
        )
    except Exception:
        if parent_fd is not None and created_name is not None:
            try:
                _remove_tree_at(parent_fd, created_name)
                os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        os.close(package_fd)
