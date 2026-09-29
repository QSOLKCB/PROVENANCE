"""Independent verification for PROVENANCE Phase 11 forensic packages."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from provenance_core import (
    ARTIFACT_SCHEMA,
    CANONICALIZATION_ID,
    CUSTODY_SCHEMA,
    EVENT_SCHEMA,
    MANIFEST_SCHEMA,
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from ._parallel import DEFAULT_MAX_VERIFY_WORKERS, ordered_bounded_map
from .custody import verify_custody_records
from .verifier import (
    verify_bundle,
    verify_bundle_fd,
    verify_bundle_fd_reference,
)


FORENSIC_PACKAGE_SCHEMA = "provenance.forensic-package.v1"
PACKAGE_SCHEMAS_SCHEMA = "provenance.package-schemas.v1"
PACKAGE_GAPS_SCHEMA = "provenance.package-gaps.v1"
PACKAGE_VERIFICATION_METADATA_SCHEMA = (
    "provenance.package-verification-metadata.v1"
)
FORENSIC_PACKAGE_DOMAIN = b"PROVENANCE/FORENSIC-PACKAGE/v1\0"
FORENSIC_PACKAGE_REPORT_SCHEMA = (
    "provenance.forensic-package-verification-report.v1"
)
BUNDLE_CONTRACT = "provenance.bundle.v1"
_CHUNK_SIZE = 1024 * 1024
_STRUCTURED_LIMIT = 16 * 1024 * 1024
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class ForensicPackageVerificationReport:
    integrity_verified: bool
    package_identity: str | None
    evidence_manifest_identity: str | None
    evidence_scope: str | None
    custody_record_count: int
    checks: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": FORENSIC_PACKAGE_REPORT_SCHEMA,
            "integrity_verified": self.integrity_verified,
            "package_identity": self.package_identity,
            "evidence_manifest_identity": self.evidence_manifest_identity,
            "evidence_scope": self.evidence_scope,
            "custody_record_count": self.custody_record_count,
            "checks": list(self.checks),
            "errors": list(self.errors),
        }


def forensic_package_identity(core: object) -> str:
    data = canonical_json_bytes(core)
    digest = hashlib.sha256(FORENSIC_PACKAGE_DOMAIN + data).hexdigest()
    return f"sha256:{digest}"


def expected_schema_metadata() -> dict[str, object]:
    return {
        "schema": PACKAGE_SCHEMAS_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "contracts": {
            "artifact": ARTIFACT_SCHEMA,
            "bundle": BUNDLE_CONTRACT,
            "custody": CUSTODY_SCHEMA,
            "event": EVENT_SCHEMA,
            "forensic_package": FORENSIC_PACKAGE_SCHEMA,
            "manifest": MANIFEST_SCHEMA,
        },
        "content_identity": "sha256",
        "structured_identity": "sha256-with-domain-separation",
    }


def expected_verification_metadata(
    bundle_report,
    custody_report,
) -> dict[str, object]:
    return {
        "schema": PACKAGE_VERIFICATION_METADATA_SCHEMA,
        "bundle": bundle_report.to_dict(),
        "custody": custody_report.to_dict(),
    }


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required if not hasattr(os, name)]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if missing:
        raise RuntimeError(
            "forensic package verification requires descriptor-relative "
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


def _open_root(path: Path) -> int:
    try:
        fd = os.open(path, _directory_flags())
    except OSError as exc:
        raise ValueError(f"package root cannot be opened safely: {exc}") from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("package root must be a directory")
    return fd


def _safe_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative:
        raise ValueError("package member path must be a non-empty string")
    if "\\" in relative or "\x00" in relative:
        raise ValueError(f"package member path is not portable: {relative!r}")
    path = PurePosixPath(relative)
    if path.is_absolute():
        raise ValueError(f"package member path must be relative: {relative!r}")
    parts = path.parts
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(_SAFE_SEGMENT.fullmatch(part) is None for part in parts)
    ):
        raise ValueError(f"package member path is unsafe: {relative!r}")
    if PurePosixPath(*parts).as_posix() != relative:
        raise ValueError(f"package member path is noncanonical: {relative!r}")
    return tuple(parts)


def _member_path_allowed(relative: str) -> bool:
    if relative in {"schemas.json", "verification.json", "gaps.json"}:
        return True
    if relative.startswith("evidence/"):
        return len(PurePosixPath(relative).parts) >= 2
    if relative.startswith("custody/sha256/"):
        parts = PurePosixPath(relative).parts
        if len(parts) != 3:
            return False
        name = parts[-1]
        return (
            len(name) == 69
            and name.endswith(".json")
            and all(char in "0123456789abcdef" for char in name[:-5])
        )
    return False


def _open_directory_at(root_fd: int, parts: tuple[str, ...]) -> int:
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


def _open_file_at(root_fd: int, relative: str) -> int:
    parts = _safe_parts(relative)
    parent_fd = _open_directory_at(root_fd, parts[:-1])
    try:
        fd = os.open(parts[-1], _file_flags(), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f"package member is not a regular file: {relative}")
    return fd


def _read_all(fd: int, *, max_bytes: int | None = None) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise ValueError("structured package member exceeds size limit")
        chunks.append(chunk)


def _read_member(
    root_fd: int,
    relative: str,
    *,
    structured: bool = True,
) -> bytes:
    fd = _open_file_at(root_fd, relative)
    try:
        return _read_all(
            fd,
            max_bytes=_STRUCTURED_LIMIT if structured else None,
        )
    finally:
        os.close(fd)


def _canonical_object(root_fd: int, relative: str) -> dict[str, Any]:
    raw = _read_member(root_fd, relative)
    try:
        value = parse_canonical_json_bytes(raw)
    except (CanonicalizationError, RecursionError) as exc:
        raise ValueError(
            f"{relative} is not canonical PROVENANCE JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain a JSON object")
    return value


def _hash_member(root_fd: int, relative: str) -> tuple[str, int]:
    fd = _open_file_at(root_fd, relative)
    hasher = hashlib.sha256()
    count = 0
    try:
        while True:
            chunk = os.read(fd, _CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            count += len(chunk)
    finally:
        os.close(fd)
    return f"sha256:{hasher.hexdigest()}", count


def _physical_files(
    root_fd: int,
) -> tuple[set[str], set[str], set[str]]:
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
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                        except OSError:
                            unsafe.add(relative)
                            continue
                        if stat.S_ISDIR(mode):
                            directories.add(relative)
                            try:
                                child = os.open(
                                    entry.name,
                                    _directory_flags(),
                                    dir_fd=dir_fd,
                                )
                            except OSError:
                                unsafe.add(relative)
                                continue
                            stack.append((child, relative))
                        elif stat.S_ISREG(mode):
                            files.add(relative)
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


def _manifest_and_events_fd(
    evidence_fd: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _canonical_object(evidence_fd, "manifest.json")
    core = manifest.get("core")
    if not isinstance(core, dict):
        raise ValueError("evidence manifest core must be an object")

    events: list[dict[str, Any]] = []
    identities = core.get("events")
    if not isinstance(identities, list):
        raise ValueError("evidence manifest events must be a list")
    for identity in identities:
        require_sha256_identity(identity, label="package event identity")
        digest = str(identity).split(":", 1)[1]
        event = _canonical_object(
            evidence_fd,
            f"events/sha256/{digest}.json",
        )
        events.append(event)
    return manifest, events


def _derive_declared_gaps(
    manifest: dict[str, Any],
    events: list[dict[str, Any]],
    custody_records: list[bytes] | tuple[bytes, ...],
) -> dict[str, object]:
    core = manifest["core"]
    manifest_identity = manifest.get("manifest_identity")
    gaps: list[dict[str, object]] = []

    if core.get("scope") == "open":
        gaps.append(
            {
                "kind": "OPEN_COLLECTION",
                "identity": manifest_identity,
            }
        )

    artifacts = core.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("manifest artifacts must be a list")
    for entry in artifacts:
        if not isinstance(entry, dict):
            raise ValueError("manifest artifact entry must be an object")
        retention = entry.get("retention")
        identity = entry.get("content_identity")
        if retention == "MISSING":
            gaps.append(
                {"kind": "MISSING_ARTIFACT", "identity": identity}
            )
        elif retention == "DIGEST_ONLY":
            gaps.append(
                {"kind": "DIGEST_ONLY_ARTIFACT", "identity": identity}
            )

    for event in events:
        identity = event.get("event_identity")
        event_core = event.get("core")
        if not isinstance(event_core, dict):
            raise ValueError("event core must be an object")
        status = event_core.get("collection_status")
        if status != "RECORDED":
            gaps.append(
                {
                    "kind": "EVENT_COLLECTION_STATUS",
                    "identity": identity,
                    "status": status,
                }
            )

    evidence_subjects: set[str] = set()
    if isinstance(manifest_identity, str):
        evidence_subjects.add(manifest_identity)
    for entry in artifacts:
        identity = entry.get("content_identity")
        if isinstance(identity, str):
            evidence_subjects.add(identity)
    for event in events:
        identity = event.get("event_identity")
        if isinstance(identity, str):
            evidence_subjects.add(identity)

    custody_subjects: set[str] = set()
    for index, raw in enumerate(custody_records):
        try:
            value = parse_canonical_json_bytes(raw)
        except Exception as exc:
            raise ValueError(
                f"custody record[{index}] cannot be parsed for gap derivation: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise ValueError(
                f"custody record[{index}] must be an object for gap derivation"
            )
        custody_core = value.get("core")
        if not isinstance(custody_core, dict):
            raise ValueError(
                f"custody record[{index}] core must be an object for gap derivation"
            )
        subject = custody_core.get("subject_identity")
        if isinstance(subject, str):
            custody_subjects.add(subject)

    missing_custody = sorted(evidence_subjects - custody_subjects)
    if not custody_records and evidence_subjects:
        gaps.append(
            {
                "kind": "CUSTODY_NOT_PRESENT",
                "identities": sorted(evidence_subjects),
            }
        )
    elif missing_custody:
        gaps.append(
            {
                "kind": "PARTIAL_CUSTODY_COVERAGE",
                "identities": missing_custody,
            }
        )

    gaps.sort(key=canonical_json_bytes)
    return {"schema": PACKAGE_GAPS_SCHEMA, "gaps": gaps}


def derive_declared_gaps_fd(
    evidence_fd: int,
    custody_records: list[bytes] | tuple[bytes, ...] = (),
) -> dict[str, object]:
    manifest, events = _manifest_and_events_fd(evidence_fd)
    return _derive_declared_gaps(manifest, events, custody_records)


def derive_declared_gaps(
    evidence_root: Path,
    custody_records: list[bytes] | tuple[bytes, ...] = (),
) -> dict[str, object]:
    try:
        evidence_fd = os.open(evidence_root, _directory_flags())
    except OSError as exc:
        raise ValueError(
            f"evidence root cannot be opened safely for gap derivation: {exc}"
        ) from exc
    try:
        return derive_declared_gaps_fd(evidence_fd, custody_records)
    finally:
        os.close(evidence_fd)


def _custody_records(
    root_fd: int,
    member_paths: list[str],
) -> tuple[list[bytes], list[str]]:
    raws: list[bytes] = []
    errors: list[str] = []
    prefix = "custody/sha256/"
    for relative in sorted(
        path for path in member_paths if path.startswith(prefix)
    ):
        if not relative.endswith(".json"):
            errors.append(f"invalid custody member filename: {relative}")
            continue
        raw = _read_member(root_fd, relative)
        try:
            value = parse_canonical_json_bytes(raw)
        except Exception as exc:
            errors.append(f"{relative}: custody record is not canonical: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{relative}: custody record must be an object")
            continue
        claimed = value.get("custody_identity")
        try:
            require_sha256_identity(
                claimed,
                label=f"{relative} custody identity",
            )
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        expected = str(claimed).split(":", 1)[1] + ".json"
        if PurePosixPath(relative).name != expected:
            errors.append(
                f"{relative}: filename does not match custody identity"
            )
            continue
        raws.append(raw)
    return raws, errors


def _member_hash_task(
    args: tuple[int, dict[str, object]],
) -> tuple[str, str | None, int | None, str | None]:
    root_fd, item = args
    relative = str(item["path"])
    try:
        identity, byte_count = _hash_member(root_fd, relative)
    except Exception as exc:
        return relative, None, None, str(exc)
    return relative, identity, byte_count, None


def _verify_forensic_package_root_fd(
    root_fd: int,
    *,
    max_workers: int,
    reference_dependencies: bool,
) -> ForensicPackageVerificationReport:
    checks: list[str] = []
    errors: list[str] = []
    package_identity_value: str | None = None
    evidence_manifest_identity: str | None = None
    evidence_scope: str | None = None
    custody_record_count = 0

        try:
            envelope = _canonical_object(root_fd, "package.json")
            if set(envelope) != {
                "core",
                "package_identity",
                "self_hash_exclusion",
            }:
                raise ValueError("package.json envelope keys changed")
            core = envelope.get("core")
            if not isinstance(core, dict):
                raise ValueError("package core must be an object")
            if set(core) != {
                "schema",
                "canonicalization",
                "package_state",
                "evidence_manifest_identity",
                "evidence_scope",
                "custody_record_count",
                "members",
            }:
                raise ValueError("package core keys changed")
            if core.get("schema") != FORENSIC_PACKAGE_SCHEMA:
                raise ValueError("package schema changed")
            if core.get("canonicalization") != CANONICALIZATION_ID:
                raise ValueError("package canonicalization changed")
            if core.get("package_state") != "FINALIZED":
                raise ValueError("package_state must be FINALIZED")
            if core.get("evidence_scope") not in {"open", "closed"}:
                raise ValueError("package evidence_scope must be open or closed")
            evidence_scope = str(core.get("evidence_scope"))
            claimed_manifest = core.get("evidence_manifest_identity")
            require_sha256_identity(
                claimed_manifest,
                label="package evidence manifest identity",
            )
            evidence_manifest_identity = str(claimed_manifest)
            count = core.get("custody_record_count")
            if type(count) is not int or not 0 <= count <= MAX_SAFE_INTEGER:
                raise ValueError(
                    "package custody_record_count must be a safe non-negative integer"
                )
            custody_record_count = count
            members = core.get("members")
            if not isinstance(members, list):
                raise ValueError("package members must be a list")

            normalized_members: list[dict[str, object]] = []
            member_paths: list[str] = []
            for index, item in enumerate(members):
                if not isinstance(item, dict) or set(item) != {
                    "path",
                    "content_identity",
                    "byte_count",
                }:
                    raise ValueError(
                        f"package member[{index}] keys changed"
                    )
                relative = item.get("path")
                parts = _safe_parts(relative)
                assert isinstance(relative, str)
                if relative == "package.json":
                    raise ValueError(
                        "package.json must not be a self-declared member"
                    )
                if not _member_path_allowed(relative):
                    raise ValueError(
                        f"package member path is outside the v1 layout: {relative}"
                    )
                content_identity = item.get("content_identity")
                require_sha256_identity(
                    content_identity,
                    label=f"package member[{index}] identity",
                )
                byte_count = item.get("byte_count")
                if (
                    type(byte_count) is not int
                    or not 0 <= byte_count <= MAX_SAFE_INTEGER
                ):
                    raise ValueError(
                        f"package member[{index}] byte_count is invalid"
                    )
                member_paths.append(PurePosixPath(*parts).as_posix())
                normalized_members.append(item)
            if member_paths != sorted(member_paths):
                raise ValueError("package members must be sorted by path")
            if len(set(member_paths)) != len(member_paths):
                raise ValueError("package member paths must be unique")

            claimed_package = envelope.get("package_identity")
            require_sha256_identity(
                claimed_package,
                label="package identity",
            )
            if envelope.get("self_hash_exclusion") != "package_identity":
                raise ValueError("package self_hash_exclusion changed")
            expected_package = forensic_package_identity(core)
            if claimed_package != expected_package:
                raise ValueError(
                    "package identity does not match canonical package core"
                )
            package_identity_value = str(claimed_package)
            checks.append("package envelope and identity verified")
        except Exception as exc:
            errors.append(str(exc))
            return ForensicPackageVerificationReport(
                False,
                package_identity_value,
                evidence_manifest_identity,
                evidence_scope,
                custody_record_count,
                tuple(checks),
                tuple(errors),
            )

        try:
            physical, physical_directories, unsafe = _physical_files(root_fd)
        except Exception as exc:
            errors.append(f"cannot enumerate package: {exc}")
            return ForensicPackageVerificationReport(
                False,
                package_identity_value,
                evidence_manifest_identity,
                evidence_scope,
                custody_record_count,
                tuple(checks),
                tuple(errors),
            )

        expected_files = {"package.json", *member_paths}
        expected_directories: set[str] = {
            "evidence",
            "custody",
            "custody/sha256",
        }
        for relative in member_paths:
            parts = PurePosixPath(relative).parts[:-1]
            for index in range(1, len(parts) + 1):
                expected_directories.add(
                    PurePosixPath(*parts[:index]).as_posix()
                )
        if unsafe:
            errors.append(
                "non-regular filesystem entries are forbidden inside forensic packages: "
                + ", ".join(sorted(unsafe))
            )
        missing = sorted(expected_files - physical)
        extra = sorted(physical - expected_files)
        if missing:
            errors.append(
                "forensic package is missing declared files: "
                + ", ".join(missing)
            )
        if extra:
            errors.append(
                "forensic package contains undeclared files: "
                + ", ".join(extra)
            )
        extra_directories = sorted(
            physical_directories - expected_directories
        )
        missing_directories = sorted(
            expected_directories - physical_directories
        )
        if missing_directories:
            errors.append(
                "forensic package is missing declared directory structure: "
                + ", ".join(missing_directories)
            )
        if extra_directories:
            errors.append(
                "forensic package contains undeclared directories: "
                + ", ".join(extra_directories)
            )
        if (
            unsafe
            or missing
            or extra
            or missing_directories
            or extra_directories
        ):
            return ForensicPackageVerificationReport(
                False,
                package_identity_value,
                evidence_manifest_identity,
                evidence_scope,
                custody_record_count,
                tuple(checks),
                tuple(errors),
            )
        checks.append("physical package membership exactly matches package.json")

        member_ok = True
        member_results = ordered_bounded_map(
            _member_hash_task,
            [(root_fd, item) for item in normalized_members],
            max_workers=max_workers,
        )
        for (
            relative,
            identity,
            byte_count,
            member_error,
        ), item in zip(member_results, normalized_members):
            if member_error is not None:
                member_ok = False
                errors.append(
                    f"{relative}: cannot hash member: {member_error}"
                )
                continue
            if identity != item["content_identity"]:
                member_ok = False
                errors.append(f"{relative}: member content identity mismatch")
            if byte_count != item["byte_count"]:
                member_ok = False
                errors.append(f"{relative}: member byte_count mismatch")
        if member_ok:
            checks.append("all package member hashes and byte counts verified")

        evidence_fd = _open_directory_at(root_fd, ("evidence",))
        try:
            bundle_report = (
                verify_bundle_fd_reference(evidence_fd)
                if reference_dependencies
                else verify_bundle_fd(evidence_fd)
            )
        finally:
            os.close(evidence_fd)
        if not bundle_report.integrity_verified:
            errors.append(
                "embedded evidence bundle failed verification: "
                + "; ".join(bundle_report.errors)
            )
        elif (
            bundle_report.manifest_identity != evidence_manifest_identity
            or bundle_report.manifest_scope != evidence_scope
        ):
            errors.append(
                "embedded evidence bundle does not match package core"
            )
        else:
            checks.append("embedded evidence bundle independently verified")

        custody_raws, custody_errors = _custody_records(
            root_fd,
            member_paths,
        )
        errors.extend(custody_errors)
        custody_report = verify_custody_records(custody_raws)
        if len(custody_raws) != custody_record_count:
            errors.append(
                "package custody_record_count does not match custody members"
            )
        if not custody_report.integrity_verified:
            errors.append(
                "embedded custody chain failed verification: "
                + "; ".join(custody_report.errors)
            )
        elif not custody_errors:
            checks.append("embedded custody records independently verified")

        try:
            schemas = _canonical_object(root_fd, "schemas.json")
            if schemas != expected_schema_metadata():
                errors.append("schemas.json does not match package contract")
            else:
                checks.append("schema/version metadata verified")
        except Exception as exc:
            errors.append(f"schemas.json: {exc}")

        if bundle_report.integrity_verified:
            try:
                gaps = _canonical_object(root_fd, "gaps.json")
                evidence_fd = _open_directory_at(root_fd, ("evidence",))
                try:
                    expected_gaps = derive_declared_gaps_fd(
                        evidence_fd,
                        custody_raws,
                    )
                finally:
                    os.close(evidence_fd)
                if gaps != expected_gaps:
                    errors.append(
                        "gaps.json does not match recomputed evidence gaps"
                    )
                else:
                    checks.append("declared gaps recomputed and verified")
            except Exception as exc:
                errors.append(f"gaps.json: {exc}")

        try:
            verification = _canonical_object(root_fd, "verification.json")
            expected_verification = expected_verification_metadata(
                bundle_report,
                custody_report,
            )
            if verification != expected_verification:
                errors.append(
                    "verification.json does not match recomputed reports"
                )
            else:
                checks.append("verification metadata recomputed and verified")
        except Exception as exc:
            errors.append(f"verification.json: {exc}")

        return ForensicPackageVerificationReport(
            integrity_verified=member_ok and not errors,
            package_identity=package_identity_value,
            evidence_manifest_identity=evidence_manifest_identity,
            evidence_scope=evidence_scope,
            custody_record_count=custody_record_count,
            checks=tuple(checks),
            errors=tuple(errors),
        )


def _verify_forensic_package(
    package_dir: Path | str,
    *,
    max_workers: int,
    reference_dependencies: bool,
) -> ForensicPackageVerificationReport:
    package = Path(package_dir)
    try:
        root_fd = _open_root(package)
    except (OSError, ValueError, RuntimeError) as exc:
        return ForensicPackageVerificationReport(
            False, None, None, None, 0, (), (str(exc),)
        )
    try:
        return _verify_forensic_package_root_fd(
            root_fd,
            max_workers=max_workers,
            reference_dependencies=reference_dependencies,
        )
    finally:
        os.close(root_fd)


def verify_forensic_package_fd(
    package_fd: int,
) -> ForensicPackageVerificationReport:
    """Verify an already-open forensic-package directory descriptor."""

    try:
        root_fd = os.dup(package_fd)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            os.close(root_fd)
            raise ValueError("package descriptor must reference a directory")
    except (OSError, TypeError, ValueError) as exc:
        return ForensicPackageVerificationReport(
            False, None, None, None, 0, (), (str(exc),)
        )
    try:
        return _verify_forensic_package_root_fd(
            root_fd,
            max_workers=DEFAULT_MAX_VERIFY_WORKERS,
            reference_dependencies=False,
        )
    finally:
        os.close(root_fd)


def verify_forensic_package_reference(
    package_dir: Path | str,
) -> ForensicPackageVerificationReport:
    """Serial Phase 11 verifier retained as the Phase 13 reference path."""

    return _verify_forensic_package(
        package_dir,
        max_workers=1,
        reference_dependencies=True,
    )


def verify_forensic_package(
    package_dir: Path | str,
) -> ForensicPackageVerificationReport:
    """Verify a forensic package with bounded deterministic parallel work."""

    return _verify_forensic_package(
        package_dir,
        max_workers=DEFAULT_MAX_VERIFY_WORKERS,
        reference_dependencies=False,
    )
