"""Atomic producer for PROVENANCE Phase 11 portable forensic packages."""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import uuid

from provenance_core import (
    CANONICALIZATION_ID,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_verify import (
    FORENSIC_PACKAGE_SCHEMA,
    derive_declared_gaps_fd,
    expected_schema_metadata,
    expected_verification_metadata,
    forensic_package_identity,
    verify_bundle,
    verify_bundle_fd,
    verify_custody_records,
    verify_forensic_package,
    verify_forensic_package_fd,
)


_CHUNK_SIZE = 1024 * 1024
_CUSTODY_ATTEMPTS = 4
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


class ForensicPackageError(RuntimeError):
    """Raised when a Phase 11 package cannot be created safely."""


@dataclass(frozen=True, slots=True)
class ForensicPackage:
    path: Path
    package_identity: str
    evidence_manifest_identity: str
    evidence_scope: str
    custody_record_count: int


def _directory_flags() -> int:
    missing = [
        name
        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
        if not hasattr(os, name)
    ]
    for operation, name in (
        (os.open, "dir_fd support for os.open"),
        (os.unlink, "dir_fd support for os.unlink"),
    ):
        if operation not in os.supports_dir_fd:
            missing.append(name)
    if missing:
        raise ForensicPackageError(
            "forensic package creation requires descriptor-relative "
            "filesystem support: " + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _rename_noreplace_at(
    source_dir_fd: int,
    source_name: str,
    destination_dir_fd: int,
    destination_name: str,
) -> None:
    if _RENAMEAT2 is None:
        raise ForensicPackageError(
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
        raise ForensicPackageError(
            "package destination must not already exist"
        )
    raise ForensicPackageError(
        "no-replace package publication failed: "
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


def _directory_identity(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise ForensicPackageError("expected directory descriptor")
    return info.st_dev, info.st_ino


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise ForensicPackageError("short package write")
        offset += written


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_dir_chain(root_fd: int, parts: tuple[str, ...]) -> int:
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


def _mkdir_chain(root_fd: int, parts: tuple[str, ...]) -> int:
    fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _member(path: str, identity: str, byte_count: int) -> dict[str, object]:
    return {
        "path": path,
        "content_identity": identity,
        "byte_count": byte_count,
    }


def _write_member(
    root_fd: int,
    relative: str,
    data: bytes,
    members: list[dict[str, object]],
) -> None:
    parts = tuple(relative.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise ForensicPackageError(f"unsafe package member path: {relative}")
    parent_fd = _mkdir_chain(root_fd, parts[:-1])
    try:
        fd = os.open(
            parts[-1],
            _file_create_flags(),
            0o600,
            dir_fd=parent_fd,
        )
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    members.append(
        _member(
            relative,
            f"sha256:{hashlib.sha256(data).hexdigest()}",
            len(data),
        )
    )


def _copy_tree(
    source_fd: int,
    destination_fd: int,
    *,
    prefix: str,
    members: list[dict[str, object]],
) -> None:
    try:
        names = sorted(os.listdir(source_fd))
    except OSError as exc:
        raise ForensicPackageError(
            f"cannot enumerate source evidence: {exc}"
        ) from exc

    for name in names:
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise ForensicPackageError("unsafe evidence member name")
        try:
            info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as exc:
            raise ForensicPackageError(
                f"cannot inspect source evidence member {name!r}: {exc}"
            ) from exc

        relative = f"{prefix}/{name}"
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(name, mode=0o700, dir_fd=destination_fd)
            source_child = os.open(
                name,
                _directory_flags(),
                dir_fd=source_fd,
            )
            destination_child = os.open(
                name,
                _directory_flags(),
                dir_fd=destination_fd,
            )
            try:
                _copy_tree(
                    source_child,
                    destination_child,
                    prefix=relative,
                    members=members,
                )
                os.fsync(destination_child)
            finally:
                os.close(source_child)
                os.close(destination_child)
            continue

        if not stat.S_ISREG(info.st_mode):
            raise ForensicPackageError(
                f"source evidence contains unsupported object {relative!r}"
            )

        source_file = os.open(
            name,
            _file_read_flags(),
            dir_fd=source_fd,
        )
        destination_file = os.open(
            name,
            _file_create_flags(),
            0o600,
            dir_fd=destination_fd,
        )
        hasher = hashlib.sha256()
        byte_count = 0
        try:
            if not stat.S_ISREG(os.fstat(source_file).st_mode):
                raise ForensicPackageError(
                    f"source evidence member is not regular: {relative}"
                )
            while True:
                chunk = os.read(source_file, _CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                byte_count += len(chunk)
                _write_all(destination_file, chunk)
            os.fsync(destination_file)
        finally:
            os.close(source_file)
            os.close(destination_file)

        members.append(
            _member(
                relative,
                f"sha256:{hasher.hexdigest()}",
                byte_count,
            )
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
        return
    os.unlink(name, dir_fd=parent_fd)


def _fd_is_within(
    directory_fd: int,
    protected: set[tuple[int, int]],
) -> bool:
    current_fd = os.dup(directory_fd)
    try:
        while True:
            identity = _directory_identity(current_fd)
            if identity in protected:
                return True
            parent_fd = os.open(
                "..",
                _directory_flags(),
                dir_fd=current_fd,
            )
            parent_identity = _directory_identity(parent_fd)
            if parent_identity == identity:
                os.close(parent_fd)
                return False
            os.close(current_fd)
            current_fd = parent_fd
    finally:
        os.close(current_fd)


def _path_matches(
    path: Path,
    expected_identity: tuple[int, int],
) -> bool:
    try:
        fd = os.open(path, _directory_flags())
    except OSError:
        return False
    try:
        return _directory_identity(fd) == expected_identity
    finally:
        os.close(fd)


def _read_head(store_root: Path) -> str:
    root_fd = os.open(store_root, _directory_flags())
    try:
        try:
            fd = os.open("HEAD", _file_read_flags(), dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise ForensicPackageError(
                "store has no finalized snapshot to package"
            ) from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ForensicPackageError("store HEAD must be a regular file")
            raw = _read_all(fd)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)

    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ForensicPackageError("store HEAD must be ASCII") from exc
    if not value.endswith("\n") or value.count("\n") != 1:
        raise ForensicPackageError(
            "store HEAD must contain exactly one identity and LF"
        )
    identity = value[:-1]
    try:
        require_sha256_identity(
            identity,
            label="store HEAD manifest identity",
        )
    except (TypeError, ValueError) as exc:
        raise ForensicPackageError(str(exc)) from exc
    return identity


def _custody_names(records_fd: int) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(records_fd) as entries:
            for entry in entries:
                if not entry.name.endswith(".json"):
                    raise ForensicPackageError(
                        f"unexpected custody record filename: {entry.name}"
                    )
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError as exc:
                    raise ForensicPackageError(
                        f"cannot inspect custody record {entry.name}: {exc}"
                    ) from exc
                if not stat.S_ISREG(mode):
                    raise ForensicPackageError(
                        f"custody record is not a regular file: {entry.name}"
                    )
                names.append(entry.name)
    except OSError as exc:
        raise ForensicPackageError(
            f"cannot enumerate custody records: {exc}"
        ) from exc
    return sorted(names)


def _stable_custody_snapshot(
    custody_root: Path,
) -> tuple[list[tuple[str, bytes]], object]:
    root_fd = os.open(custody_root, _directory_flags())
    try:
        records_fd = _open_dir_chain(root_fd, ("records", "sha256"))
        try:
            for _attempt in range(_CUSTODY_ATTEMPTS):
                before = _custody_names(records_fd)
                records: list[tuple[str, bytes]] = []
                raws: list[bytes] = []

                for name in before:
                    fd = os.open(
                        name,
                        _file_read_flags(),
                        dir_fd=records_fd,
                    )
                    try:
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            raise ForensicPackageError(
                                f"custody record is not regular: {name}"
                            )
                        raw = _read_all(fd)
                    finally:
                        os.close(fd)

                    try:
                        value = parse_canonical_json_bytes(raw)
                    except Exception as exc:
                        raise ForensicPackageError(
                            f"custody record {name} is not canonical: {exc}"
                        ) from exc
                    if not isinstance(value, dict):
                        raise ForensicPackageError(
                            f"custody record {name} must be an object"
                        )
                    claimed = value.get("custody_identity")
                    try:
                        require_sha256_identity(
                            claimed,
                            label=f"custody record {name} identity",
                        )
                    except (TypeError, ValueError) as exc:
                        raise ForensicPackageError(str(exc)) from exc
                    expected = str(claimed).split(":", 1)[1] + ".json"
                    if name != expected:
                        raise ForensicPackageError(
                            f"custody record filename {name} "
                            "does not match identity"
                        )
                    records.append((name, raw))
                    raws.append(raw)

                report = verify_custody_records(raws)
                if not report.integrity_verified:
                    raise ForensicPackageError(
                        "source custody ledger failed verification: "
                        + "; ".join(report.errors)
                    )

                after = _custody_names(records_fd)
                if before == after:
                    return records, report

            raise ForensicPackageError(
                "custody ledger changed repeatedly during package snapshot"
            )
        finally:
            os.close(records_fd)
    finally:
        os.close(root_fd)


def create_forensic_package(
    store_root: Path | str,
    custody_root: Path | str,
    destination: Path | str,
) -> ForensicPackage:
    store = Path(store_root).expanduser()
    custody = Path(custody_root).expanduser()
    supplied = Path(destination).expanduser()

    for path, label in ((store, "store root"), (custody, "custody root")):
        if path.is_symlink():
            raise ForensicPackageError(f"{label} must not be a symlink")
        try:
            info = path.stat()
        except OSError as exc:
            raise ForensicPackageError(
                f"{label} cannot be inspected: {exc}"
            ) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ForensicPackageError(f"{label} must be a directory")

    manifest_identity = _read_head(store)
    manifest_digest = manifest_identity.split(":", 1)[1]
    snapshot = store / "snapshots" / "sha256" / manifest_digest
    source_report = verify_bundle(snapshot)
    if (
        not source_report.integrity_verified
        or source_report.manifest_identity != manifest_identity
        or source_report.manifest_scope not in {"open", "closed"}
    ):
        raise ForensicPackageError(
            "current finalized snapshot failed verification before packaging"
        )

    custody_records, source_custody_report = _stable_custody_snapshot(custody)

    if supplied.name in {"", ".", ".."}:
        raise ForensicPackageError("package destination name is invalid")
    if supplied.exists() or supplied.is_symlink():
        raise ForensicPackageError(
            "package destination must not already exist"
        )
    if supplied.parent.is_symlink():
        raise ForensicPackageError(
            "package destination parent must not be a symlink"
        )
    try:
        parent = supplied.parent.resolve(strict=True)
    except OSError as exc:
        raise ForensicPackageError(
            f"package destination parent cannot be resolved: {exc}"
        ) from exc

    protected_paths = (
        store.resolve(strict=True),
        custody.resolve(strict=True),
        snapshot.resolve(strict=True),
    )
    protected_fds: list[int] = []
    protected_identities: set[tuple[int, int]] = set()
    parent_fd: int | None = None
    staging_name = f".{supplied.name}.{uuid.uuid4().hex}.tmp"
    created_name: str | None = None

    try:
        for path in protected_paths:
            fd = os.open(path, _directory_flags())
            protected_fds.append(fd)
            protected_identities.add(_directory_identity(fd))

        parent_fd = os.open(parent, _directory_flags())
        parent_identity = _directory_identity(parent_fd)
        if _fd_is_within(parent_fd, protected_identities):
            raise ForensicPackageError(
                "package destination must be outside the live store, "
                "custody ledger, and source snapshot"
            )

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
            os.mkdir("evidence", mode=0o700, dir_fd=staging_fd)
            evidence_fd = os.open(
                "evidence",
                _directory_flags(),
                dir_fd=staging_fd,
            )
            source_fd = os.open(snapshot, _directory_flags())
            try:
                _copy_tree(
                    source_fd,
                    evidence_fd,
                    prefix="evidence",
                    members=members,
                )
                os.fsync(evidence_fd)
            finally:
                os.close(source_fd)
                os.close(evidence_fd)

            custody_fd = _mkdir_chain(
                staging_fd,
                ("custody", "sha256"),
            )
            try:
                for name, raw in custody_records:
                    fd = os.open(
                        name,
                        _file_create_flags(),
                        0o600,
                        dir_fd=custody_fd,
                    )
                    try:
                        _write_all(fd, raw)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    members.append(
                        _member(
                            f"custody/sha256/{name}",
                            f"sha256:{hashlib.sha256(raw).hexdigest()}",
                            len(raw),
                        )
                    )
                os.fsync(custody_fd)
            finally:
                os.close(custody_fd)

            if not _path_matches(parent, parent_identity):
                raise ForensicPackageError(
                    "package destination parent changed during staging"
                )
            staging_path = parent / staging_name
            evidence_check_fd = os.open(
                "evidence",
                _directory_flags(),
                dir_fd=staging_fd,
            )
            try:
                exported_bundle_report = verify_bundle_fd(
                    evidence_check_fd
                )
                declared_gaps = derive_declared_gaps_fd(
                    evidence_check_fd,
                    [raw for _name, raw in custody_records],
                )
            finally:
                os.close(evidence_check_fd)
            if (
                not exported_bundle_report.integrity_verified
                or exported_bundle_report.manifest_identity
                != manifest_identity
                or exported_bundle_report.manifest_scope
                != source_report.manifest_scope
            ):
                raise ForensicPackageError(
                    "copied evidence failed independent verification"
                )

            copied_custody_report = verify_custody_records(
                [raw for _name, raw in custody_records]
            )
            if (
                not copied_custody_report.integrity_verified
                or copied_custody_report.to_dict()
                != source_custody_report.to_dict()
            ):
                raise ForensicPackageError(
                    "copied custody records failed independent verification"
                )

            _write_member(
                staging_fd,
                "schemas.json",
                canonical_json_bytes(expected_schema_metadata()),
                members,
            )
            _write_member(
                staging_fd,
                "gaps.json",
                canonical_json_bytes(declared_gaps),
                members,
            )
            _write_member(
                staging_fd,
                "verification.json",
                canonical_json_bytes(
                    expected_verification_metadata(
                        exported_bundle_report,
                        copied_custody_report,
                    )
                ),
                members,
            )

            members.sort(key=lambda item: str(item["path"]))
            core = {
                "schema": FORENSIC_PACKAGE_SCHEMA,
                "canonicalization": CANONICALIZATION_ID,
                "package_state": "FINALIZED",
                "evidence_manifest_identity": manifest_identity,
                "evidence_scope": source_report.manifest_scope,
                "custody_record_count": len(custody_records),
                "members": members,
            }
            package_identity = forensic_package_identity(core)
            envelope = {
                "core": core,
                "package_identity": package_identity,
                "self_hash_exclusion": "package_identity",
            }
            package_bytes = canonical_json_bytes(envelope)
            fd = os.open(
                "package.json",
                _file_create_flags(),
                0o600,
                dir_fd=staging_fd,
            )
            try:
                _write_all(fd, package_bytes)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)

        if (
            not _path_matches(parent, parent_identity)
            or _fd_is_within(parent_fd, protected_identities)
        ):
            raise ForensicPackageError(
                "package destination parent changed before verification"
            )

        staged_fd = os.open(
            staging_name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
        try:
            if _directory_identity(staged_fd) != staging_identity:
                raise ForensicPackageError(
                    "staged package filesystem identity changed"
                )
            staged_report = verify_forensic_package_fd(staged_fd)
        finally:
            os.close(staged_fd)
        if (
            not staged_report.integrity_verified
            or staged_report.package_identity != package_identity
            or staged_report.evidence_manifest_identity != manifest_identity
        ):
            raise ForensicPackageError(
                "staged forensic package failed independent verification: "
                + "; ".join(staged_report.errors)
            )

        if (
            not _path_matches(parent, parent_identity)
            or _fd_is_within(parent_fd, protected_identities)
        ):
            raise ForensicPackageError(
                "package destination parent changed before publication"
            )

        _rename_noreplace_at(
            parent_fd,
            staging_name,
            parent_fd,
            supplied.name,
        )
        # Do not recursively delete the final name on any later failure: an
        # attacker could replace that directory after publication.
        created_name = None
        os.fsync(parent_fd)

        if not _path_matches(parent, parent_identity):
            raise ForensicPackageError(
                "package destination parent changed during publication"
            )

        final_path = parent / supplied.name
        final_fd = os.open(
            supplied.name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
        try:
            if _directory_identity(final_fd) != staging_identity:
                raise ForensicPackageError(
                    "published package filesystem identity changed"
                )
            final_report = verify_forensic_package_fd(final_fd)
        finally:
            os.close(final_fd)
        if (
            not final_report.integrity_verified
            or final_report.package_identity != package_identity
            or final_report.evidence_manifest_identity != manifest_identity
        ):
            raise ForensicPackageError(
                "published forensic package failed independent verification: "
                + "; ".join(final_report.errors)
            )

        created_name = None
        return ForensicPackage(
            path=final_path,
            package_identity=package_identity,
            evidence_manifest_identity=manifest_identity,
            evidence_scope=str(source_report.manifest_scope),
            custody_record_count=len(custody_records),
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
        for fd in protected_fds:
            os.close(fd)
