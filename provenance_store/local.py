"""Local filesystem evidence store for PROVENANCE Phase 3."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import shutil
import stat
import uuid
from typing import Iterator

from provenance_core import (
    ArtifactRecord,
    CanonicalizationError,
    EventEnvelope,
    ManifestArtifact,
    ManifestCore,
    ManifestEnvelope,
    RetentionState,
    artifact_record_identity,
    canonical_json_bytes,
    manifest_identity,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_verify import VerificationReport, verify_bundle

STORE_FORMAT = "provenance.local-store.v1"
_OBJECT_ARTIFACTS = ("objects", "artifacts", "sha256")
_OBJECT_RECORDS = ("objects", "artifact_records", "sha256")
_OBJECT_EVENTS = ("objects", "events", "sha256")
_SNAPSHOTS = ("snapshots", "sha256")
_HEAD = "HEAD"
_LOCK = ".store.lock"
_FORMAT = "STORE_FORMAT"
_CHUNK_SIZE = 1024 * 1024
_DIR_FD_SUPPORT = {
    "open": os.open in os.supports_dir_fd,
    "mkdir": os.mkdir in os.supports_dir_fd,
    "unlink": os.unlink in os.supports_dir_fd,
    "link": os.link in os.supports_dir_fd,
    "rename": os.rename in os.supports_dir_fd,
}


class StoreError(RuntimeError):
    """Raised when the local evidence store cannot preserve its contract."""


@dataclass(frozen=True, slots=True)
class StoredSnapshot:
    manifest_identity: str
    path: Path
    verification: VerificationReport


def _digest(identity: str, *, label: str) -> str:
    try:
        require_sha256_identity(identity, label=label)
    except (TypeError, ValueError) as exc:
        raise StoreError(str(exc)) from exc
    return identity.split(":", 1)[1]


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required if not hasattr(os, name)]
    for name, description in (
        ("open", "dir_fd support for os.open"),
        ("mkdir", "dir_fd support for os.mkdir"),
        ("unlink", "dir_fd support for os.unlink"),
        ("link", "dir_fd support for os.link"),
        ("rename", "dir_fd support for os.rename"),
    ):
        if not _DIR_FD_SUPPORT[name]:
            missing.append(description)
    if missing:
        raise StoreError(
            "local store requires descriptor-relative filesystem support: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_read_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)


def _file_create_flags() -> int:
    return os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short write while publishing evidence")
        offset += written


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _fsync_directory(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        raise StoreError(f"directory fsync failed: {exc}") from exc


class LocalEvidenceStore:
    """Local content-addressed store with verifier-gated immutable snapshots."""

    def __init__(self, root: Path | str):
        supplied_root = Path(root).expanduser()
        if supplied_root.is_symlink():
            raise StoreError("store root must not be a symbolic link")
        self.root = supplied_root.resolve(strict=False)
        self._root_identity: tuple[int, int] | None = None
        self._artifacts: dict[str, ManifestArtifact] = {}
        self._events: set[str] = set()
        self._current_manifest_identity: str | None = None
        self._session_changed_artifacts: set[str] = set()
        self._initialize()
        self._load_head()

    @property
    def current_manifest_identity(self) -> str | None:
        return self._current_manifest_identity

    @property
    def artifact_count(self) -> int:
        return len(self._artifacts)

    @property
    def event_count(self) -> int:
        return len(self._events)

    def _initialize(self) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreError(f"store root cannot be created: {exc}") from exc
        try:
            root_stat = self.root.lstat()
        except OSError as exc:
            raise StoreError(f"store root cannot be inspected: {exc}") from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise StoreError("store root must be a directory")
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)

        with self._root_fd() as root_fd:
            self._ensure_store_format(root_fd)
            for parts in (
                _OBJECT_ARTIFACTS,
                _OBJECT_RECORDS,
                _OBJECT_EVENTS,
                _SNAPSHOTS,
            ):
                fd = self._open_dir_chain(root_fd, parts, create=True)
                os.close(fd)
            self._ensure_lock_file(root_fd)

    @contextmanager
    def _root_fd(self) -> Iterator[int]:
        try:
            fd = os.open(self.root, _directory_flags())
        except OSError as exc:
            raise StoreError(f"store root cannot be opened safely: {exc}") from exc
        try:
            opened = os.fstat(fd)
            if not stat.S_ISDIR(opened.st_mode):
                raise StoreError("store root must be a directory")
            if (
                self._root_identity is not None
                and (opened.st_dev, opened.st_ino) != self._root_identity
            ):
                raise StoreError(
                    "store root filesystem identity changed since construction"
                )
            yield fd
        finally:
            os.close(fd)

    def _open_dir_chain(
        self,
        root_fd: int,
        parts: tuple[str, ...],
        *,
        create: bool,
    ) -> int:
        current_fd = os.dup(root_fd)
        try:
            for part in parts:
                if not part or part in {".", ".."} or "/" in part:
                    raise StoreError(f"unsafe managed directory component: {part!r}")
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current_fd)
                        _fsync_directory(current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise StoreError(
                            f"managed directory {part!r} cannot be created: {exc}"
                        ) from exc
                try:
                    next_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
                except OSError as exc:
                    raise StoreError(
                        f"managed directory {part!r} is missing or unsafe: {exc}"
                    ) from exc
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    def _ensure_store_format(self, root_fd: int) -> None:
        expected = (STORE_FORMAT + "\n").encode("ascii")
        try:
            fd = os.open(
                _FORMAT,
                _file_read_flags(),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            if os.scandir not in os.supports_fd:
                raise StoreError(
                    "store format initialization requires scandir(fd) support"
                )
            with os.scandir(root_fd) as entries:
                existing = [entry.name for entry in entries]
            if existing:
                raise StoreError(
                    "existing store root has no STORE_FORMAT marker; "
                    "refusing to assume a layout version"
                )
            try:
                fd = os.open(
                    _FORMAT,
                    _file_create_flags(),
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise StoreError(
                    f"STORE_FORMAT marker cannot be created: {exc}"
                ) from exc
            try:
                _write_all(fd, expected)
                os.fsync(fd)
            except OSError as exc:
                raise StoreError(
                    f"STORE_FORMAT marker cannot be written durably: {exc}"
                ) from exc
            finally:
                os.close(fd)
            _fsync_directory(root_fd)
            return
        except OSError as exc:
            raise StoreError(
                f"STORE_FORMAT marker cannot be opened safely: {exc}"
            ) from exc

        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoreError("STORE_FORMAT marker must be a regular file")
            raw = _read_all(fd)
        finally:
            os.close(fd)
        if raw != expected:
            raise StoreError(
                "unsupported or corrupt STORE_FORMAT marker: "
                + raw.decode("ascii", errors="replace").rstrip("\n")
            )

    def _ensure_lock_file(self, root_fd: int) -> None:
        try:
            fd = os.open(
                _LOCK,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise StoreError(f"store lock file cannot be created safely: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoreError("store lock must be a regular file")
        finally:
            os.close(fd)

    @contextmanager
    def _exclusive_finalize_lock(self) -> Iterator[None]:
        with self._root_fd() as root_fd:
            try:
                fd = os.open(
                    _LOCK,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise StoreError(f"store lock cannot be opened: {exc}") from exc
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise StoreError("store lock must be a regular file")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError as exc:
                    raise StoreError(f"store lock cannot be acquired: {exc}") from exc
                yield
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _existing_bytes_match(self, parent_fd: int, name: str, data: bytes) -> bool:
        try:
            fd = os.open(name, _file_read_flags(), dir_fd=parent_fd)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StoreError(
                f"existing object {name} cannot be opened safely: {exc}"
            ) from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoreError(f"existing object {name} is not a regular file")
            offset = 0
            while True:
                chunk = os.read(fd, _CHUNK_SIZE)
                if not chunk:
                    return offset == len(data)
                end = offset + len(chunk)
                if end > len(data) or data[offset:end] != chunk:
                    return False
                offset = end
        finally:
            os.close(fd)

    def _publish_bytes(
        self,
        category: tuple[str, ...],
        name: str,
        data: bytes,
    ) -> bool:
        """Publish exact immutable bytes atomically, never overwriting an object."""

        with self._root_fd() as root_fd:
            parent_fd = self._open_dir_chain(root_fd, category, create=True)
            try:
                if self._existing_bytes_match(parent_fd, name, data):
                    _fsync_directory(parent_fd)
                    return False
                try:
                    probe_fd = os.open(name, _file_read_flags(), dir_fd=parent_fd)
                except FileNotFoundError:
                    probe_fd = None
                except OSError as exc:
                    raise StoreError(
                        f"existing object {name} cannot be inspected safely: {exc}"
                    ) from exc
                if probe_fd is not None:
                    os.close(probe_fd)
                    raise StoreError(
                        f"existing object {name} conflicts with expected immutable bytes"
                    )

                temp_name = f".{name}.{uuid.uuid4().hex}.tmp"
                temp_fd: int | None = None
                try:
                    try:
                        temp_fd = os.open(
                            temp_name,
                            _file_create_flags(),
                            0o600,
                            dir_fd=parent_fd,
                        )
                    except OSError as exc:
                        raise StoreError(
                            f"temporary object {temp_name} cannot be created: {exc}"
                        ) from exc

                    try:
                        _write_all(temp_fd, data)
                        os.fsync(temp_fd)
                    except OSError as exc:
                        raise StoreError(f"temporary object write failed: {exc}") from exc
                    finally:
                        os.close(temp_fd)
                        temp_fd = None

                    try:
                        os.link(
                            temp_name,
                            name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        if not self._existing_bytes_match(parent_fd, name, data):
                            raise StoreError(
                                f"concurrent object {name} conflicts with expected bytes"
                            )
                        _fsync_directory(parent_fd)
                        return False
                    except OSError as exc:
                        raise StoreError(f"object publication failed: {exc}") from exc

                    _fsync_directory(parent_fd)
                    return True
                finally:
                    if temp_fd is not None:
                        os.close(temp_fd)
                    try:
                        os.unlink(temp_name, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        pass
            finally:
                os.close(parent_fd)

    def _read_artifact_record_object(
        self,
        record_identity: str,
    ) -> dict[str, object]:
        digest = _digest(record_identity, label="artifact record identity")
        with self._root_fd() as root_fd:
            parent_fd = self._open_dir_chain(
                root_fd,
                _OBJECT_RECORDS,
                create=False,
            )
            try:
                try:
                    fd = os.open(
                        digest + ".json",
                        _file_read_flags(),
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    raise StoreError(
                        f"prior artifact record {record_identity} cannot be opened: {exc}"
                    ) from exc
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise StoreError(
                            f"prior artifact record {record_identity} is not a regular file"
                        )
                    raw = _read_all(fd)
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)

        try:
            value = parse_canonical_json_bytes(raw)
        except (CanonicalizationError, RecursionError) as exc:
            raise StoreError(
                f"prior artifact record {record_identity} is not canonical: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise StoreError(
                f"prior artifact record {record_identity} must be an object"
            )
        if artifact_record_identity(value) != record_identity:
            raise StoreError(
                f"prior artifact record {record_identity} does not match its identity"
            )
        return value

    def put_artifact(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        retain_content: bool = True,
    ) -> ArtifactRecord:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        retention = (
            RetentionState.CONTENT_RETAINED
            if retain_content
            else RetentionState.DIGEST_ONLY
        )
        record = ArtifactRecord.from_bytes(
            data,
            media_type=media_type,
            retention=retention,
        )
        entry = ManifestArtifact.from_record(record)
        self._check_artifact_rebinding(entry, new_record=record)

        content_digest = _digest(
            record.content_identity,
            label="artifact content identity",
        )
        if retain_content:
            self._publish_bytes(_OBJECT_ARTIFACTS, content_digest, data)

        record_digest = _digest(
            record.record_identity,
            label="artifact record identity",
        )
        self._publish_bytes(
            _OBJECT_RECORDS,
            record_digest + ".json",
            canonical_json_bytes(record.to_dict()),
        )
        self._artifacts[record.content_identity] = entry
        self._session_changed_artifacts.add(record.content_identity)
        return record

    def _check_artifact_rebinding(
        self,
        entry: ManifestArtifact,
        *,
        new_record: ArtifactRecord | None = None,
    ) -> None:
        prior = self._artifacts.get(entry.content_identity)
        if prior is None or prior == entry:
            return

        if (
            self._current_manifest_identity is None
            or entry.content_identity in self._session_changed_artifacts
        ):
            raise StoreError(
                "current working snapshot already binds a different state "
                "to this content identity"
            )

        if prior.retention is RetentionState.CONTENT_RETAINED:
            raise StoreError(
                "artifact availability cannot be downgraded from CONTENT_RETAINED"
            )

        if entry.retention is RetentionState.MISSING:
            raise StoreError(
                "artifact availability cannot be downgraded to MISSING"
            )

        if prior.retention is RetentionState.MISSING:
            if entry.retention in {
                RetentionState.DIGEST_ONLY,
                RetentionState.CONTENT_RETAINED,
            }:
                return

        if (
            prior.retention is RetentionState.DIGEST_ONLY
            and entry.retention is RetentionState.CONTENT_RETAINED
        ):
            if prior.record_identity is None or new_record is None:
                raise StoreError(
                    "DIGEST_ONLY upgrade requires the prior and new artifact records"
                )
            prior_record = self._read_artifact_record_object(
                prior.record_identity
            )
            new_record_dict = new_record.to_dict()
            for field in (
                "schema",
                "canonicalization",
                "content_identity",
                "byte_count",
                "media_type",
            ):
                if prior_record.get(field) != new_record_dict.get(field):
                    raise StoreError(
                        "artifact retention upgrade changes stable metadata "
                        f"field {field}"
                    )
            return

        raise StoreError(
            "artifact state change is not a monotonic availability upgrade"
        )

    def mark_missing(self, content_identity: str) -> ManifestArtifact:
        entry = ManifestArtifact.missing(content_identity)
        self._check_artifact_rebinding(entry)
        self._artifacts[content_identity] = entry
        self._session_changed_artifacts.add(content_identity)
        return entry

    def put_event(self, event: EventEnvelope) -> str:
        if not isinstance(event, EventEnvelope):
            raise TypeError("event must be an EventEnvelope")
        event_digest = _digest(event.event_identity, label="event identity")
        self._publish_bytes(
            _OBJECT_EVENTS,
            event_digest + ".json",
            canonical_json_bytes(event.to_dict()),
        )
        self._events.add(event.event_identity)
        return event.event_identity

    def _copy_object_into_snapshot(
        self,
        root_fd: int,
        temp_snapshot_fd: int,
        *,
        source_category: tuple[str, ...],
        source_name: str,
        destination_category: tuple[str, ...],
        destination_name: str,
    ) -> None:
        source_parent_fd = self._open_dir_chain(
            root_fd,
            source_category,
            create=False,
        )
        try:
            destination_parent_fd = self._open_dir_chain(
                temp_snapshot_fd,
                destination_category,
                create=True,
            )
        except Exception:
            os.close(source_parent_fd)
            raise
        try:
            try:
                source_fd = os.open(
                    source_name,
                    _file_read_flags(),
                    dir_fd=source_parent_fd,
                )
            except FileNotFoundError as exc:
                raise StoreError(
                    "required object is missing: "
                    + "/".join((*source_category, source_name))
                ) from exc
            except OSError as exc:
                raise StoreError(
                    "required object is missing or unsafe: "
                    + "/".join((*source_category, source_name))
                    + f": {exc}"
                ) from exc

            try:
                if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                    raise StoreError(
                        "required object is not a regular file: "
                        + "/".join((*source_category, source_name))
                    )

                try:
                    destination_fd = os.open(
                        destination_name,
                        _file_create_flags(),
                        0o600,
                        dir_fd=destination_parent_fd,
                    )
                except OSError as exc:
                    raise StoreError(
                        f"snapshot object {destination_name} cannot be created: {exc}"
                    ) from exc

                try:
                    while True:
                        chunk = os.read(source_fd, _CHUNK_SIZE)
                        if not chunk:
                            break
                        _write_all(destination_fd, chunk)
                    os.fsync(destination_fd)
                except OSError as exc:
                    raise StoreError(
                        f"snapshot object {destination_name} copy failed: {exc}"
                    ) from exc
                finally:
                    os.close(destination_fd)
            finally:
                os.close(source_fd)

            _fsync_directory(destination_parent_fd)
        finally:
            os.close(source_parent_fd)
            os.close(destination_parent_fd)

    def _write_snapshot_manifest(
        self,
        temp_snapshot_fd: int,
        manifest: ManifestEnvelope,
    ) -> None:
        try:
            fd = os.open(
                "manifest.json",
                _file_create_flags(),
                0o600,
                dir_fd=temp_snapshot_fd,
            )
        except OSError as exc:
            raise StoreError(f"snapshot manifest cannot be created: {exc}") from exc
        try:
            try:
                _write_all(fd, canonical_json_bytes(manifest.to_dict()))
                os.fsync(fd)
            except OSError as exc:
                raise StoreError(f"snapshot manifest write failed: {exc}") from exc
        finally:
            os.close(fd)
        _fsync_directory(temp_snapshot_fd)

    def _existing_snapshot_is_safe(
        self,
        snapshots_parent_fd: int,
        digest: str,
    ) -> bool:
        try:
            fd = os.open(
                digest,
                _directory_flags(),
                dir_fd=snapshots_parent_fd,
            )
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StoreError(
                f"existing snapshot {digest} is missing or unsafe: {exc}"
            ) from exc
        else:
            os.close(fd)
            return True

    def _verify_snapshot_identity(
        self,
        snapshot: Path,
        expected_identity: str,
        *,
        label: str,
    ) -> VerificationReport:
        report = verify_bundle(snapshot)
        if not report.integrity_verified:
            raise StoreError(
                f"{label} failed independent verification: "
                + "; ".join(report.errors)
            )
        if report.manifest_identity != expected_identity:
            raise StoreError(
                f"{label} manifest identity does not match expected identity "
                f"{expected_identity}"
            )
        return report

    def _build_snapshot(self, manifest: ManifestEnvelope) -> Path:
        digest = _digest(manifest.manifest_identity, label="manifest identity")
        final_snapshot = self.root.joinpath(*_SNAPSHOTS, digest)
        temp_name = f".{digest}.{uuid.uuid4().hex}.tmp"
        temp_snapshot = self.root.joinpath(*_SNAPSHOTS, temp_name)
        created_final = False

        try:
            with self._root_fd() as root_fd:
                snapshots_parent_fd = self._open_dir_chain(
                    root_fd,
                    _SNAPSHOTS,
                    create=True,
                )
                try:
                    if self._existing_snapshot_is_safe(
                        snapshots_parent_fd,
                        digest,
                    ):
                        self._verify_snapshot_identity(
                            final_snapshot,
                            manifest.manifest_identity,
                            label="existing snapshot",
                        )
                        # A previous finalize may have failed immediately after
                        # renaming this snapshot. Re-establish parent durability
                        # before allowing HEAD to advance on this retry.
                        _fsync_directory(snapshots_parent_fd)
                        return final_snapshot

                    try:
                        os.mkdir(
                            temp_name,
                            mode=0o700,
                            dir_fd=snapshots_parent_fd,
                        )
                        _fsync_directory(snapshots_parent_fd)
                    except OSError as exc:
                        raise StoreError(
                            f"temporary snapshot cannot be created: {exc}"
                        ) from exc

                    try:
                        temp_snapshot_fd = os.open(
                            temp_name,
                            _directory_flags(),
                            dir_fd=snapshots_parent_fd,
                        )
                    except OSError as exc:
                        raise StoreError(
                            f"temporary snapshot cannot be opened safely: {exc}"
                        ) from exc

                    try:
                        for entry in self._artifacts.values():
                            if entry.retention is RetentionState.MISSING:
                                continue
                            if entry.record_identity is None:
                                raise StoreError(
                                    "non-missing artifact lacks record identity"
                                )

                            record_digest = _digest(
                                entry.record_identity,
                                label="artifact record identity",
                            )
                            self._copy_object_into_snapshot(
                                root_fd,
                                temp_snapshot_fd,
                                source_category=_OBJECT_RECORDS,
                                source_name=record_digest + ".json",
                                destination_category=("artifact_records", "sha256"),
                                destination_name=record_digest + ".json",
                            )

                            if entry.retention is RetentionState.CONTENT_RETAINED:
                                content_digest = _digest(
                                    entry.content_identity,
                                    label="artifact content identity",
                                )
                                self._copy_object_into_snapshot(
                                    root_fd,
                                    temp_snapshot_fd,
                                    source_category=_OBJECT_ARTIFACTS,
                                    source_name=content_digest,
                                    destination_category=("artifacts", "sha256"),
                                    destination_name=content_digest,
                                )

                        for event_identity_value in self._events:
                            event_digest = _digest(
                                event_identity_value,
                                label="event identity",
                            )
                            self._copy_object_into_snapshot(
                                root_fd,
                                temp_snapshot_fd,
                                source_category=_OBJECT_EVENTS,
                                source_name=event_digest + ".json",
                                destination_category=("events", "sha256"),
                                destination_name=event_digest + ".json",
                            )

                        self._write_snapshot_manifest(
                            temp_snapshot_fd,
                            manifest,
                        )
                    finally:
                        os.close(temp_snapshot_fd)

                    if self._existing_snapshot_is_safe(
                        snapshots_parent_fd,
                        digest,
                    ):
                        shutil.rmtree(temp_snapshot)
                        _fsync_directory(snapshots_parent_fd)
                    else:
                        try:
                            os.rename(
                                temp_name,
                                digest,
                                src_dir_fd=snapshots_parent_fd,
                                dst_dir_fd=snapshots_parent_fd,
                            )
                            created_final = True
                        except FileExistsError:
                            shutil.rmtree(temp_snapshot)
                        except OSError as exc:
                            raise StoreError(
                                f"snapshot publication failed: {exc}"
                            ) from exc

                        # Required for both a fresh rename and a raced existing
                        # snapshot before HEAD may become authoritative.
                        _fsync_directory(snapshots_parent_fd)
                finally:
                    os.close(snapshots_parent_fd)

            try:
                self._verify_snapshot_identity(
                    final_snapshot,
                    manifest.manifest_identity,
                    label="new snapshot",
                )
            except StoreError:
                if created_final:
                    shutil.rmtree(final_snapshot, ignore_errors=True)
                raise
            return final_snapshot
        except Exception:
            if temp_snapshot.exists():
                shutil.rmtree(temp_snapshot, ignore_errors=True)
            raise

    def _update_head(self, manifest_identity: str) -> None:
        _digest(manifest_identity, label="manifest identity")
        data = (manifest_identity + "\n").encode("ascii")
        with self._root_fd() as root_fd:
            temp_name = f".HEAD.{uuid.uuid4().hex}.tmp"
            fd: int | None = None
            try:
                try:
                    fd = os.open(
                        temp_name,
                        _file_create_flags(),
                        0o600,
                        dir_fd=root_fd,
                    )
                    _write_all(fd, data)
                    os.fsync(fd)
                except OSError as exc:
                    raise StoreError(f"HEAD update preparation failed: {exc}") from exc
                finally:
                    if fd is not None:
                        os.close(fd)
                        fd = None

                try:
                    os.rename(
                        temp_name,
                        _HEAD,
                        src_dir_fd=root_fd,
                        dst_dir_fd=root_fd,
                    )
                    _fsync_directory(root_fd)
                except OSError as exc:
                    raise StoreError(f"HEAD update failed: {exc}") from exc
            finally:
                if fd is not None:
                    os.close(fd)
                try:
                    os.unlink(temp_name, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    def finalize(self, *, scope: str = "closed") -> StoredSnapshot:
        with self._exclusive_finalize_lock():
            disk_head = self._read_head()
            if disk_head != self._current_manifest_identity:
                raise StoreError(
                    "store HEAD changed since this instance loaded; "
                    "reopen before finalizing"
                )
            core = ManifestCore.build(
                artifacts=self._artifacts.values(),
                events=self._events,
                scope=scope,
            )
            manifest = ManifestEnvelope.seal(core)
            snapshot_path = self._build_snapshot(manifest)
            report = self._verify_snapshot_identity(
                snapshot_path,
                manifest.manifest_identity,
                label="snapshot before HEAD publication",
            )
            self._update_head(manifest.manifest_identity)
            self._current_manifest_identity = manifest.manifest_identity
            self._session_changed_artifacts.clear()
            return StoredSnapshot(
                manifest_identity=manifest.manifest_identity,
                path=snapshot_path,
                verification=report,
            )

    def current_snapshot_path(self) -> Path | None:
        if self._current_manifest_identity is None:
            return None
        digest = _digest(
            self._current_manifest_identity,
            label="current manifest identity",
        )
        return self.root.joinpath(*_SNAPSHOTS, digest)

    def verify_current(self) -> VerificationReport:
        path = self.current_snapshot_path()
        if path is None or self._current_manifest_identity is None:
            raise StoreError("store has no finalized snapshot")
        return self._verify_snapshot_identity(
            path,
            self._current_manifest_identity,
            label="current snapshot",
        )

    def _read_head(self) -> str | None:
        with self._root_fd() as root_fd:
            try:
                fd = os.open(_HEAD, _file_read_flags(), dir_fd=root_fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise StoreError(f"HEAD cannot be opened safely: {exc}") from exc
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise StoreError("HEAD must be a regular file")
                try:
                    raw = _read_all(fd)
                except OSError as exc:
                    raise StoreError(f"HEAD cannot be read: {exc}") from exc
            finally:
                os.close(fd)

        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise StoreError("HEAD must be ASCII") from exc
        if not text.endswith("\n") or text.count("\n") != 1:
            raise StoreError("HEAD must contain exactly one identity and LF")
        identity = text[:-1]
        _digest(identity, label="HEAD manifest identity")
        return identity

    def _read_snapshot_manifest(
        self,
        snapshot: Path,
        expected_identity: str,
    ) -> dict[str, object]:
        try:
            snapshot_fd = os.open(snapshot, _directory_flags())
        except OSError as exc:
            raise StoreError(f"snapshot cannot be opened safely: {exc}") from exc
        try:
            try:
                manifest_fd = os.open(
                    "manifest.json",
                    _file_read_flags(),
                    dir_fd=snapshot_fd,
                )
            except OSError as exc:
                raise StoreError(
                    f"snapshot manifest cannot be opened safely: {exc}"
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(manifest_fd).st_mode):
                    raise StoreError("snapshot manifest must be a regular file")
                raw = _read_all(manifest_fd)
            finally:
                os.close(manifest_fd)
        finally:
            os.close(snapshot_fd)

        try:
            envelope = parse_canonical_json_bytes(raw)
        except (CanonicalizationError, RecursionError) as exc:
            raise StoreError(f"snapshot manifest cannot be parsed: {exc}") from exc
        if not isinstance(envelope, dict):
            raise StoreError("snapshot manifest envelope must be an object")
        core = envelope.get("core")
        if not isinstance(core, dict):
            raise StoreError("snapshot manifest core must be an object")
        if (
            envelope.get("self_hash_exclusion") != "manifest_identity"
            or envelope.get("manifest_identity") != expected_identity
            or manifest_identity(core) != expected_identity
        ):
            raise StoreError(
                "snapshot manifest changed after verification or does not match HEAD"
            )
        return envelope

    def _open_regular_member(
        self,
        parent_fd: int,
        name: str,
        *,
        label: str,
    ) -> int:
        try:
            fd = os.open(
                name,
                _file_read_flags(),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise StoreError(f"{label} is missing or unsafe: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoreError(f"{label} is not a regular file")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _assert_pool_member_matches_snapshot(
        self,
        root_fd: int,
        snapshot_fd: int,
        *,
        pool_category: tuple[str, ...],
        pool_name: str,
        snapshot_category: tuple[str, ...],
        snapshot_name: str,
        label: str,
    ) -> None:
        pool_parent_fd = self._open_dir_chain(
            root_fd,
            pool_category,
            create=False,
        )
        try:
            snapshot_parent_fd = self._open_dir_chain(
                snapshot_fd,
                snapshot_category,
                create=False,
            )
        except Exception:
            os.close(pool_parent_fd)
            raise
        try:
            pool_fd = self._open_regular_member(
                pool_parent_fd,
                pool_name,
                label=f"object pool {label}",
            )
            try:
                snapshot_member_fd = self._open_regular_member(
                    snapshot_parent_fd,
                    snapshot_name,
                    label=f"verified snapshot {label}",
                )
            except Exception:
                os.close(pool_fd)
                raise
            try:
                while True:
                    pool_chunk = os.read(pool_fd, _CHUNK_SIZE)
                    snapshot_chunk = os.read(snapshot_member_fd, _CHUNK_SIZE)
                    if pool_chunk != snapshot_chunk:
                        raise StoreError(
                            f"object pool {label} differs from verified snapshot"
                        )
                    if not pool_chunk:
                        break
            finally:
                os.close(pool_fd)
                os.close(snapshot_member_fd)
        finally:
            os.close(pool_parent_fd)
            os.close(snapshot_parent_fd)

    def _validate_object_pool_against_snapshot(
        self,
        snapshot_identity: str,
        artifacts: dict[str, ManifestArtifact],
        events: set[str],
    ) -> None:
        snapshot_digest = _digest(
            snapshot_identity,
            label="snapshot manifest identity",
        )
        with self._root_fd() as root_fd:
            snapshots_parent_fd = self._open_dir_chain(
                root_fd,
                _SNAPSHOTS,
                create=False,
            )
            try:
                try:
                    snapshot_fd = os.open(
                        snapshot_digest,
                        _directory_flags(),
                        dir_fd=snapshots_parent_fd,
                    )
                except OSError as exc:
                    raise StoreError(
                        f"verified snapshot cannot be reopened safely: {exc}"
                    ) from exc
            finally:
                os.close(snapshots_parent_fd)

            try:
                for entry in artifacts.values():
                    if entry.retention is RetentionState.MISSING:
                        continue
                    if entry.record_identity is None:
                        raise StoreError(
                            "verified snapshot artifact lacks record identity"
                        )
                    record_digest = _digest(
                        entry.record_identity,
                        label="artifact record identity",
                    )
                    self._assert_pool_member_matches_snapshot(
                        root_fd,
                        snapshot_fd,
                        pool_category=_OBJECT_RECORDS,
                        pool_name=record_digest + ".json",
                        snapshot_category=("artifact_records", "sha256"),
                        snapshot_name=record_digest + ".json",
                        label=f"artifact record {entry.record_identity}",
                    )

                    if entry.retention is RetentionState.CONTENT_RETAINED:
                        content_digest = _digest(
                            entry.content_identity,
                            label="artifact content identity",
                        )
                        self._assert_pool_member_matches_snapshot(
                            root_fd,
                            snapshot_fd,
                            pool_category=_OBJECT_ARTIFACTS,
                            pool_name=content_digest,
                            snapshot_category=("artifacts", "sha256"),
                            snapshot_name=content_digest,
                            label=f"artifact content {entry.content_identity}",
                        )

                for event_identity_value in events:
                    event_digest = _digest(
                        event_identity_value,
                        label="event identity",
                    )
                    self._assert_pool_member_matches_snapshot(
                        root_fd,
                        snapshot_fd,
                        pool_category=_OBJECT_EVENTS,
                        pool_name=event_digest + ".json",
                        snapshot_category=("events", "sha256"),
                        snapshot_name=event_digest + ".json",
                        label=f"event {event_identity_value}",
                    )
            finally:
                os.close(snapshot_fd)

    def _load_head(self) -> None:
        identity = self._read_head()
        if identity is None:
            return
        digest = _digest(identity, label="HEAD manifest identity")
        snapshot = self.root.joinpath(*_SNAPSHOTS, digest)
        self._verify_snapshot_identity(
            snapshot,
            identity,
            label="HEAD snapshot",
        )

        envelope = self._read_snapshot_manifest(snapshot, identity)
        core = envelope.get("core")
        if not isinstance(core, dict):
            raise StoreError("verified snapshot manifest core must be an object")
        artifacts = core.get("artifacts")
        events = core.get("events")
        if not isinstance(artifacts, list) or not isinstance(events, list):
            raise StoreError("verified snapshot manifest collections are malformed")

        loaded_artifacts: dict[str, ManifestArtifact] = {}
        for entry in artifacts:
            if not isinstance(entry, dict):
                raise StoreError("verified snapshot artifact entry is malformed")
            content_identity = entry.get("content_identity")
            retention_raw = entry.get("retention")
            record_identity = entry.get("record_identity")
            if not isinstance(content_identity, str) or not isinstance(retention_raw, str):
                raise StoreError("verified snapshot artifact entry has invalid types")
            try:
                retention = RetentionState(retention_raw)
                manifest_artifact = ManifestArtifact(
                    content_identity=content_identity,
                    retention=retention,
                    record_identity=record_identity,
                )
            except (TypeError, ValueError) as exc:
                raise StoreError(
                    f"verified snapshot artifact cannot be reconstructed: {exc}"
                ) from exc
            loaded_artifacts[content_identity] = manifest_artifact

        loaded_events: set[str] = set()
        for value in events:
            if not isinstance(value, str):
                raise StoreError("verified snapshot event identity is not a string")
            _digest(value, label="verified snapshot event identity")
            loaded_events.add(value)

        self._validate_object_pool_against_snapshot(
            identity,
            loaded_artifacts,
            loaded_events,
        )

        self._artifacts = loaded_artifacts
        self._events = loaded_events
        self._current_manifest_identity = identity
        self._session_changed_artifacts.clear()
