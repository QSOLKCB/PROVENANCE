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
    EventEnvelope,
    ManifestArtifact,
    ManifestCore,
    ManifestEnvelope,
    RetentionState,
    canonical_json_bytes,
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
_CHUNK_SIZE = 1024 * 1024


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
    for function, description in (
        (os.open, "dir_fd support for os.open"),
        (os.mkdir, "dir_fd support for os.mkdir"),
        (os.unlink, "dir_fd support for os.unlink"),
        (os.link, "dir_fd support for os.link"),
        (os.rename, "dir_fd support for os.rename"),
    ):
        if function not in os.supports_dir_fd:
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
        self.root = Path(root)
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
        if self.root.exists() and self.root.is_symlink():
            raise StoreError("store root must not be a symbolic link")
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreError(f"store root cannot be created: {exc}") from exc
        try:
            mode = self.root.lstat().st_mode
        except OSError as exc:
            raise StoreError(f"store root cannot be inspected: {exc}") from exc
        if not stat.S_ISDIR(mode):
            raise StoreError("store root must be a directory")

        with self._root_fd() as root_fd:
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
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise StoreError("store root must be a directory")
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

    def _managed_object_path(
        self,
        category: tuple[str, ...],
        name: str,
    ) -> Path:
        return self.root.joinpath(*category, name)

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
        self._check_artifact_rebinding(entry)

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

    def _check_artifact_rebinding(self, entry: ManifestArtifact) -> None:
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

    def _link_object_into_snapshot(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        try:
            mode = source.lstat().st_mode
        except OSError as exc:
            raise StoreError(f"required object is missing: {source}") from exc
        if not stat.S_ISREG(mode):
            raise StoreError(f"required object is not a regular file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source, destination, follow_symlinks=False)
        except OSError as exc:
            raise StoreError(
                f"required object cannot be linked into snapshot: {source}: {exc}"
            ) from exc

    def _write_snapshot_manifest(
        self,
        temp_snapshot: Path,
        manifest: ManifestEnvelope,
    ) -> None:
        manifest_path = temp_snapshot / "manifest.json"
        try:
            fd = os.open(
                manifest_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
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

    def _build_snapshot(self, manifest: ManifestEnvelope) -> Path:
        digest = _digest(manifest.manifest_identity, label="manifest identity")
        snapshots_parent = self.root.joinpath(*_SNAPSHOTS)
        final_snapshot = snapshots_parent / digest
        if final_snapshot.exists():
            report = verify_bundle(final_snapshot)
            if not report.integrity_verified:
                raise StoreError(
                    "existing snapshot for manifest identity failed verification: "
                    + "; ".join(report.errors)
                )
            return final_snapshot

        temp_snapshot = snapshots_parent / f".{digest}.{uuid.uuid4().hex}.tmp"
        created_final = False
        try:
            temp_snapshot.mkdir(mode=0o700)

            for entry in self._artifacts.values():
                if entry.retention is RetentionState.MISSING:
                    continue
                if entry.record_identity is None:
                    raise StoreError("non-missing artifact lacks record identity")
                record_digest = _digest(
                    entry.record_identity,
                    label="artifact record identity",
                )
                self._link_object_into_snapshot(
                    self._managed_object_path(
                        _OBJECT_RECORDS,
                        record_digest + ".json",
                    ),
                    temp_snapshot
                    / "artifact_records"
                    / "sha256"
                    / f"{record_digest}.json",
                )

                if entry.retention is RetentionState.CONTENT_RETAINED:
                    content_digest = _digest(
                        entry.content_identity,
                        label="artifact content identity",
                    )
                    self._link_object_into_snapshot(
                        self._managed_object_path(
                            _OBJECT_ARTIFACTS,
                            content_digest,
                        ),
                        temp_snapshot / "artifacts" / "sha256" / content_digest,
                    )

            for event_identity_value in self._events:
                event_digest = _digest(event_identity_value, label="event identity")
                self._link_object_into_snapshot(
                    self._managed_object_path(
                        _OBJECT_EVENTS,
                        event_digest + ".json",
                    ),
                    temp_snapshot
                    / "events"
                    / "sha256"
                    / f"{event_digest}.json",
                )

            self._write_snapshot_manifest(temp_snapshot, manifest)

            try:
                os.rename(temp_snapshot, final_snapshot)
                created_final = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise StoreError(f"snapshot publication failed: {exc}") from exc

            if not created_final and temp_snapshot.exists():
                shutil.rmtree(temp_snapshot)

            report = verify_bundle(final_snapshot)
            if not report.integrity_verified:
                if created_final:
                    shutil.rmtree(final_snapshot, ignore_errors=True)
                raise StoreError(
                    "new snapshot failed independent verification: "
                    + "; ".join(report.errors)
                )
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
            core = ManifestCore.build(
                artifacts=self._artifacts.values(),
                events=self._events,
                scope=scope,
            )
            manifest = ManifestEnvelope.seal(core)
            snapshot_path = self._build_snapshot(manifest)
            report = verify_bundle(snapshot_path)
            if not report.integrity_verified:
                raise StoreError(
                    "snapshot failed verification before HEAD publication: "
                    + "; ".join(report.errors)
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
        if path is None:
            raise StoreError("store has no finalized snapshot")
        return verify_bundle(path)

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

    def _read_snapshot_manifest(self, snapshot: Path) -> dict[str, object]:
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
        except Exception as exc:
            raise StoreError(f"snapshot manifest cannot be parsed: {exc}") from exc
        if not isinstance(envelope, dict):
            raise StoreError("snapshot manifest envelope must be an object")
        return envelope

    def _load_head(self) -> None:
        identity = self._read_head()
        if identity is None:
            return
        digest = _digest(identity, label="HEAD manifest identity")
        snapshot = self.root.joinpath(*_SNAPSHOTS, digest)
        report = verify_bundle(snapshot)
        if not report.integrity_verified:
            raise StoreError(
                "HEAD snapshot failed independent verification: "
                + "; ".join(report.errors)
            )

        envelope = self._read_snapshot_manifest(snapshot)
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

        self._artifacts = loaded_artifacts
        self._events = loaded_events
        self._current_manifest_identity = identity
        self._session_changed_artifacts.clear()
