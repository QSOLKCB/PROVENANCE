"""Append-only local custody ledger for PROVENANCE Phase 4."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import threading
import uuid
from typing import Iterator

from provenance_core import (
    CustodyAction,
    CustodyCore,
    CustodyEnvelope,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_verify import CustodyVerificationReport, verify_custody_records

from .time_source import ClockObservation, observe_clock

CUSTODY_LEDGER_FORMAT = "provenance.local-custody.v1"
_FORMAT = "CUSTODY_FORMAT"
_LOCK = ".custody.lock"
_RECORDS = ("records", "sha256")
_STAGING = ("staging",)
_CHUNK_SIZE = 1024 * 1024

_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[tuple[int, int, str], threading.Lock] = {}


class CustodyLedgerError(RuntimeError):
    """Raised when the local custody ledger cannot preserve its contract."""


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required if not hasattr(os, name)]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if os.mkdir not in os.supports_dir_fd:
        missing.append("dir_fd support for os.mkdir")
    if os.unlink not in os.supports_dir_fd:
        missing.append("dir_fd support for os.unlink")
    if os.link not in os.supports_dir_fd:
        missing.append("dir_fd support for os.link")
    if missing:
        raise CustodyLedgerError(
            "custody ledger requires descriptor-relative filesystem support: "
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
            raise OSError("short write while publishing custody evidence")
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
        raise CustodyLedgerError(f"directory fsync failed: {exc}") from exc


def _process_lock_for_root(root_fd: int) -> threading.Lock:
    root_stat = os.fstat(root_fd)
    key = (root_stat.st_dev, root_stat.st_ino, _LOCK)
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PROCESS_LOCKS[key] = lock
        return lock


class LocalCustodyLedger:
    """Immutable custody records with derived per-subject chain tips."""

    def __init__(self, root: Path | str):
        supplied = Path(root).expanduser()
        if supplied.is_symlink():
            raise CustodyLedgerError("custody root must not be a symbolic link")
        self.root = supplied.resolve(strict=False)
        self._root_identity: tuple[int, int] | None = None
        self._initialize()

    def _initialize(self) -> None:
        parent = self.root.parent
        if not parent.exists():
            raise CustodyLedgerError(
                "custody root parent must already exist"
            )
        if parent.is_symlink():
            raise CustodyLedgerError(
                "custody root parent must not be a symbolic link"
            )
        try:
            parent_fd = os.open(parent, _directory_flags())
        except OSError as exc:
            raise CustodyLedgerError(
                f"custody root parent cannot be opened safely: {exc}"
            ) from exc
        try:
            try:
                os.mkdir(self.root.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise CustodyLedgerError(
                    f"custody root cannot be created: {exc}"
                ) from exc
            _fsync_directory(parent_fd)
        finally:
            os.close(parent_fd)

        try:
            root_stat = self.root.lstat()
        except OSError as exc:
            raise CustodyLedgerError(
                f"custody root cannot be inspected: {exc}"
            ) from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise CustodyLedgerError("custody root must be a directory")
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)

        with self._root_fd() as root_fd:
            self._ensure_format(root_fd)
            records_fd = self._open_dir_chain(
                root_fd,
                _RECORDS,
                create=True,
            )
            os.close(records_fd)
            staging_fd = self._open_dir_chain(
                root_fd,
                _STAGING,
                create=True,
            )
            os.close(staging_fd)
            self._ensure_lock(root_fd)

        with self._exclusive_lock():
            self._recover_staging_locked()
            report = self.verify()
            if not report.integrity_verified:
                raise CustodyLedgerError(
                    "existing custody ledger failed verification: "
                    + "; ".join(report.errors)
                )

    @contextmanager
    def _root_fd(self) -> Iterator[int]:
        try:
            fd = os.open(self.root, _directory_flags())
        except OSError as exc:
            raise CustodyLedgerError(
                f"custody root cannot be opened safely: {exc}"
            ) from exc
        try:
            opened = os.fstat(fd)
            if not stat.S_ISDIR(opened.st_mode):
                raise CustodyLedgerError("custody root must be a directory")
            if (
                self._root_identity is not None
                and (opened.st_dev, opened.st_ino) != self._root_identity
            ):
                raise CustodyLedgerError(
                    "custody root filesystem identity changed"
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
                    raise CustodyLedgerError(
                        f"unsafe custody directory component: {part!r}"
                    )
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise CustodyLedgerError(
                            f"custody directory {part!r} cannot be created: {exc}"
                        ) from exc
                    _fsync_directory(current_fd)
                try:
                    next_fd = os.open(
                        part,
                        _directory_flags(),
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise CustodyLedgerError(
                        f"custody directory {part!r} is missing or unsafe: {exc}"
                    ) from exc
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    def _ensure_format(self, root_fd: int) -> None:
        expected = (CUSTODY_LEDGER_FORMAT + "\n").encode("ascii")
        try:
            fd = os.open(_FORMAT, _file_read_flags(), dir_fd=root_fd)
        except FileNotFoundError:
            try:
                fd = os.open(
                    _FORMAT,
                    _file_create_flags(),
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise CustodyLedgerError(
                    f"custody format marker cannot be created: {exc}"
                ) from exc
            try:
                _write_all(fd, expected)
                os.fsync(fd)
            except OSError as exc:
                raise CustodyLedgerError(
                    f"custody format marker cannot be written: {exc}"
                ) from exc
            finally:
                os.close(fd)
            _fsync_directory(root_fd)
            return
        except OSError as exc:
            raise CustodyLedgerError(
                f"custody format marker cannot be opened: {exc}"
            ) from exc

        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise CustodyLedgerError(
                    "custody format marker must be a regular file"
                )
            raw = _read_all(fd)
            if raw != expected:
                raise CustodyLedgerError(
                    "unsupported custody ledger format"
                )
            os.fsync(fd)
        except OSError as exc:
            raise CustodyLedgerError(
                f"custody format marker cannot be synced: {exc}"
            ) from exc
        finally:
            os.close(fd)
        _fsync_directory(root_fd)

    def _ensure_lock(self, root_fd: int) -> None:
        process_lock = _process_lock_for_root(root_fd)
        with process_lock:
            try:
                fd = os.open(
                    _LOCK,
                    os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise CustodyLedgerError(
                    f"custody lock cannot be created safely: {exc}"
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise CustodyLedgerError(
                        "custody lock must be a regular file"
                    )
            finally:
                os.close(fd)
            _fsync_directory(root_fd)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._root_fd() as root_fd:
            process_lock = _process_lock_for_root(root_fd)
            process_lock.acquire()
            fd: int | None = None
            posix_locked = False
            try:
                try:
                    fd = os.open(
                        _LOCK,
                        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=root_fd,
                    )
                except OSError as exc:
                    raise CustodyLedgerError(
                        f"custody lock cannot be opened: {exc}"
                    ) from exc
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise CustodyLedgerError(
                        "custody lock must be a regular file"
                    )
                try:
                    fcntl.lockf(
                        fd,
                        fcntl.LOCK_EX,
                        0,
                        0,
                        os.SEEK_SET,
                    )
                    posix_locked = True
                except OSError as exc:
                    raise CustodyLedgerError(
                        f"custody POSIX lock operation failed: {exc}"
                    ) from exc
                yield
            finally:
                try:
                    if fd is not None and posix_locked:
                        fcntl.lockf(
                            fd,
                            fcntl.LOCK_UN,
                            0,
                            0,
                            os.SEEK_SET,
                        )
                finally:
                    if fd is not None:
                        os.close(fd)
                    process_lock.release()

    def _recover_staging_locked(self) -> None:
        with self._root_fd() as root_fd:
            staging_fd = self._open_dir_chain(
                root_fd,
                _STAGING,
                create=True,
            )
            try:
                if os.scandir not in os.supports_fd:
                    raise CustodyLedgerError(
                        "custody staging recovery requires scandir(fd) support"
                    )
                stale: list[str] = []
                with os.scandir(staging_fd) as entries:
                    for entry in entries:
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                        except OSError as exc:
                            raise CustodyLedgerError(
                                f"custody staging entry {entry.name} cannot be inspected: {exc}"
                            ) from exc
                        if (
                            not stat.S_ISREG(mode)
                            or not entry.name.startswith(".")
                            or not entry.name.endswith(".tmp")
                        ):
                            raise CustodyLedgerError(
                                f"unexpected custody staging entry: {entry.name}"
                            )
                        stale.append(entry.name)

                for name in stale:
                    try:
                        os.unlink(name, dir_fd=staging_fd)
                    except OSError as exc:
                        raise CustodyLedgerError(
                            f"stale custody staging file {name} cannot be removed: {exc}"
                        ) from exc
                if stale:
                    _fsync_directory(staging_fd)
            finally:
                os.close(staging_fd)

    def _record_bytes(self) -> list[bytes]:
        with self._root_fd() as root_fd:
            records_fd = self._open_dir_chain(
                root_fd,
                _RECORDS,
                create=False,
            )
            try:
                if os.scandir not in os.supports_fd:
                    raise CustodyLedgerError(
                        "custody enumeration requires scandir(fd) support"
                    )
                names: list[str] = []
                with os.scandir(records_fd) as entries:
                    for entry in entries:
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                        except OSError as exc:
                            raise CustodyLedgerError(
                                f"custody entry {entry.name} cannot be inspected: {exc}"
                            ) from exc
                        if not stat.S_ISREG(mode):
                            raise CustodyLedgerError(
                                f"custody entry {entry.name} is not a regular file"
                            )
                        names.append(entry.name)

                records: list[bytes] = []
                for name in sorted(names):
                    if not name.endswith(".json"):
                        raise CustodyLedgerError(
                            f"unexpected custody record filename: {name}"
                        )
                    try:
                        fd = os.open(
                            name,
                            _file_read_flags(),
                            dir_fd=records_fd,
                        )
                    except OSError as exc:
                        raise CustodyLedgerError(
                            f"custody record {name} cannot be opened: {exc}"
                        ) from exc
                    try:
                        raw = _read_all(fd)
                    finally:
                        os.close(fd)

                    try:
                        parsed = parse_canonical_json_bytes(raw)
                    except Exception as exc:
                        raise CustodyLedgerError(
                            f"custody record {name} is not canonical: {exc}"
                        ) from exc
                    if not isinstance(parsed, dict):
                        raise CustodyLedgerError(
                            f"custody record {name} must be an object"
                        )
                    claimed = parsed.get("custody_identity")
                    if not isinstance(claimed, str):
                        raise CustodyLedgerError(
                            f"custody record {name} lacks identity"
                        )
                    expected_name = claimed.split(":", 1)[-1] + ".json"
                    if name != expected_name:
                        raise CustodyLedgerError(
                            f"custody record filename {name} does not match identity"
                        )
                    records.append(raw)
                return records
            finally:
                os.close(records_fd)

    def verify(self) -> CustodyVerificationReport:
        try:
            records = self._record_bytes()
        except CustodyLedgerError as exc:
            return CustodyVerificationReport(
                integrity_verified=False,
                record_count=0,
                subject_count=0,
                tips=(),
                errors=(str(exc),),
            )
        return verify_custody_records(records)

    def _publish(self, envelope: CustodyEnvelope) -> None:
        data = canonical_json_bytes(envelope.to_dict())
        digest = envelope.custody_identity.split(":", 1)[1]
        name = digest + ".json"
        temp_name = f".{name}.{uuid.uuid4().hex}.tmp"

        with self._root_fd() as root_fd:
            records_fd = self._open_dir_chain(
                root_fd,
                _RECORDS,
                create=True,
            )
            staging_fd = self._open_dir_chain(
                root_fd,
                _STAGING,
                create=True,
            )
            try:
                try:
                    existing_fd = os.open(
                        name,
                        _file_read_flags(),
                        dir_fd=records_fd,
                    )
                except FileNotFoundError:
                    existing_fd = None
                except OSError as exc:
                    raise CustodyLedgerError(
                        f"custody record {name} cannot be inspected: {exc}"
                    ) from exc
                if existing_fd is not None:
                    try:
                        existing = _read_all(existing_fd)
                    finally:
                        os.close(existing_fd)
                    if existing != data:
                        raise CustodyLedgerError(
                            f"custody identity collision at {name}"
                        )
                    _fsync_directory(records_fd)
                    return

                fd: int | None = None
                try:
                    try:
                        fd = os.open(
                            temp_name,
                            _file_create_flags(),
                            0o600,
                            dir_fd=staging_fd,
                        )
                        _write_all(fd, data)
                        os.fsync(fd)
                    except OSError as exc:
                        raise CustodyLedgerError(
                            f"custody temporary write failed: {exc}"
                        ) from exc
                    finally:
                        if fd is not None:
                            os.close(fd)
                            fd = None

                    try:
                        os.link(
                            temp_name,
                            name,
                            src_dir_fd=staging_fd,
                            dst_dir_fd=records_fd,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        try:
                            existing_fd = os.open(
                                name,
                                _file_read_flags(),
                                dir_fd=records_fd,
                            )
                        except OSError as exc:
                            raise CustodyLedgerError(
                                f"concurrent custody record cannot be opened: {exc}"
                            ) from exc
                        try:
                            existing = _read_all(existing_fd)
                        finally:
                            os.close(existing_fd)
                        if existing != data:
                            raise CustodyLedgerError(
                                f"concurrent custody identity collision at {name}"
                            )
                    except OSError as exc:
                        raise CustodyLedgerError(
                            f"custody publication failed: {exc}"
                        ) from exc

                    _fsync_directory(records_fd)
                finally:
                    try:
                        os.unlink(temp_name, dir_fd=staging_fd)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        raise CustodyLedgerError(
                            f"custody staging cleanup failed: {exc}"
                        ) from exc
                    else:
                        _fsync_directory(staging_fd)
            finally:
                os.close(staging_fd)
                os.close(records_fd)

    def append(
        self,
        subject_identity: str,
        action: CustodyAction,
        *,
        actor: str | None = None,
        source: str | None = None,
        related_identity: str | None = None,
        clock: ClockObservation | None = None,
    ) -> CustodyEnvelope:
        require_sha256_identity(
            subject_identity,
            label="custody subject identity",
        )
        if not isinstance(action, CustodyAction):
            raise TypeError("custody action must be a CustodyAction")
        if related_identity is not None:
            require_sha256_identity(
                related_identity,
                label="custody related identity",
            )
        if clock is None:
            clock = observe_clock()
        if not isinstance(clock, ClockObservation):
            raise TypeError("clock must be a ClockObservation")

        with self._exclusive_lock():
            self._recover_staging_locked()
            before = self.verify()
            if not before.integrity_verified:
                raise CustodyLedgerError(
                    "cannot append to invalid custody ledger: "
                    + "; ".join(before.errors)
                )
            tips = dict(before.tips)
            previous = tips.get(subject_identity)

            envelope = CustodyEnvelope.seal(
                CustodyCore(
                    subject_identity=subject_identity,
                    action=action,
                    recorded_at=clock.recorded_at,
                    clock_source=clock.clock_source,
                    clock_assurance=clock.clock_assurance,
                    actor=actor,
                    source=source,
                    previous_custody=previous,
                    related_identity=related_identity,
                )
            )
            self._publish(envelope)

            after = self.verify()
            if not after.integrity_verified:
                raise CustodyLedgerError(
                    "custody append produced invalid chain: "
                    + "; ".join(after.errors)
                )
            if dict(after.tips).get(subject_identity) != envelope.custody_identity:
                raise CustodyLedgerError(
                    "custody append did not become the unique subject tip"
                )
            return envelope
