"""PROVENANCE terminal backend composed from existing modules."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Iterator
import uuid

from provenance_core import (
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    ManifestArtifact,
    Relationship,
    RetentionState,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_custody import LocalCustodyLedger, observe_clock
from provenance_export import create_forensic_package
from provenance_privacy.disclosure import create_redacted_disclosure
from provenance_store import LocalEvidenceStore
from provenance_trust.records import (
    create_git_anchor_record,
    create_signature_record,
    write_git_anchor_payload,
    write_trust_record,
)
from provenance_verify import (
    verify_assurance,
    verify_bundle,
    verify_forensic_package,
    verify_git_anchor_record,
    verify_selective_disclosure,
    verify_signature_record,
)


CLI_INTERFACE_ID = "provenance-cli:rust/v1"

# Phase 8 deliberately shares Phase 7's hardened operational state so CLI and
# MCP cannot acknowledge disjoint pending working sets. This is operational
# state, not evidence semantics. The historical mcp-named files/schema remain
# for compatibility with Phase 7.
_WORKING_STATE = ".provenance-mcp-working.json"
_WORKING_LOCK = ".provenance-mcp-working.lock"
_WORKING_SCHEMA = "provenance.mcp-working-state.v1"
_CHUNK_SIZE = 1024 * 1024


class CliError(RuntimeError):
    """Raised when the terminal operator surface cannot preserve its contract."""


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _directory_flags() -> int:
    missing = [
        name
        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
        if not hasattr(os, name)
    ]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if os.rename not in os.supports_dir_fd:
        missing.append("dir_fd support for os.rename")
    if os.unlink not in os.supports_dir_fd:
        missing.append("dir_fd support for os.unlink")
    if missing:
        raise CliError(
            "provenance-cli requires descriptor-relative filesystem support: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


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
            raise OSError("short write")
        offset += written


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _directory_identity(fd: int) -> tuple[int, int]:
    value = os.fstat(fd)
    if not stat.S_ISDIR(value.st_mode):
        raise CliError("expected directory descriptor")
    return value.st_dev, value.st_ino


def _digest(identity: object, *, label: str) -> str:
    try:
        require_sha256_identity(identity, label=label)
    except (TypeError, ValueError) as exc:
        raise CliError(str(exc)) from exc
    assert isinstance(identity, str)
    return identity.split(":", 1)[1]


def _canonical_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = parse_canonical_json_bytes(data)
    except Exception as exc:
        raise CliError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CliError(f"{label} must be a JSON object")
    return value


def _copy_directory_contents(source_fd: int, destination_fd: int) -> None:
    for name in sorted(os.listdir(source_fd)):
        if not name or name in {".", ".."} or "/" in name:
            raise CliError("unsafe snapshot member name")
        info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(name, mode=0o700, dir_fd=destination_fd)
            source_child = os.open(name, _directory_flags(), dir_fd=source_fd)
            destination_child = os.open(
                name,
                _directory_flags(),
                dir_fd=destination_fd,
            )
            try:
                _copy_directory_contents(source_child, destination_child)
                os.fsync(destination_child)
            finally:
                os.close(source_child)
                os.close(destination_child)
            continue

        if not stat.S_ISREG(info.st_mode):
            raise CliError(
                f"snapshot contains unsupported filesystem object {name!r}"
            )

        source_file = os.open(name, _file_read_flags(), dir_fd=source_fd)
        destination_file = os.open(
            name,
            _file_create_flags(),
            0o600,
            dir_fd=destination_fd,
        )
        try:
            while True:
                chunk = os.read(source_file, _CHUNK_SIZE)
                if not chunk:
                    break
                _write_all(destination_file, chunk)
            os.fsync(destination_file)
        finally:
            os.close(source_file)
            os.close(destination_file)


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
            current_identity = _directory_identity(current_fd)
            if current_identity in protected:
                return True
            parent_fd = os.open("..", _directory_flags(), dir_fd=current_fd)
            parent_identity = _directory_identity(parent_fd)
            if parent_identity == current_identity:
                os.close(parent_fd)
                return False
            os.close(current_fd)
            current_fd = parent_fd
    finally:
        os.close(current_fd)


def _parent_path_still_matches(
    parent: Path,
    expected_identity: tuple[int, int],
) -> bool:
    try:
        fd = os.open(parent, _directory_flags())
    except OSError:
        return False
    try:
        return _directory_identity(fd) == expected_identity
    finally:
        os.close(fd)


class CliSession:
    """Terminal orchestration over existing store/custody/verifier contracts."""

    def __init__(self, store_root: Path | str, custody_root: Path | str):
        self.store = LocalEvidenceStore(store_root)
        with self.store._root_fd() as root_fd:
            self._bound_store_identity = _directory_identity(root_fd)
        self._active_root_fd: int | None = None
        self._pending_artifacts: set[str] = set()
        self._pending_events: set[str] = set()
        self._working_base_manifest_identity = (
            self.store.current_manifest_identity
        )
        self._custody_root = Path(custody_root).expanduser()
        with self._state_lock():
            self.custody = LocalCustodyLedger(self._custody_root)
            self._synchronize_locked()

    def _assert_bound_store_path(self) -> None:
        try:
            fd = os.open(self.store.root, _directory_flags())
        except OSError as exc:
            raise CliError(
                f"store root cannot be reopened safely: {exc}"
            ) from exc
        try:
            if _directory_identity(fd) != self._bound_store_identity:
                raise CliError(
                    "store root filesystem identity changed during CLI operation"
                )
        finally:
            os.close(fd)

    @contextmanager
    def _state_lock(self) -> Iterator[None]:
        root_fd = os.open(self.store.root, _directory_flags())
        if _directory_identity(root_fd) != self._bound_store_identity:
            os.close(root_fd)
            raise CliError(
                "store root filesystem identity changed before CLI operation"
            )
        lock_fd: int | None = None
        self._active_root_fd = root_fd
        try:
            try:
                lock_fd = os.open(
                    _WORKING_LOCK,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise CliError(
                    f"shared interface lock cannot be opened safely: {exc}"
                ) from exc
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise CliError("shared interface lock must be a regular file")
            os.fsync(root_fd)
            try:
                fcntl.lockf(lock_fd, fcntl.LOCK_EX)
            except OSError as exc:
                raise CliError(
                    f"shared interface lock cannot be acquired: {exc}"
                ) from exc
            try:
                yield
                self._assert_bound_store_path()
            finally:
                fcntl.lockf(lock_fd, fcntl.LOCK_UN)
        finally:
            self._active_root_fd = None
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(root_fd)

    def _root_fd(self) -> int:
        if self._active_root_fd is None:
            raise CliError("working-state access requires active CLI lock")
        return self._active_root_fd

    def _read_working_state(self) -> dict[str, Any] | None:
        root_fd = self._root_fd()
        try:
            fd = os.open(
                _WORKING_STATE,
                _file_read_flags(),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CliError(
                f"working state cannot be opened safely: {exc}"
            ) from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise CliError("working state must be a regular file")
            raw = _read_all(fd)
        finally:
            os.close(fd)

        value = _canonical_object(raw, label="working state")
        expected = {
            "schema",
            "phase",
            "base_manifest_identity",
            "finalized_manifest_identity",
            "artifacts",
            "events",
            "pending_verified_artifacts",
        }
        if set(value) != expected:
            raise CliError("working state keys changed")
        if value.get("schema") != _WORKING_SCHEMA:
            raise CliError("unsupported working state schema")
        if value.get("phase") not in {"recording", "finalized"}:
            raise CliError("working state phase is invalid")
        return value

    def _write_working_state(
        self,
        *,
        phase: str,
        finalized_manifest_identity: str | None = None,
    ) -> None:
        artifacts: list[dict[str, object]] = []
        for identity in sorted(self._pending_artifacts):
            entry = self.store.current_artifact_entry(identity)
            if entry is None:
                raise CliError(
                    f"pending artifact missing from working store: {identity}"
                )
            artifacts.append(entry.to_dict())

        value = {
            "schema": _WORKING_SCHEMA,
            "phase": phase,
            "base_manifest_identity": self._working_base_manifest_identity,
            "finalized_manifest_identity": finalized_manifest_identity,
            "artifacts": artifacts,
            "events": sorted(self._pending_events),
            "pending_verified_artifacts": sorted(self._pending_artifacts),
        }
        data = canonical_json_bytes(value)
        root_fd = self._root_fd()
        temp_name = f".{_WORKING_STATE}.{uuid.uuid4().hex}.tmp"
        fd: int | None = None
        try:
            fd = os.open(
                temp_name,
                _file_create_flags(),
                0o600,
                dir_fd=root_fd,
            )
            _write_all(fd, data)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.rename(
                temp_name,
                _WORKING_STATE,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
            os.fsync(root_fd)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass

    def _clear_working_state(self) -> None:
        root_fd = self._root_fd()
        try:
            os.unlink(_WORKING_STATE, dir_fd=root_fd)
        except FileNotFoundError:
            return
        os.fsync(root_fd)

    def _decode_artifacts(
        self,
        raw: object,
    ) -> tuple[ManifestArtifact, ...]:
        if not isinstance(raw, list):
            raise CliError("working artifacts must be a list")
        result: list[ManifestArtifact] = []
        for value in raw:
            if not isinstance(value, dict) or set(value) != {
                "content_identity",
                "record_identity",
                "retention",
            }:
                raise CliError("working artifact entry is malformed")
            try:
                result.append(
                    ManifestArtifact(
                        content_identity=value.get("content_identity"),
                        record_identity=value.get("record_identity"),
                        retention=RetentionState(value.get("retention")),
                    )
                )
            except (TypeError, ValueError) as exc:
                raise CliError(
                    f"working artifact cannot be reconstructed: {exc}"
                ) from exc
        return tuple(result)

    def _current_manifest_object(self) -> dict[str, Any] | None:
        snapshot = self.store.current_snapshot_path()
        if snapshot is None:
            return None
        try:
            raw = (snapshot / "manifest.json").read_bytes()
        except OSError as exc:
            raise CliError(
                f"current manifest cannot be read: {exc}"
            ) from exc
        return _canonical_object(raw, label="current manifest")

    def _journal_members_in_current_manifest(
        self,
        artifacts: tuple[ManifestArtifact, ...],
        events: tuple[str, ...],
    ) -> bool:
        manifest = self._current_manifest_object()
        if manifest is None:
            return False
        core = manifest.get("core")
        if not isinstance(core, dict):
            return False
        manifest_artifacts_raw = core.get("artifacts")
        manifest_events_raw = core.get("events")
        if (
            not isinstance(manifest_artifacts_raw, list)
            or not isinstance(manifest_events_raw, list)
        ):
            return False
        manifest_artifacts = {
            item.get("content_identity"): item
            for item in manifest_artifacts_raw
            if isinstance(item, dict)
        }
        for entry in artifacts:
            if manifest_artifacts.get(entry.content_identity) != entry.to_dict():
                return False
        return set(events).issubset(
            {
                item
                for item in manifest_events_raw
                if isinstance(item, str)
            }
        )

    def _append_custody(
        self,
        subject_identity: str,
        action: CustodyAction,
        *,
        actor: str,
        source: str,
        related_identity: str | None = None,
    ) -> str:
        envelope = self.custody.append(
            subject_identity,
            action,
            actor=actor,
            source=source,
            related_identity=related_identity,
            clock=observe_clock(),
        )
        return envelope.custody_identity

    def _complete_recovered_finalization(
        self,
        manifest_identity: str,
    ) -> None:
        report = self.store.verify_current()
        if (
            not report.integrity_verified
            or report.manifest_identity != manifest_identity
        ):
            raise CliError(
                "recovered finalization does not match verified store HEAD"
            )
        for identity in sorted(self._pending_artifacts):
            self._append_custody(
                identity,
                CustodyAction.VERIFIED,
                actor="provenance-verify",
                source=CLI_INTERFACE_ID,
                related_identity=manifest_identity,
            )
        self._append_custody(
            manifest_identity,
            CustodyAction.VERIFIED,
            actor="provenance-verify",
            source=CLI_INTERFACE_ID,
        )
        custody_report = self.custody.verify()
        if not custody_report.integrity_verified:
            raise CliError(
                "custody verification failed during recovery: "
                + "; ".join(custody_report.errors)
            )
        self._clear_working_state()
        self._pending_artifacts.clear()
        self._pending_events.clear()
        self._working_base_manifest_identity = manifest_identity

    def _synchronize_locked(self) -> None:
        self.store.refresh_from_disk()
        self._pending_artifacts.clear()
        self._pending_events.clear()
        self._working_base_manifest_identity = (
            self.store.current_manifest_identity
        )

        state = self._read_working_state()
        if state is None:
            return

        artifacts = self._decode_artifacts(state.get("artifacts"))
        events_raw = state.get("events")
        pending_raw = state.get("pending_verified_artifacts")
        if not isinstance(events_raw, list) or not all(
            isinstance(value, str) for value in events_raw
        ):
            raise CliError("working event list is malformed")
        if not isinstance(pending_raw, list) or not all(
            isinstance(value, str) for value in pending_raw
        ):
            raise CliError("pending verification list is malformed")

        events = tuple(events_raw)
        artifact_identities = {
            entry.content_identity
            for entry in artifacts
        }
        pending = set(pending_raw)
        if len(pending) != len(pending_raw):
            raise CliError("pending verification list contains duplicates")
        if pending != artifact_identities:
            raise CliError(
                "pending verification subjects do not match artifact membership"
            )

        self._pending_artifacts = pending
        self._pending_events = set(events)

        base = state.get("base_manifest_identity")
        finalized = state.get("finalized_manifest_identity")
        for label, identity in (("base", base), ("finalized", finalized)):
            if identity is not None:
                try:
                    require_sha256_identity(
                        identity,
                        label=f"CLI {label} manifest identity",
                    )
                except (TypeError, ValueError) as exc:
                    raise CliError(str(exc)) from exc

        current = self.store.current_manifest_identity
        phase = state.get("phase")
        if phase == "recording" and current == base:
            self.store.restore_unfinalized_membership(
                artifacts=artifacts,
                events=events,
                expected_head=base,
            )
            self._working_base_manifest_identity = base
            return

        recovered_manifest = (
            finalized
            if phase == "finalized"
            else current
        )
        if (
            isinstance(recovered_manifest, str)
            and current == recovered_manifest
            and self._journal_members_in_current_manifest(
                artifacts,
                events,
            )
        ):
            self._complete_recovered_finalization(recovered_manifest)
            return

        raise CliError(
            "working state does not match the current verified store HEAD"
        )

    def record(
        self,
        *,
        actor: str,
        operation: str,
        data: bytes,
        media_type: str,
        retain_content: bool,
        source_label: str,
    ) -> dict[str, Any]:
        if not actor:
            raise CliError("actor must be non-empty")
        if not operation:
            raise CliError("operation must be non-empty")
        if not media_type:
            raise CliError("media type must be non-empty")

        with self._state_lock():
            self._synchronize_locked()

            artifact = self.store.put_artifact(
                data,
                media_type=media_type,
                retain_content=retain_content,
            )
            self._append_custody(
                artifact.content_identity,
                CustodyAction.CAPTURED,
                actor=CLI_INTERFACE_ID,
                source=source_label,
            )
            self._append_custody(
                artifact.content_identity,
                CustodyAction.STORED,
                actor="provenance-store:local",
                source=CLI_INTERFACE_ID,
            )

            declaration_event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.DECLARED,
                    actor=actor,
                    operation=operation,
                    outputs=(artifact.content_identity,),
                )
            )
            self.store.put_event(declaration_event)

            receipt_bytes = canonical_json_bytes(
                {
                    "schema": "provenance.cli-receipt.v1",
                    "interface": CLI_INTERFACE_ID,
                    "invocation_id": uuid.uuid4().hex,
                    "declaration_artifact_identity": artifact.content_identity,
                    "declaration_event_identity": (
                        declaration_event.event_identity
                    ),
                }
            )
            receipt = self.store.put_artifact(
                receipt_bytes,
                media_type="application/json",
                retain_content=True,
            )
            self._append_custody(
                receipt.content_identity,
                CustodyAction.CAPTURED,
                actor=CLI_INTERFACE_ID,
                source="provenance record invocation receipt",
            )
            self._append_custody(
                receipt.content_identity,
                CustodyAction.STORED,
                actor="provenance-store:local",
                source=CLI_INTERFACE_ID,
            )

            receipt_event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor=CLI_INTERFACE_ID,
                    operation="provenance.cli.record.received",
                    inputs=(artifact.content_identity,),
                    outputs=(receipt.content_identity,),
                    relationships=(
                        Relationship(
                            "records_declaration",
                            declaration_event.event_identity,
                        ),
                    ),
                )
            )
            self.store.put_event(receipt_event)

            self._pending_artifacts.update(
                (
                    artifact.content_identity,
                    receipt.content_identity,
                )
            )
            self._pending_events.update(
                (
                    declaration_event.event_identity,
                    receipt_event.event_identity,
                )
            )
            self._write_working_state(phase="recording")

            return {
                "classification": "DECLARED",
                "occurrence_classification": "OBSERVED",
                "artifact_identity": artifact.content_identity,
                "event_identity": declaration_event.event_identity,
                "receipt_artifact_identity": receipt.content_identity,
                "receipt_event_identity": receipt_event.event_identity,
                "retention": (
                    "CONTENT_RETAINED"
                    if retain_content
                    else "DIGEST_ONLY"
                ),
                "byte_count": len(data),
                "media_type": media_type,
            }

    def inspect(self, identity: str | None) -> dict[str, Any]:
        with self._state_lock():
            self._synchronize_locked()
            if identity is None:
                return {
                    "current_manifest_identity": (
                        self.store.current_manifest_identity
                    ),
                    "artifact_count": self.store.artifact_count,
                    "event_count": self.store.event_count,
                    "pending_artifact_count": len(
                        self._pending_artifacts
                    ),
                    "pending_event_count": len(self._pending_events),
                    "manifest": self._current_manifest_object(),
                }

            digest = _digest(identity, label="inspect identity")
            entry = self.store.current_artifact_entry(identity)
            if entry is not None:
                return {
                    "kind": "artifact",
                    "identity": identity,
                    "retention": entry.retention.value,
                    "record_identity": entry.record_identity,
                }

            event_path = (
                self.store.root
                / "objects"
                / "events"
                / "sha256"
                / f"{digest}.json"
            )
            if event_path.is_file() and not event_path.is_symlink():
                return {
                    "kind": "event",
                    "identity": identity,
                }

            snapshot_path = (
                self.store.root
                / "snapshots"
                / "sha256"
                / digest
            )
            if snapshot_path.is_dir() and not snapshot_path.is_symlink():
                return {
                    "kind": "manifest",
                    "identity": identity,
                }

            custody_path = (
                self.custody.root
                / "records"
                / "sha256"
                / f"{digest}.json"
            )
            if custody_path.is_file() and not custody_path.is_symlink():
                return {
                    "kind": "custody",
                    "identity": identity,
                }

            raise CliError(f"unknown evidence identity: {identity}")

    def verify(self) -> dict[str, Any]:
        with self._state_lock():
            self._synchronize_locked()
            bundle = self.store.verify_current()
            custody = self.custody.verify()
            return {
                "bundle": bundle.to_dict(),
                "custody": custody.to_dict(),
            }

    def finalize(self, *, scope: str) -> dict[str, Any]:
        if scope not in {"open", "closed"}:
            raise CliError("scope must be 'open' or 'closed'")
        with self._state_lock():
            self._synchronize_locked()
            snapshot = self.store.finalize(scope=scope)
            self._write_working_state(
                phase="finalized",
                finalized_manifest_identity=snapshot.manifest_identity,
            )

            for identity in sorted(self._pending_artifacts):
                self._append_custody(
                    identity,
                    CustodyAction.VERIFIED,
                    actor="provenance-verify",
                    source=CLI_INTERFACE_ID,
                    related_identity=snapshot.manifest_identity,
                )
            self._append_custody(
                snapshot.manifest_identity,
                CustodyAction.VERIFIED,
                actor="provenance-verify",
                source=CLI_INTERFACE_ID,
            )

            custody_report = self.custody.verify()
            if not custody_report.integrity_verified:
                raise CliError(
                    "custody verification failed after finalization: "
                    + "; ".join(custody_report.errors)
                )

            self._clear_working_state()
            self._pending_artifacts.clear()
            self._pending_events.clear()
            self._working_base_manifest_identity = (
                snapshot.manifest_identity
            )

            return {
                "manifest_identity": snapshot.manifest_identity,
                "scope": scope,
                "integrity_verified": (
                    snapshot.verification.integrity_verified
                ),
                "custody_verified": custody_report.integrity_verified,
            }

    def package(self, destination_text: str) -> dict[str, Any]:
        if not destination_text:
            raise CliError("destination must be non-empty")
        with self._state_lock():
            self._synchronize_locked()
            result = create_forensic_package(
                self.store.root,
                self.custody.root,
                destination_text,
            )
            custody_identity = self._append_custody(
                result.evidence_manifest_identity,
                CustodyAction.EXPORTED,
                actor=CLI_INTERFACE_ID,
                source=str(result.path),
                related_identity=result.package_identity,
            )
            custody_report = self.custody.verify()
            if not custody_report.integrity_verified:
                raise CliError(
                    "custody verification failed after forensic package export: "
                    + "; ".join(custody_report.errors)
                )
            return {
                "package_identity": result.package_identity,
                "manifest_identity": result.evidence_manifest_identity,
                "scope": result.evidence_scope,
                "custody_record_count": result.custody_record_count,
                "destination": str(result.path),
                "integrity_verified": True,
                "export_custody_identity": custody_identity,
                "custody_verified": True,
            }

    def export(self, destination_text: str) -> dict[str, Any]:
        if not destination_text:
            raise CliError("destination must be non-empty")
        with self._state_lock():
            self._synchronize_locked()
            snapshot = self.store.current_snapshot_path()
            manifest_identity = self.store.current_manifest_identity
            if snapshot is None or manifest_identity is None:
                raise CliError("store has no finalized snapshot to export")
            current_report = self.store.verify_current()
            if not current_report.integrity_verified:
                raise CliError(
                    "current snapshot failed verification before export"
                )

            supplied = Path(destination_text).expanduser()
            if supplied.name in {"", ".", ".."}:
                raise CliError("export destination name is invalid")
            if supplied.is_symlink() or supplied.exists():
                raise CliError("export destination must not already exist")

            supplied_parent = supplied.parent
            if supplied_parent.is_symlink():
                raise CliError(
                    "export destination parent must not be a symlink"
                )
            try:
                parent = supplied_parent.resolve(strict=True)
            except OSError as exc:
                raise CliError(
                    f"export destination parent cannot be resolved: {exc}"
                ) from exc
            destination = parent / supplied.name

            protected_paths = (
                Path(self.store.root).resolve(strict=True),
                Path(self.custody.root).resolve(strict=True),
                snapshot.resolve(strict=True),
            )
            protected_identities: set[tuple[int, int]] = set()
            protected_fds: list[int] = []
            try:
                for path in protected_paths:
                    fd = os.open(path, _directory_flags())
                    protected_fds.append(fd)
                    protected_identities.add(_directory_identity(fd))

                parent_fd = os.open(parent, _directory_flags())
                parent_identity = _directory_identity(parent_fd)
                created = False
                try:
                    if _fd_is_within(parent_fd, protected_identities):
                        raise CliError(
                            "export destination must be outside the live "
                            "store, custody ledger, and source snapshot"
                        )

                    os.mkdir(
                        supplied.name,
                        mode=0o700,
                        dir_fd=parent_fd,
                    )
                    created = True
                    destination_fd = os.open(
                        supplied.name,
                        _directory_flags(),
                        dir_fd=parent_fd,
                    )
                    source_fd = os.open(snapshot, _directory_flags())
                    try:
                        _copy_directory_contents(
                            source_fd,
                            destination_fd,
                        )
                        os.fsync(destination_fd)
                    finally:
                        os.close(source_fd)
                        os.close(destination_fd)
                    os.fsync(parent_fd)

                    if (
                        not _parent_path_still_matches(
                            parent,
                            parent_identity,
                        )
                        or _fd_is_within(
                            parent_fd,
                            protected_identities,
                        )
                    ):
                        raise CliError(
                            "export destination parent changed during "
                            "publication"
                        )

                    exported_report = verify_bundle(destination)
                    if (
                        not exported_report.integrity_verified
                        or exported_report.manifest_identity
                        != manifest_identity
                    ):
                        raise CliError(
                            "exported snapshot failed independent verification"
                        )

                    if (
                        not _parent_path_still_matches(
                            parent,
                            parent_identity,
                        )
                        or _fd_is_within(
                            parent_fd,
                            protected_identities,
                        )
                    ):
                        raise CliError(
                            "export destination parent changed during "
                            "verification"
                        )
                except Exception:
                    if created:
                        try:
                            _remove_tree_at(parent_fd, supplied.name)
                            os.fsync(parent_fd)
                        except OSError:
                            pass
                    raise
                finally:
                    os.close(parent_fd)
            finally:
                for fd in protected_fds:
                    os.close(fd)

            custody_identity = self._append_custody(
                manifest_identity,
                CustodyAction.EXPORTED,
                actor=CLI_INTERFACE_ID,
                source=str(destination),
            )
            custody_report = self.custody.verify()
            if not custody_report.integrity_verified:
                raise CliError(
                    "custody verification failed after export: "
                    + "; ".join(custody_report.errors)
                )
            return {
                "manifest_identity": manifest_identity,
                "destination": str(destination),
                "integrity_verified": True,
                "custody_identity": custody_identity,
                "custody_verified": True,
            }


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--store",
        required=True,
        help="LocalEvidenceStore root.",
    )
    parser.add_argument(
        "--custody",
        required=True,
        help="LocalCustodyLedger root.",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenance",
        description="PROVENANCE terminal backend.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record")
    _add_common(record)
    source = record.add_mutually_exclusive_group(required=True)
    source.add_argument("--file")
    source.add_argument("--text")
    record.add_argument("--actor", required=True)
    record.add_argument("--operation", required=True)
    record.add_argument("--media-type")
    record.add_argument(
        "--digest-only",
        action="store_true",
        help="Record only content identity + metadata, not source bytes.",
    )

    inspect = subparsers.add_parser("inspect")
    _add_common(inspect)
    inspect.add_argument("--identity")

    verify = subparsers.add_parser("verify")
    _add_common(verify)

    finalize = subparsers.add_parser("finalize")
    _add_common(finalize)
    finalize.add_argument(
        "--scope",
        choices=("open", "closed"),
        default="closed",
    )

    export = subparsers.add_parser("export")
    _add_common(export)
    export.add_argument("--destination", required=True)

    package = subparsers.add_parser("package")
    _add_common(package)
    package.add_argument("--destination", required=True)

    sign_package = subparsers.add_parser("sign-package")
    sign_package.add_argument("--package", required=True)
    sign_package.add_argument("--key", required=True)
    sign_package.add_argument("--output", required=True)

    anchor_payload = subparsers.add_parser("anchor-payload")
    anchor_payload.add_argument("--package", required=True)
    anchor_payload.add_argument("--output", required=True)

    anchor_git = subparsers.add_parser("anchor-git")
    anchor_git.add_argument("--package", required=True)
    anchor_git.add_argument("--git-repo", required=True)
    anchor_git.add_argument("--commit", required=True)
    anchor_git.add_argument("--path", required=True)
    anchor_git.add_argument("--output", required=True)
    anchor_git.add_argument("--repository-hint")

    verify_assurance_parser = subparsers.add_parser("verify-assurance")
    verify_assurance_parser.add_argument("--package", required=True)
    verify_assurance_parser.add_argument("--signature")
    verify_assurance_parser.add_argument("--anchor")
    verify_assurance_parser.add_argument("--git-repo")

    redact = subparsers.add_parser("redact-disclosure")
    redact.add_argument("--package", required=True)
    redact.add_argument("--source", required=True)
    redact.add_argument(
        "--range",
        dest="ranges",
        action="append",
        required=True,
        help="Byte range START:END; may be supplied multiple times.",
    )
    redact.add_argument("--mask-byte", type=int, default=42)
    redact.add_argument("--output", required=True)

    verify_disclosure = subparsers.add_parser("verify-disclosure")
    verify_disclosure.add_argument("--disclosure", required=True)
    verify_disclosure.add_argument("--source-package")

    return parser


def _parse_redaction_ranges(values: list[str]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or value.count(":") != 1:
            raise CliError(
                f"--range[{index}] must use START:END"
            )
        start_text, end_text = value.split(":", 1)
        try:
            start = int(start_text, 10)
            end = int(end_text, 10)
        except ValueError as exc:
            raise CliError(
                f"--range[{index}] bounds must be decimal integers"
            ) from exc
        ranges.append((start, end))
    return ranges


def _load_record_source(args: argparse.Namespace) -> tuple[bytes, str, str]:
    if args.file is not None:
        path = Path(args.file).expanduser()
        if path.is_symlink():
            raise CliError("record source file must not be a symbolic link")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CliError(f"record source file cannot be read: {exc}") from exc
        media_type = args.media_type or "application/octet-stream"
        return data, media_type, str(path.resolve(strict=False))

    assert args.text is not None
    data = args.text.encode("utf-8")
    media_type = args.media_type or "text/plain; charset=utf-8"
    return data, media_type, "operator-supplied UTF-8 text"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "redact-disclosure":
            ranges = _parse_redaction_ranges(args.ranges)
            disclosure = create_redacted_disclosure(
                args.package,
                args.source,
                ranges,
                args.output,
                mask_byte=args.mask_byte,
            )
            verification = verify_selective_disclosure(
                disclosure.path,
                source_package=args.package,
            )
            if (
                not verification.integrity_verified
                or verification.lineage != "VERIFIED"
                or verification.transformation != "VERIFIED"
            ):
                raise CliError(
                    "new selective disclosure failed verification: "
                    + "; ".join(verification.errors)
                )
            result = {
                "output": str(disclosure.path),
                "disclosure_identity": disclosure.disclosure_identity,
                "source_content_identity": (
                    disclosure.source_content_identity
                ),
                "derivative_content_identity": (
                    disclosure.derivative_content_identity
                ),
                "derivation_event_identity": (
                    disclosure.derivation_event_identity
                ),
                "verification": verification.to_dict(),
            }
        elif args.command == "verify-disclosure":
            result = verify_selective_disclosure(
                args.disclosure,
                source_package=args.source_package,
            ).to_dict()
        elif args.command == "sign-package":
            record = create_signature_record(args.package, args.key)
            output = write_trust_record(args.output, record)
            verification = verify_signature_record(args.package, output)
            if verification.status != "VERIFIED":
                raise CliError(
                    "new signature record failed verification: "
                    + "; ".join(verification.errors)
                )
            result = {
                "output": str(output),
                "signature_identity": record["signature_identity"],
                "subject_identity": record["core"]["subject_identity"],
                "key_fingerprint": record["core"]["key_fingerprint"],
                "signature": verification.to_dict(),
            }
        elif args.command == "anchor-payload":
            output = write_git_anchor_payload(args.package, args.output)
            package_report = verify_forensic_package(args.package)
            if not package_report.integrity_verified:
                raise CliError("package failed verification before anchor payload")
            result = {
                "output": str(output),
                "subject_identity": package_report.package_identity,
            }
        elif args.command == "anchor-git":
            record = create_git_anchor_record(
                args.package,
                args.git_repo,
                args.commit,
                args.path,
                repository_hint=args.repository_hint,
            )
            output = write_trust_record(args.output, record)
            verification = verify_git_anchor_record(
                args.package,
                output,
                git_repo=args.git_repo,
            )
            if verification.status != "VERIFIED":
                raise CliError(
                    "new Git anchor record failed verification: "
                    + "; ".join(verification.errors)
                )
            result = {
                "output": str(output),
                "anchor_identity": record["anchor_identity"],
                "subject_identity": record["core"]["subject_identity"],
                "commit_oid": record["core"]["commit_oid"],
                "path": record["core"]["path"],
                "external_anchor": verification.to_dict(),
            }
        elif args.command == "verify-assurance":
            result = verify_assurance(
                args.package,
                signature_record=args.signature,
                anchor_record=args.anchor,
                git_repo=args.git_repo,
            ).to_dict()
        else:
            session = CliSession(args.store, args.custody)
            if args.command == "record":
                data, media_type, source_label = _load_record_source(args)
                result = session.record(
                    actor=args.actor,
                    operation=args.operation,
                    data=data,
                    media_type=media_type,
                    retain_content=not args.digest_only,
                    source_label=source_label,
                )
            elif args.command == "inspect":
                result = session.inspect(args.identity)
            elif args.command == "verify":
                result = session.verify()
            elif args.command == "finalize":
                result = session.finalize(scope=args.scope)
            elif args.command == "export":
                result = session.export(args.destination)
            elif args.command == "package":
                result = session.package(args.destination)
            else:
                raise CliError(f"unsupported command: {args.command}")
    except Exception as exc:
        print(
            _json_text(
                {
                    "ok": False,
                    "error": type(exc).__name__,
                    "detail": str(exc),
                }
            ),
            file=sys.stderr,
        )
        return 1

    print(_json_text({"ok": True, "result": result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
