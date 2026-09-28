from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from provenance_core import (
    EvidenceClass,
    EventCore,
    EventEnvelope,
    RetentionState,
    sha256_identity,
)
import provenance_store.local as store_module
from provenance_store import LocalEvidenceStore, StoreError
from provenance_verify import verify_bundle


def _event_for(content_identity: str, *, operation: str = "capture") -> EventEnvelope:
    return EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="store:test",
            operation=operation,
            outputs=(content_identity,),
        )
    )


def _content_object(store_root: Path, identity: str) -> Path:
    digest = identity.split(":", 1)[1]
    return store_root / "objects" / "artifacts" / "sha256" / digest


def _record_object(store_root: Path, identity: str) -> Path:
    digest = identity.split(":", 1)[1]
    return (
        store_root
        / "objects"
        / "artifact_records"
        / "sha256"
        / f"{digest}.json"
    )


def _event_object(store_root: Path, identity: str) -> Path:
    digest = identity.split(":", 1)[1]
    return store_root / "objects" / "events" / "sha256" / f"{digest}.json"


class LocalEvidenceStoreTests(unittest.TestCase):
    def test_finalize_uses_posix_record_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalEvidenceStore(Path(tmp) / "store")
            artifact = store.put_artifact(b"posix lock")
            store.put_event(_event_for(artifact.content_identity))
            real_lockf = store_module.fcntl.lockf

            with mock.patch.object(
                store_module.fcntl,
                "lockf",
                wraps=real_lockf,
            ) as lockf:
                snapshot = store.finalize()

            self.assertTrue(snapshot.verification.integrity_verified)
            commands = [call.args[1] for call in lockf.call_args_list]
            self.assertIn(store_module.fcntl.LOCK_EX, commands)
            self.assertIn(store_module.fcntl.LOCK_UN, commands)

    def test_record_finalize_reopen_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(
                b"retained evidence\n",
                media_type="text/plain",
            )
            event = _event_for(artifact.content_identity)
            store.put_event(event)

            snapshot = store.finalize()

            self.assertTrue(snapshot.verification.integrity_verified)
            self.assertEqual(
                snapshot.manifest_identity,
                store.current_manifest_identity,
            )
            self.assertTrue((root / "HEAD").is_file())
            self.assertTrue(verify_bundle(snapshot.path).integrity_verified)

            reopened = LocalEvidenceStore(root)
            self.assertEqual(
                reopened.current_manifest_identity,
                snapshot.manifest_identity,
            )
            self.assertEqual(reopened.artifact_count, 1)
            self.assertEqual(reopened.event_count, 1)
            self.assertTrue(reopened.verify_current().integrity_verified)

    def test_exact_content_deduplicates_without_duplicate_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)

            first = store.put_artifact(b"same", media_type="text/plain")
            second = store.put_artifact(b"same", media_type="text/plain")

            self.assertEqual(first.content_identity, second.content_identity)
            self.assertEqual(first.record_identity, second.record_identity)
            self.assertEqual(store.artifact_count, 1)
            objects = list((root / "objects" / "artifacts" / "sha256").iterdir())
            self.assertEqual([path.name for path in objects], [
                first.content_identity.split(":", 1)[1]
            ])

    def test_same_content_with_conflicting_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalEvidenceStore(Path(tmp) / "store")
            store.put_artifact(b"same", media_type="text/plain")

            with self.assertRaisesRegex(StoreError, "different state"):
                store.put_artifact(
                    b"same",
                    media_type="application/octet-stream",
                )

    def test_digest_only_snapshot_verifies_without_content_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(
                b"digest only",
                media_type="text/plain",
                retain_content=False,
            )
            store.put_event(_event_for(artifact.content_identity))

            snapshot = store.finalize()

            self.assertEqual(artifact.retention, RetentionState.DIGEST_ONLY)
            self.assertFalse(_content_object(root, artifact.content_identity).exists())
            self.assertTrue(snapshot.verification.integrity_verified)

    def test_open_snapshot_preserves_known_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalEvidenceStore(Path(tmp) / "store")
            missing = sha256_identity(b"known unavailable bytes")
            store.mark_missing(missing)
            store.put_event(_event_for(missing))

            snapshot = store.finalize(scope="open")

            self.assertTrue(snapshot.verification.integrity_verified)
            self.assertEqual(snapshot.verification.manifest_scope, "open")
            self.assertEqual(snapshot.verification.known_missing_artifacts, 1)

    def test_reopened_open_snapshot_can_resolve_prior_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            first_store = LocalEvidenceStore(root)
            missing_bytes = b"later recovered"
            missing_identity = sha256_identity(missing_bytes)
            first_store.mark_missing(missing_identity)
            first_store.put_event(_event_for(missing_identity))
            first = first_store.finalize(scope="open")
            self.assertEqual(first.verification.known_missing_artifacts, 1)

            reopened = LocalEvidenceStore(root)
            recovered = reopened.put_artifact(
                missing_bytes,
                media_type="application/octet-stream",
                retain_content=True,
            )
            second = reopened.finalize(scope="closed")

            self.assertEqual(recovered.content_identity, missing_identity)
            self.assertNotEqual(first.manifest_identity, second.manifest_identity)
            self.assertEqual(second.verification.known_missing_artifacts, 0)
            self.assertEqual(second.verification.manifest_scope, "closed")
            self.assertTrue(second.verification.integrity_verified)
            self.assertTrue(verify_bundle(first.path).integrity_verified)

    def test_interrupted_object_write_never_publishes_partial_final_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            real_write = os.write

            def partial_then_fail(fd: int, data: bytes) -> None:
                real_write(fd, data[: max(1, len(data) // 2)])
                raise OSError("injected interruption")

            with mock.patch.object(
                store_module,
                "_write_all",
                side_effect=partial_then_fail,
            ):
                with self.assertRaisesRegex(StoreError, "temporary object write failed"):
                    store.put_artifact(b"partial publication must not survive")

            digest = sha256_identity(
                b"partial publication must not survive"
            ).split(":", 1)[1]
            object_dir = root / "objects" / "artifacts" / "sha256"
            self.assertFalse((object_dir / digest).exists())
            self.assertEqual(
                [path for path in object_dir.iterdir() if path.name.endswith(".tmp")],
                [],
            )

    def test_existing_corrupt_content_object_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"original")
            content_path = _content_object(root, artifact.content_identity)
            content_path.write_bytes(b"corrupt")

            reopened = LocalEvidenceStore(root)
            with self.assertRaisesRegex(StoreError, "conflicts with expected"):
                reopened.put_artifact(b"original")

            self.assertEqual(content_path.read_bytes(), b"corrupt")

    def test_missing_object_prevents_finalization_and_head_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"must remain present")
            event = _event_for(artifact.content_identity)
            store.put_event(event)
            _record_object(root, artifact.record_identity).unlink()

            with self.assertRaisesRegex(StoreError, "required object is missing"):
                store.finalize()

            self.assertFalse((root / "HEAD").exists())
            self.assertIsNone(store.current_manifest_identity)

    def test_missing_event_object_prevents_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"event reference")
            event = _event_for(artifact.content_identity)
            store.put_event(event)
            _event_object(root, event.event_identity).unlink()

            with self.assertRaisesRegex(StoreError, "required object is missing"):
                store.finalize()

            self.assertFalse((root / "HEAD").exists())

    def test_publication_permission_failure_does_not_create_final_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)

            with mock.patch.object(
                store_module.os,
                "link",
                side_effect=PermissionError("injected permission failure"),
            ):
                with self.assertRaisesRegex(StoreError, "object publication failed"):
                    store.put_artifact(b"permission failure")

            digest = sha256_identity(b"permission failure").split(":", 1)[1]
            self.assertFalse(
                (root / "objects" / "artifacts" / "sha256" / digest).exists()
            )

    def test_head_failure_leaves_verified_snapshot_unreferenced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"head failure")
            store.put_event(_event_for(artifact.content_identity))
            real_rename = store_module.os.rename

            def fail_head_only(src, dst, *args, **kwargs):
                if dst == "HEAD":
                    raise PermissionError("injected HEAD failure")
                return real_rename(src, dst, *args, **kwargs)

            with mock.patch.object(
                store_module.os,
                "rename",
                side_effect=fail_head_only,
            ):
                with self.assertRaisesRegex(StoreError, "HEAD update failed"):
                    store.finalize()

            self.assertFalse((root / "HEAD").exists())
            self.assertIsNone(store.current_manifest_identity)
            snapshots = [
                path
                for path in (root / "snapshots" / "sha256").iterdir()
                if path.is_dir() and not path.name.startswith(".")
            ]
            self.assertEqual(len(snapshots), 1)
            self.assertTrue(verify_bundle(snapshots[0]).integrity_verified)

    def test_refinalizing_same_state_reuses_same_verified_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalEvidenceStore(Path(tmp) / "store")
            artifact = store.put_artifact(b"stable snapshot")
            store.put_event(_event_for(artifact.content_identity))

            first = store.finalize()
            second = store.finalize()

            self.assertEqual(first.manifest_identity, second.manifest_identity)
            self.assertEqual(first.path, second.path)
            self.assertTrue(second.verification.integrity_verified)

    def test_reopen_then_extend_creates_new_verified_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            first_store = LocalEvidenceStore(root)
            first_artifact = first_store.put_artifact(b"first")
            first_store.put_event(_event_for(first_artifact.content_identity))
            first = first_store.finalize()

            second_store = LocalEvidenceStore(root)
            second_artifact = second_store.put_artifact(b"second")
            second_store.put_event(
                _event_for(second_artifact.content_identity, operation="second")
            )
            second = second_store.finalize()

            self.assertNotEqual(first.manifest_identity, second.manifest_identity)
            self.assertEqual(second_store.artifact_count, 2)
            self.assertEqual(second_store.event_count, 2)
            self.assertTrue(second.verification.integrity_verified)
            self.assertTrue(first.path.exists())
            self.assertTrue(verify_bundle(first.path).integrity_verified)

    def test_symlinked_managed_event_parent_blocks_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            root = temp_root / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"managed parent")
            event = _event_for(artifact.content_identity)
            store.put_event(event)

            events_dir = root / "objects" / "events"
            outside_events = temp_root / "outside-events"
            events_dir.rename(outside_events)
            events_dir.symlink_to(outside_events, target_is_directory=True)

            with self.assertRaisesRegex(StoreError, "events.*unsafe"):
                store.finalize()

            self.assertFalse((root / "HEAD").exists())
            snapshots = [
                path
                for path in (root / "snapshots" / "sha256").iterdir()
                if path.is_dir() and not path.name.startswith(".")
            ]
            self.assertEqual(snapshots, [])

    def test_stale_store_instance_cannot_overwrite_newer_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            first = LocalEvidenceStore(root)
            stale = LocalEvidenceStore(root)

            first_artifact = first.put_artifact(b"first writer")
            first.put_event(_event_for(first_artifact.content_identity))
            first_snapshot = first.finalize()

            stale_artifact = stale.put_artifact(b"stale writer")
            stale.put_event(
                _event_for(stale_artifact.content_identity, operation="stale")
            )

            with self.assertRaisesRegex(StoreError, "HEAD changed"):
                stale.finalize()

            reopened = LocalEvidenceStore(root)
            self.assertEqual(
                reopened.current_manifest_identity,
                first_snapshot.manifest_identity,
            )
            self.assertEqual(reopened.artifact_count, 1)
            self.assertTrue(reopened.verify_current().integrity_verified)

    def test_relative_root_remains_bound_after_chdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            first_cwd = base / "first"
            second_cwd = base / "second"
            first_cwd.mkdir()
            second_cwd.mkdir()
            original_cwd = Path.cwd()
            try:
                os.chdir(first_cwd)
                store = LocalEvidenceStore("store")
                expected_root = (first_cwd / "store").absolute()

                os.chdir(second_cwd)
                artifact = store.put_artifact(b"bound root")
                store.put_event(_event_for(artifact.content_identity))
                snapshot = store.finalize()
            finally:
                os.chdir(original_cwd)

            self.assertEqual(store.root, expected_root)
            self.assertTrue((expected_root / "HEAD").is_file())
            self.assertTrue(snapshot.path.is_relative_to(expected_root))
            self.assertFalse((second_cwd / "store").exists())

    def test_retained_artifact_cannot_be_downgraded_to_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"retained")
            store.put_event(_event_for(artifact.content_identity))
            store.finalize()

            reopened = LocalEvidenceStore(root)
            with self.assertRaisesRegex(StoreError, "cannot be downgraded"):
                reopened.mark_missing(artifact.content_identity)

    def test_retained_artifact_cannot_be_downgraded_to_digest_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(
                b"retained",
                media_type="text/plain",
                retain_content=True,
            )
            store.put_event(_event_for(artifact.content_identity))
            store.finalize()

            reopened = LocalEvidenceStore(root)
            with self.assertRaisesRegex(StoreError, "cannot be downgraded"):
                reopened.put_artifact(
                    b"retained",
                    media_type="text/plain",
                    retain_content=False,
                )

    def test_digest_only_can_upgrade_to_retained_with_stable_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            digest_only = store.put_artifact(
                b"upgrade",
                media_type="text/plain",
                retain_content=False,
            )
            store.put_event(_event_for(digest_only.content_identity))
            first = store.finalize()
            self.assertTrue(first.verification.integrity_verified)

            reopened = LocalEvidenceStore(root)
            retained = reopened.put_artifact(
                b"upgrade",
                media_type="text/plain",
                retain_content=True,
            )
            second = reopened.finalize()

            self.assertEqual(retained.content_identity, digest_only.content_identity)
            self.assertEqual(retained.retention, RetentionState.CONTENT_RETAINED)
            self.assertNotEqual(first.manifest_identity, second.manifest_identity)
            self.assertTrue(second.verification.integrity_verified)

    def test_digest_only_upgrade_rejects_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(
                b"stable metadata",
                media_type="text/plain",
                retain_content=False,
            )
            store.put_event(_event_for(artifact.content_identity))
            store.finalize()

            reopened = LocalEvidenceStore(root)
            with self.assertRaisesRegex(StoreError, "stable metadata"):
                reopened.put_artifact(
                    b"stable metadata",
                    media_type="application/octet-stream",
                    retain_content=True,
                )

    def test_snapshot_files_do_not_share_writable_inodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            first_artifact = store.put_artifact(b"shared artifact")
            store.put_event(_event_for(first_artifact.content_identity))
            first = store.finalize()

            reopened = LocalEvidenceStore(root)
            second_artifact = reopened.put_artifact(b"second artifact")
            reopened.put_event(
                _event_for(second_artifact.content_identity, operation="second")
            )
            second = reopened.finalize()

            digest = first_artifact.content_identity.split(":", 1)[1]
            object_path = root / "objects" / "artifacts" / "sha256" / digest
            first_path = first.path / "artifacts" / "sha256" / digest
            second_path = second.path / "artifacts" / "sha256" / digest

            self.assertNotEqual(object_path.stat().st_ino, first_path.stat().st_ino)
            self.assertNotEqual(object_path.stat().st_ino, second_path.stat().st_ino)
            self.assertNotEqual(first_path.stat().st_ino, second_path.stat().st_ino)

            second_path.write_bytes(b"tampered newer snapshot")

            self.assertEqual(object_path.read_bytes(), b"shared artifact")
            self.assertEqual(first_path.read_bytes(), b"shared artifact")
            self.assertTrue(verify_bundle(first.path).integrity_verified)
            self.assertFalse(verify_bundle(second.path).integrity_verified)

    def test_head_rejects_snapshot_directory_with_different_manifest_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"identity binding")
            store.put_event(_event_for(artifact.content_identity))
            snapshot = store.finalize()

            fake_identity = sha256_identity(b"forged head")
            fake_digest = fake_identity.split(":", 1)[1]
            fake_snapshot = root / "snapshots" / "sha256" / fake_digest
            shutil.copytree(snapshot.path, fake_snapshot)
            (root / "HEAD").write_text(fake_identity + "\n", encoding="ascii")

            with self.assertRaisesRegex(
                StoreError,
                "manifest identity does not match expected identity",
            ):
                LocalEvidenceStore(root)

    def test_existing_snapshot_reuse_requires_matching_manifest_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"expected snapshot")
            event = _event_for(artifact.content_identity)
            store.put_event(event)

            core = store_module.ManifestCore.build(
                artifacts=store._artifacts.values(),
                events=store._events,
                scope="closed",
            )
            expected_manifest = store_module.ManifestEnvelope.seal(core)
            expected_digest = expected_manifest.manifest_identity.split(":", 1)[1]
            expected_path = root / "snapshots" / "sha256" / expected_digest

            other_root = Path(tmp) / "other"
            other = LocalEvidenceStore(other_root)
            other_artifact = other.put_artifact(b"other snapshot")
            other.put_event(_event_for(other_artifact.content_identity))
            other_snapshot = other.finalize()
            shutil.copytree(other_snapshot.path, expected_path)

            with self.assertRaisesRegex(
                StoreError,
                "manifest identity does not match expected identity",
            ):
                store.finalize()

            self.assertFalse((root / "HEAD").exists())

    def test_snapshot_directory_fsync_failure_prevents_head_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"durability")
            store.put_event(_event_for(artifact.content_identity))
            real_fsync_directory = store_module._fsync_directory
            calls = 0

            def fail_during_snapshot(fd: int) -> None:
                nonlocal calls
                calls += 1
                if calls > 1:
                    raise StoreError("injected directory fsync failure")
                real_fsync_directory(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=fail_during_snapshot,
            ):
                with self.assertRaisesRegex(StoreError, "fsync"):
                    store.finalize()

            self.assertFalse((root / "HEAD").exists())
            self.assertIsNone(store.current_manifest_identity)

    def test_prior_artifact_record_identity_is_verified_before_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(
                b"upgrade identity",
                media_type="text/plain",
                retain_content=False,
            )
            store.put_event(_event_for(artifact.content_identity))
            store.finalize()

            reopened = LocalEvidenceStore(root)
            tampered = store_module.ArtifactRecord(
                content_identity=artifact.content_identity,
                byte_count=artifact.byte_count,
                media_type="application/octet-stream",
                retention=RetentionState.DIGEST_ONLY,
            )
            _record_object(root, artifact.record_identity).write_bytes(
                store_module.canonical_json_bytes(tampered.to_dict())
            )

            with self.assertRaisesRegex(StoreError, "does not match its identity"):
                reopened.put_artifact(
                    b"upgrade identity",
                    media_type="application/octet-stream",
                    retain_content=True,
                )

    def test_recovered_snapshot_is_refsynced_before_head_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"recovered durability")
            store.put_event(_event_for(artifact.content_identity))

            real_rename = store_module.os.rename
            real_fsync_directory = store_module._fsync_directory
            snapshot_renamed = False
            injected = False

            def observe_rename(src, dst, *args, **kwargs):
                nonlocal snapshot_renamed
                result = real_rename(src, dst, *args, **kwargs)
                if dst != "HEAD":
                    snapshot_renamed = True
                return result

            def fail_post_rename_fsync(fd: int) -> None:
                nonlocal injected
                if snapshot_renamed and not injected:
                    injected = True
                    raise StoreError("injected post-rename parent fsync failure")
                real_fsync_directory(fd)

            with mock.patch.object(
                store_module.os,
                "rename",
                side_effect=observe_rename,
            ), mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=fail_post_rename_fsync,
            ):
                with self.assertRaisesRegex(StoreError, "post-rename"):
                    store.finalize()

            self.assertFalse((root / "HEAD").exists())
            finalized = [
                path
                for path in (root / "snapshots" / "sha256").iterdir()
                if path.is_dir() and not path.name.startswith(".")
            ]
            self.assertEqual(len(finalized), 1)
            self.assertTrue(verify_bundle(finalized[0]).integrity_verified)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=StoreError("retry must refsync snapshot parent"),
            ):
                with self.assertRaisesRegex(StoreError, "retry must refsync"):
                    store.finalize()

            self.assertFalse((root / "HEAD").exists())
            final = store.finalize()
            self.assertTrue(final.verification.integrity_verified)
            self.assertTrue((root / "HEAD").is_file())

    def test_reopen_revalidates_manifest_used_for_state_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"manifest swap")
            store.put_event(_event_for(artifact.content_identity))
            snapshot = store.finalize()

            empty_manifest = store_module.ManifestEnvelope.seal(
                store_module.ManifestCore.build(
                    artifacts=[],
                    events=[],
                    scope="closed",
                )
            )
            empty_bytes = store_module.canonical_json_bytes(
                empty_manifest.to_dict()
            )
            original_verify = LocalEvidenceStore._verify_snapshot_identity

            def verify_then_swap(self, path, expected_identity, *, label):
                report = original_verify(
                    self,
                    path,
                    expected_identity,
                    label=label,
                )
                if label == "HEAD snapshot":
                    (path / "manifest.json").write_bytes(empty_bytes)
                return report

            with mock.patch.object(
                LocalEvidenceStore,
                "_verify_snapshot_identity",
                new=verify_then_swap,
            ):
                with self.assertRaisesRegex(StoreError, "changed after verification"):
                    LocalEvidenceStore(root)

            self.assertEqual(
                snapshot.manifest_identity,
                store.current_manifest_identity,
            )

    def test_failed_snapshot_assembly_removes_temporary_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"x" * 1024)
            event = _event_for(artifact.content_identity)
            store.put_event(event)
            _event_object(root, event.event_identity).unlink()

            snapshots_dir = root / "snapshots" / "sha256"
            for _ in range(3):
                with self.assertRaisesRegex(StoreError, "required object is missing"):
                    store.finalize()
                leftovers = [
                    path
                    for path in snapshots_dir.iterdir()
                    if path.name.startswith(".") and path.name.endswith(".tmp")
                ]
                self.assertEqual(leftovers, [])

    def test_store_format_marker_is_persisted_and_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            LocalEvidenceStore(root)
            marker_path = root / "STORE_FORMAT"

            self.assertEqual(
                marker_path.read_text(encoding="ascii"),
                store_module.STORE_FORMAT + "\n",
            )

            marker_path.write_text(
                "provenance.local-store.v999\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(StoreError, "STORE_FORMAT"):
                LocalEvidenceStore(root)

    def test_ancestor_symlink_retarget_cannot_redirect_existing_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            first_parent = base / "first"
            second_parent = base / "second"
            first_parent.mkdir()
            second_parent.mkdir()
            alias = base / "alias"
            alias.symlink_to(first_parent, target_is_directory=True)

            store = LocalEvidenceStore(alias / "store")
            LocalEvidenceStore(second_parent / "store")

            alias.unlink()
            alias.symlink_to(second_parent, target_is_directory=True)

            artifact = store.put_artifact(b"pinned through ancestor")
            store.put_event(_event_for(artifact.content_identity))
            store.finalize()

            self.assertTrue((first_parent / "store" / "HEAD").is_file())
            self.assertFalse((second_parent / "store" / "HEAD").exists())
            self.assertEqual(
                store.root,
                (first_parent / "store").resolve(),
            )

    def test_reopen_rejects_missing_or_changed_object_pool_members(self) -> None:
        cases = ("content", "record", "event")

        for missing_kind in cases:
            with self.subTest(missing_kind=missing_kind):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "store"
                    store = LocalEvidenceStore(root)
                    artifact = store.put_artifact(b"pool completeness")
                    event = _event_for(artifact.content_identity)
                    store.put_event(event)
                    store.finalize()

                    if missing_kind == "content":
                        _content_object(root, artifact.content_identity).unlink()
                    elif missing_kind == "record":
                        _record_object(root, artifact.record_identity).unlink()
                    else:
                        _event_object(root, event.event_identity).unlink()

                    with self.assertRaisesRegex(StoreError, "object pool"):
                        LocalEvidenceStore(root)

    def test_dangling_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "missing-target"
            alias = base / "store-link"
            alias.symlink_to(target, target_is_directory=True)

            self.assertTrue(alias.is_symlink())
            self.assertFalse(alias.exists())
            with self.assertRaisesRegex(StoreError, "must not be a symbolic link"):
                LocalEvidenceStore(alias)

            self.assertFalse(target.exists())

    def test_object_publication_retry_refsyncs_recovered_directory_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="test",
                    operation="observe",
                )
            )

            event_path = _event_object(root, event.event_identity)
            real_fsync_directory = store_module._fsync_directory
            failed = False

            def fail_post_link_parent_sync(fd: int) -> None:
                nonlocal failed
                fd_path = (
                    os.readlink(f"/proc/self/fd/{fd}")
                    if Path("/proc/self/fd").is_dir()
                    else ""
                )
                if (
                    not failed
                    and fd_path.endswith("/objects/events/sha256")
                    and event_path.exists()
                ):
                    failed = True
                    raise StoreError("injected object directory fsync failure")
                real_fsync_directory(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=fail_post_link_parent_sync,
            ):
                with self.assertRaisesRegex(StoreError, "directory fsync"):
                    store.put_event(event)

            self.assertTrue(event_path.is_file())

            real_fsync_directory = store_module._fsync_directory
            with mock.patch.object(
                store_module,
                "_fsync_directory",
                wraps=real_fsync_directory,
            ) as sync:
                store.put_event(event)

            self.assertGreater(sync.call_count, 0)

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "requires Linux-style /proc/self/fd",
    )
    def test_snapshot_destination_setup_failure_does_not_leak_source_fd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"descriptor leak test")
            record_digest = artifact.record_identity.split(":", 1)[1]

            temp_snapshot = root / "snapshots" / "sha256" / "manual-temp"
            temp_snapshot.mkdir()
            before = len(list(Path("/proc/self/fd").iterdir()))

            original_open_dir_chain = store._open_dir_chain

            def fail_destination(root_fd: int, parts: tuple[str, ...], *, create: bool):
                if parts == ("artifact_records", "sha256"):
                    raise StoreError("injected destination setup failure")
                return original_open_dir_chain(root_fd, parts, create=create)

            with store._root_fd() as root_fd:
                temp_fd = os.open(temp_snapshot, store_module._directory_flags())
                try:
                    with mock.patch.object(
                        store,
                        "_open_dir_chain",
                        side_effect=fail_destination,
                    ):
                        with self.assertRaisesRegex(
                            StoreError,
                            "destination setup failure",
                        ):
                            store._copy_object_into_snapshot(
                                root_fd,
                                temp_fd,
                                source_category=(
                                    "objects",
                                    "artifact_records",
                                    "sha256",
                                ),
                                source_name=record_digest + ".json",
                                destination_category=("artifact_records", "sha256"),
                                destination_name=record_digest + ".json",
                            )
                finally:
                    os.close(temp_fd)

            after = len(list(Path("/proc/self/fd").iterdir()))
            self.assertEqual(after, before)

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "requires Linux-style /proc/self/fd",
    )
    def test_pool_validation_setup_failure_does_not_leak_parent_or_member_fds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"pool fd leak")
            store.put_event(_event_for(artifact.content_identity))
            snapshot = store.finalize()

            before = len(list(Path("/proc/self/fd").iterdir()))
            with store._root_fd() as root_fd:
                snapshot_fd = os.open(snapshot.path, store_module._directory_flags())
                try:
                    original_open_dir_chain = store._open_dir_chain

                    def fail_snapshot_parent(
                        fd: int,
                        parts: tuple[str, ...],
                        *,
                        create: bool,
                    ):
                        if parts == ("artifact_records", "sha256") and fd == snapshot_fd:
                            raise StoreError("injected snapshot parent failure")
                        return original_open_dir_chain(fd, parts, create=create)

                    with mock.patch.object(
                        store,
                        "_open_dir_chain",
                        side_effect=fail_snapshot_parent,
                    ):
                        with self.assertRaisesRegex(
                            StoreError,
                            "snapshot parent failure",
                        ):
                            store._assert_pool_member_matches_snapshot(
                                root_fd,
                                snapshot_fd,
                                pool_category=(
                                    "objects",
                                    "artifact_records",
                                    "sha256",
                                ),
                                pool_name=artifact.record_identity.split(":", 1)[1]
                                + ".json",
                                snapshot_category=("artifact_records", "sha256"),
                                snapshot_name=artifact.record_identity.split(":", 1)[1]
                                + ".json",
                                label="artifact record",
                                member_kind="artifact_record",
                                expected_identity=artifact.record_identity,
                            )
                finally:
                    os.close(snapshot_fd)

            after = len(list(Path("/proc/self/fd").iterdir()))
            self.assertEqual(after, before)

    def test_new_store_root_ancestors_are_fsynced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            root = base / "new-parent" / "store"
            real_sync = store_module._fsync_directory
            synced: set[tuple[int, int]] = set()

            def record_sync(fd: int) -> None:
                st = os.fstat(fd)
                synced.add((st.st_dev, st.st_ino))
                real_sync(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=record_sync,
            ):
                LocalEvidenceStore(root)

            base_stat = base.stat()
            parent_stat = (base / "new-parent").stat()
            self.assertIn((base_stat.st_dev, base_stat.st_ino), synced)
            self.assertIn((parent_stat.st_dev, parent_stat.st_ino), synced)

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "requires Linux-style /proc/self/fd",
    )
    def test_managed_directory_retry_refsyncs_existing_child_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            real_sync = store_module._fsync_directory
            failed = False

            def fail_artifacts_parent_once(fd: int) -> None:
                nonlocal failed
                path = os.readlink(f"/proc/self/fd/{fd}")
                if path.endswith("/objects/artifacts") and not failed:
                    failed = True
                    raise StoreError("injected managed-directory fsync failure")
                real_sync(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=fail_artifacts_parent_once,
            ):
                with self.assertRaisesRegex(StoreError, "managed-directory"):
                    LocalEvidenceStore(root)

            self.assertTrue(
                (root / "objects" / "artifacts" / "sha256").is_dir()
            )

            synced_paths: list[str] = []

            def record_sync(fd: int) -> None:
                synced_paths.append(os.readlink(f"/proc/self/fd/{fd}"))
                real_sync(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=record_sync,
            ):
                LocalEvidenceStore(root)

            self.assertTrue(
                any(path.endswith("/objects/artifacts") for path in synced_paths),
                synced_paths,
            )

    def test_recovered_snapshot_reuse_rejects_missing_pool_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"recovered snapshot pool")
            store.put_event(_event_for(artifact.content_identity))

            with mock.patch.object(
                store,
                "_update_head",
                side_effect=StoreError("injected HEAD failure"),
            ):
                with self.assertRaisesRegex(StoreError, "HEAD failure"):
                    store.finalize()

            self.assertFalse((root / "HEAD").exists())
            _content_object(root, artifact.content_identity).unlink()

            with self.assertRaisesRegex(StoreError, "object pool"):
                store.finalize()

            self.assertFalse((root / "HEAD").exists())

    def test_reopen_rejects_post_verification_extra_manifest_envelope_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"extra envelope field")
            store.put_event(_event_for(artifact.content_identity))
            store.finalize()

            original_verify = LocalEvidenceStore._verify_snapshot_identity

            def verify_then_add_field(
                self,
                path: Path,
                expected_identity: str,
                *,
                label: str,
            ):
                report = original_verify(
                    self,
                    path,
                    expected_identity,
                    label=label,
                )
                if label == "HEAD snapshot":
                    envelope = store_module.parse_canonical_json_bytes(
                        (path / "manifest.json").read_bytes()
                    )
                    assert isinstance(envelope, dict)
                    envelope["unexpected"] = "field"
                    (path / "manifest.json").write_bytes(
                        store_module.canonical_json_bytes(envelope)
                    )
                return report

            with mock.patch.object(
                LocalEvidenceStore,
                "_verify_snapshot_identity",
                new=verify_then_add_field,
            ):
                with self.assertRaisesRegex(
                    StoreError,
                    "envelope has unexpected fields",
                ):
                    LocalEvidenceStore(root)

    def test_reopen_binds_retained_content_identity_to_compared_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"descriptor-bound content")
            store.put_event(_event_for(artifact.content_identity))
            snapshot = store.finalize()

            digest = artifact.content_identity.split(":", 1)[1]
            snapshot_content = snapshot.path / "artifacts" / "sha256" / digest
            pool_content = _content_object(root, artifact.content_identity)
            original_verify = LocalEvidenceStore._verify_snapshot_identity

            def verify_then_mutate_both(
                self,
                path: Path,
                expected_identity: str,
                *,
                label: str,
            ):
                report = original_verify(
                    self,
                    path,
                    expected_identity,
                    label=label,
                )
                if label == "HEAD snapshot":
                    tampered = b"same tampered bytes"
                    snapshot_content.write_bytes(tampered)
                    pool_content.write_bytes(tampered)
                return report

            with mock.patch.object(
                LocalEvidenceStore,
                "_verify_snapshot_identity",
                new=verify_then_mutate_both,
            ):
                with self.assertRaisesRegex(
                    StoreError,
                    "expected content identity",
                ):
                    LocalEvidenceStore(root)

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "requires Linux-style /proc/self/fd",
    )
    def test_root_ancestor_retry_refsyncs_surviving_created_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            root = base / "new-parent" / "store"
            real_sync = store_module._fsync_directory
            failed = False

            def fail_base_after_parent_creation(fd: int) -> None:
                nonlocal failed
                fd_path = os.readlink(f"/proc/self/fd/{fd}")
                if (
                    not failed
                    and Path(fd_path) == base
                    and (base / "new-parent").exists()
                ):
                    failed = True
                    raise StoreError("injected ancestor durability failure")
                real_sync(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=fail_base_after_parent_creation,
            ):
                with self.assertRaisesRegex(StoreError, "ancestor durability"):
                    LocalEvidenceStore(root)

            self.assertTrue((base / "new-parent").is_dir())
            self.assertFalse(root.exists())

            synced_paths: list[Path] = []

            def record_sync(fd: int) -> None:
                synced_paths.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
                real_sync(fd)

            with mock.patch.object(
                store_module,
                "_fsync_directory",
                side_effect=record_sync,
            ):
                store = LocalEvidenceStore(root)
                artifact = store.put_artifact(b"ancestor retry")
                store.put_event(_event_for(artifact.content_identity))
                store.finalize()

            self.assertIn(base, synced_paths)
            self.assertTrue((root / "HEAD").is_file())

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "requires Linux-style /proc/self/fd",
    )
    def test_store_format_retry_refsyncs_existing_marker_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            root.mkdir()
            real_fsync = store_module.os.fsync
            failed = False

            def fail_marker_data_sync(fd: int) -> None:
                nonlocal failed
                fd_path = Path(os.readlink(f"/proc/self/fd/{fd}"))
                if (
                    not failed
                    and fd_path.name == "STORE_FORMAT"
                    and fd_path.parent == root
                ):
                    failed = True
                    raise OSError("injected marker data fsync failure")
                real_fsync(fd)

            with mock.patch.object(
                store_module.os,
                "fsync",
                side_effect=fail_marker_data_sync,
            ):
                with self.assertRaisesRegex(StoreError, "STORE_FORMAT"):
                    LocalEvidenceStore(root)

            marker_path = root / "STORE_FORMAT"
            self.assertTrue(marker_path.is_file())
            self.assertEqual(
                marker_path.read_text(encoding="ascii"),
                store_module.STORE_FORMAT + "\n",
            )

            fsynced_files: list[tuple[int, int]] = []

            def record_fsync(fd: int) -> None:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode):
                    fsynced_files.append((st.st_dev, st.st_ino))
                real_fsync(fd)

            with mock.patch.object(
                store_module.os,
                "fsync",
                side_effect=record_fsync,
            ):
                store = LocalEvidenceStore(root)
                artifact = store.put_artifact(b"marker retry")
                store.put_event(_event_for(artifact.content_identity))
                store.finalize()

            marker_stat = marker_path.stat()
            self.assertIn(
                (marker_stat.st_dev, marker_stat.st_ino),
                fsynced_files,
            )

    def test_corrupt_head_snapshot_is_rejected_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            store = LocalEvidenceStore(root)
            artifact = store.put_artifact(b"tamper after finalize")
            store.put_event(_event_for(artifact.content_identity))
            snapshot = store.finalize()

            retained = (
                snapshot.path
                / "artifacts"
                / "sha256"
                / artifact.content_identity.split(":", 1)[1]
            )
            retained.write_bytes(b"tampered")

            with self.assertRaisesRegex(
                StoreError,
                "HEAD snapshot failed independent verification",
            ):
                LocalEvidenceStore(root)


if __name__ == "__main__":
    unittest.main()
