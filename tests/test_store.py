from __future__ import annotations

import os
from pathlib import Path
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

            with self.assertRaisesRegex(StoreError, "different metadata"):
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
