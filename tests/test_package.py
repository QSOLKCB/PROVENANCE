from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from provenance_core import (
    ClockAssurance,
    CollectionStatus,
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    RetentionState,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    sha256_identity,
)
from provenance_custody import ClockObservation, LocalCustodyLedger
import provenance_export.package as package_module
from provenance_export import (
    ForensicPackageError,
    create_forensic_package,
)
from provenance_store import LocalEvidenceStore
from provenance_verify import forensic_package_identity, verify_forensic_package


def _fingerprint(root: Path) -> tuple[tuple[object, ...], ...]:
    rows: list[tuple[object, ...]] = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append((relative, "symlink", path.readlink().as_posix()))
        elif path.is_file():
            rows.append(
                (
                    relative,
                    "file",
                    info.st_mode,
                    info.st_size,
                    info.st_mtime_ns,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        else:
            rows.append((relative, "dir", info.st_mode, info.st_mtime_ns))
    return tuple(rows)


def _clock() -> ClockObservation:
    return ClockObservation(
        recorded_at="2026-09-29T13:00:00.000000Z",
        clock_source="phase11-test",
        clock_assurance=ClockAssurance.LOCAL,
    )


def _closed_fixture(root: Path) -> tuple[Path, Path, str]:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    custody = LocalCustodyLedger(custody_root)

    retained = store.put_artifact(
        b"portable retained evidence\n",
        media_type="text/plain",
        retain_content=True,
    )
    digest_only = store.put_artifact(
        b"digest-only evidence\n",
        media_type="text/plain",
        retain_content=False,
    )
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="adapter:phase11-test",
            operation="package.capture",
            inputs=(digest_only.content_identity,),
            outputs=(retained.content_identity,),
        )
    )
    store.put_event(event)
    snapshot = store.finalize(scope="closed")

    for subject in (
        retained.content_identity,
        digest_only.content_identity,
        event.event_identity,
        snapshot.manifest_identity,
    ):
        custody.append(
            subject,
            CustodyAction.VERIFIED,
            actor="provenance-verify:v1",
            source="phase11-fixture",
            related_identity=(
                None
                if subject == snapshot.manifest_identity
                else snapshot.manifest_identity
            ),
            clock=_clock(),
        )
    return store_root, custody_root, snapshot.manifest_identity


def _open_fixture(root: Path) -> tuple[Path, Path, str, str]:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    custody = LocalCustodyLedger(custody_root)

    missing = sha256_identity(b"known but unavailable")
    store.mark_missing(missing)
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="adapter:phase11-test",
            operation="package.gap",
            outputs=(missing,),
            collection_status=CollectionStatus.EVIDENCE_GAP_OPENED,
        )
    )
    store.put_event(event)
    snapshot = store.finalize(scope="open")
    custody.append(
        snapshot.manifest_identity,
        CustodyAction.VERIFIED,
        actor="provenance-verify:v1",
        source="phase11-fixture",
        clock=_clock(),
    )
    return store_root, custody_root, snapshot.manifest_identity, missing


class ForensicPackageTests(unittest.TestCase):
    def test_closed_package_moves_to_another_machine_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine_a = root / "machine-a"
            machine_b = root / "machine-b"
            machine_a.mkdir()
            machine_b.mkdir()
            store, custody, manifest = _closed_fixture(machine_a)

            before_store = _fingerprint(store)
            before_custody = _fingerprint(custody)
            package = create_forensic_package(
                store,
                custody,
                machine_a / "portable-package",
            )

            report = verify_forensic_package(package.path)
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.package_identity, package.package_identity)
            self.assertEqual(report.evidence_manifest_identity, manifest)
            self.assertEqual(report.evidence_scope, "closed")
            self.assertGreater(report.custody_record_count, 0)
            self.assertEqual(before_store, _fingerprint(store))
            self.assertEqual(before_custody, _fingerprint(custody))

            moved = machine_b / "received-package"
            shutil.copytree(package.path, moved)
            shutil.rmtree(package.path)

            moved_report = verify_forensic_package(moved)
            self.assertTrue(moved_report.integrity_verified, moved_report.errors)
            self.assertEqual(
                moved_report.package_identity,
                package.package_identity,
            )
            self.assertEqual(
                moved_report.evidence_manifest_identity,
                manifest,
            )

    def test_same_evidence_and_custody_produce_same_package_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)

            first = create_forensic_package(
                store,
                custody,
                root / "package-one",
            )
            second = create_forensic_package(
                store,
                custody,
                root / "package-two",
            )

            self.assertEqual(first.package_identity, second.package_identity)

    def test_open_package_is_finalized_but_declares_open_collection_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, manifest, missing = _open_fixture(root)
            package = create_forensic_package(
                store,
                custody,
                root / "open-package",
            )

            report = verify_forensic_package(package.path)
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.evidence_scope, "open")
            package_json = (
                package.path / "package.json"
            ).read_text(encoding="utf-8")
            self.assertIn('"package_state":"FINALIZED"', package_json)

            gaps = (package.path / "gaps.json").read_text(encoding="utf-8")
            self.assertIn("OPEN_COLLECTION", gaps)
            self.assertIn("MISSING_ARTIFACT", gaps)
            self.assertIn("EVENT_COLLECTION_STATUS", gaps)
            self.assertIn("PARTIAL_CUSTODY_COVERAGE", gaps)
            self.assertIn(missing, gaps)
            self.assertIn(manifest, gaps)

    def test_closed_digest_only_reference_is_explicit_gap_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)
            package = create_forensic_package(
                store,
                custody,
                root / "package",
            )
            gaps = (package.path / "gaps.json").read_text(encoding="utf-8")
            self.assertIn("DIGEST_ONLY_ARTIFACT", gaps)
            self.assertTrue(
                verify_forensic_package(package.path).integrity_verified
            )

    def test_zero_custody_records_are_valid_but_explicitly_declared(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"
            store = LocalEvidenceStore(store_root)
            LocalCustodyLedger(custody_root)

            artifact = store.put_artifact(
                b"evidence without custody\n",
                media_type="text/plain",
                retain_content=True,
            )
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="adapter:phase11-test",
                    operation="package.no-custody",
                    outputs=(artifact.content_identity,),
                )
            )
            store.put_event(event)
            store.finalize(scope="closed")

            package = create_forensic_package(
                store_root,
                custody_root,
                root / "package",
            )
            report = verify_forensic_package(package.path)
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.custody_record_count, 0)
            gaps = (package.path / "gaps.json").read_text(encoding="utf-8")
            self.assertIn("CUSTODY_NOT_PRESENT", gaps)
            self.assertTrue((package.path / "custody" / "sha256").is_dir())

    def test_tampered_member_and_extra_member_fail_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)
            package = create_forensic_package(
                store,
                custody,
                root / "package",
            )

            manifest_path = package.path / "evidence" / "manifest.json"
            manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
            report = verify_forensic_package(package.path)
            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "content identity mismatch" in error
                    for error in report.errors
                ),
                report.errors,
            )

            shutil.rmtree(package.path)
            package = create_forensic_package(
                store,
                custody,
                root / "package",
            )
            (package.path / "undeclared.txt").write_text(
                "not declared",
                encoding="utf-8",
            )
            report = verify_forensic_package(package.path)
            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "undeclared files" in error
                    for error in report.errors
                ),
                report.errors,
            )

    def test_declared_attachment_outside_v1_layout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)
            package = create_forensic_package(
                store,
                custody,
                root / "package",
            )

            rogue = b"declared but unsupported attachment\n"
            (package.path / "rogue.txt").write_bytes(rogue)
            package_path = package.path / "package.json"
            envelope = parse_canonical_json_bytes(package_path.read_bytes())
            core = envelope["core"]
            core["members"].append(
                {
                    "path": "rogue.txt",
                    "content_identity": sha256_identity(rogue),
                    "byte_count": len(rogue),
                }
            )
            core["members"].sort(key=lambda item: item["path"])
            envelope["package_identity"] = forensic_package_identity(core)
            package_path.write_bytes(canonical_json_bytes(envelope))

            report = verify_forensic_package(package.path)
            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "outside the v1 layout" in error
                    for error in report.errors
                ),
                report.errors,
            )

    def test_undeclared_empty_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)
            package = create_forensic_package(
                store,
                custody,
                root / "package",
            )
            (package.path / "surprise").mkdir()

            report = verify_forensic_package(package.path)
            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "undeclared directories" in error
                    for error in report.errors
                ),
                report.errors,
            )

    def test_symlink_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)
            package = create_forensic_package(
                store,
                custody,
                root / "package",
            )
            target = root / "outside.txt"
            target.write_text("outside", encoding="utf-8")
            (package.path / "link").symlink_to(target)

            report = verify_forensic_package(package.path)
            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "non-regular filesystem entries" in error
                    for error in report.errors
                ),
                report.errors,
            )

    def test_destination_race_does_not_replace_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)
            destination = root / "raced-package"
            original_rename = package_module._rename_noreplace_at
            raced_inode: int | None = None

            def create_raced_destination(
                source_dir_fd: int,
                source_name: str,
                destination_dir_fd: int,
                destination_name: str,
            ) -> None:
                nonlocal raced_inode
                os.mkdir(destination_name, dir_fd=destination_dir_fd)
                raced_inode = os.stat(
                    destination_name,
                    dir_fd=destination_dir_fd,
                    follow_symlinks=False,
                ).st_ino
                original_rename(
                    source_dir_fd,
                    source_name,
                    destination_dir_fd,
                    destination_name,
                )

            with mock.patch.object(
                package_module,
                "_rename_noreplace_at",
                side_effect=create_raced_destination,
            ):
                with self.assertRaisesRegex(
                    ForensicPackageError,
                    "destination must not already exist",
                ):
                    create_forensic_package(
                        store,
                        custody,
                        destination,
                    )

            self.assertTrue(destination.is_dir())
            self.assertEqual(destination.stat().st_ino, raced_inode)
            self.assertEqual(list(destination.iterdir()), [])
            self.assertFalse(
                any(
                    path.name.startswith(".raced-package.")
                    for path in root.iterdir()
                )
            )

    def test_destination_inside_live_store_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, _manifest = _closed_fixture(root)

            with self.assertRaisesRegex(
                ForensicPackageError,
                "outside the live store",
            ):
                create_forensic_package(
                    store,
                    custody,
                    store / "bad-package",
                )
            self.assertFalse((store / "bad-package").exists())


if __name__ == "__main__":
    unittest.main()
