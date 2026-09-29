from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from provenance_core import (
    EvidenceClass,
    EventCore,
    EventEnvelope,
    RetentionState,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from provenance_custody import LocalCustodyLedger
from provenance_export import create_forensic_package
from provenance_privacy.disclosure import (
    PrivacyError,
    create_redacted_disclosure,
)
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_selective_disclosure


SOURCE_BYTES = b"name=Alice;token=SECRET-12345;status=ok\n"
SECRET = b"SECRET-12345"


def _package_fixture(
    root: Path,
    *,
    retain_source: bool = True,
) -> tuple[Path, str]:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    LocalCustodyLedger(custody_root)

    artifact = store.put_artifact(
        SOURCE_BYTES,
        media_type="text/plain",
        retain_content=retain_source,
    )
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="phase14:test",
            operation="privacy.source",
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
    return package.path, artifact.content_identity


def _secret_range() -> tuple[int, int]:
    start = SOURCE_BYTES.index(SECRET)
    return start, start + len(SECRET)


def _all_file_bytes(root: Path) -> bytes:
    chunks: list[bytes] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            chunks.append(path.read_bytes())
    return b"\n".join(chunks)


class Phase14PrivacyTests(unittest.TestCase):
    def test_redacted_disclosure_withholds_source_and_verifies_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root)
            disclosure = create_redacted_disclosure(
                package,
                source_identity,
                [_secret_range()],
                root / "disclosure",
            )

            report = verify_selective_disclosure(disclosure.path)
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.lineage, "VERIFIED")
            self.assertEqual(
                report.transformation,
                "NOT_ATTEMPTED_SOURCE_WITHHELD",
            )
            self.assertEqual(
                report.source_package_binding,
                "NOT_ATTEMPTED",
            )
            self.assertFalse(report.source_content_disclosed)
            self.assertEqual(
                report.source_content_identity,
                source_identity,
            )
            self.assertNotEqual(
                report.derivative_content_identity,
                source_identity,
            )
            self.assertNotIn(SECRET, _all_file_bytes(disclosure.path))

            derivative = (disclosure.path / "derivative.bin").read_bytes()
            self.assertIn(b"************", derivative)
            self.assertNotIn(SECRET, derivative)

    def test_source_package_allows_exact_transform_recomputation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root)
            disclosure = create_redacted_disclosure(
                package,
                source_identity,
                [_secret_range()],
                root / "disclosure",
            )

            report = verify_selective_disclosure(
                disclosure.path,
                source_package=package,
            )
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.lineage, "VERIFIED")
            self.assertEqual(report.transformation, "VERIFIED")
            self.assertEqual(
                report.source_package_binding,
                "VERIFIED",
            )

    def test_wrong_source_package_does_not_invalidate_disclosure_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root / "a")
            disclosure = create_redacted_disclosure(
                package,
                source_identity,
                [_secret_range()],
                root / "disclosure",
            )

            other_root = root / "b"
            other_root.mkdir()
            other_store = LocalEvidenceStore(other_root / "store")
            LocalCustodyLedger(other_root / "custody")
            other_artifact = other_store.put_artifact(
                b"different source\n",
                media_type="text/plain",
                retain_content=True,
            )
            other_store.put_event(
                EventEnvelope.seal(
                    EventCore(
                        evidence_class=EvidenceClass.OBSERVED,
                        actor="phase14:test",
                        operation="other.source",
                        outputs=(other_artifact.content_identity,),
                    )
                )
            )
            other_store.finalize(scope="closed")
            other_package = create_forensic_package(
                other_root / "store",
                other_root / "custody",
                other_root / "package",
            )

            report = verify_selective_disclosure(
                disclosure.path,
                source_package=other_package.path,
            )
            self.assertTrue(report.integrity_verified)
            self.assertEqual(report.lineage, "VERIFIED")
            self.assertEqual(report.transformation, "FAILED")
            self.assertEqual(report.source_package_binding, "FAILED")
            self.assertTrue(report.errors)

    def test_tampered_derivative_fails_disclosure_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root)
            disclosure = create_redacted_disclosure(
                package,
                source_identity,
                [_secret_range()],
                root / "disclosure",
            )
            derivative = disclosure.path / "derivative.bin"
            derivative.write_bytes(derivative.read_bytes() + b"tamper")

            report = verify_selective_disclosure(disclosure.path)
            self.assertFalse(report.integrity_verified)
            self.assertEqual(report.lineage, "FAILED")

    def test_derivation_event_cannot_claim_derivative_is_original(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root)
            disclosure = create_redacted_disclosure(
                package,
                source_identity,
                [_secret_range()],
                root / "disclosure",
            )

            event_path = disclosure.path / "derivation_event.json"
            event = parse_canonical_json_bytes(event_path.read_bytes())
            event["core"]["evidence_class"] = EvidenceClass.OBSERVED.value
            event_path.write_bytes(canonical_json_bytes(event))

            report = verify_selective_disclosure(disclosure.path)
            self.assertFalse(report.integrity_verified)
            self.assertNotEqual(report.lineage, "VERIFIED")

    def test_digest_only_source_cannot_be_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(
                root,
                retain_source=False,
            )
            with self.assertRaisesRegex(
                PrivacyError,
                "requires source content retained",
            ):
                create_redacted_disclosure(
                    package,
                    source_identity,
                    [(0, 1)],
                    root / "disclosure",
                )

    def test_overlapping_redaction_ranges_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root)
            with self.assertRaisesRegex(
                ValueError,
                "must not overlap",
            ):
                create_redacted_disclosure(
                    package,
                    source_identity,
                    [(1, 5), (4, 8)],
                    root / "disclosure",
                )

    def test_noop_redaction_is_rejected_as_not_a_new_derivative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = b"*****\n"
            store = LocalEvidenceStore(root / "store")
            LocalCustodyLedger(root / "custody")
            artifact = store.put_artifact(
                source,
                media_type="text/plain",
                retain_content=True,
            )
            store.put_event(
                EventEnvelope.seal(
                    EventCore(
                        evidence_class=EvidenceClass.OBSERVED,
                        actor="phase14:test",
                        operation="noop.source",
                        outputs=(artifact.content_identity,),
                    )
                )
            )
            store.finalize(scope="closed")
            package = create_forensic_package(
                root / "store",
                root / "custody",
                root / "package",
            )

            with self.assertRaisesRegex(
                PrivacyError,
                "identical to the source",
            ):
                create_redacted_disclosure(
                    package.path,
                    artifact.content_identity,
                    [(0, 5)],
                    root / "disclosure",
                    mask_byte=ord("*"),
                )

    def test_source_witness_preserves_original_retention_without_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, source_identity = _package_fixture(root)
            disclosure = create_redacted_disclosure(
                package,
                source_identity,
                [_secret_range()],
                root / "disclosure",
            )

            source_record = parse_canonical_json_bytes(
                (
                    disclosure.path
                    / "source_artifact_record.json"
                ).read_bytes()
            )
            self.assertEqual(
                source_record["retention"],
                RetentionState.CONTENT_RETAINED.value,
            )
            envelope = parse_canonical_json_bytes(
                (disclosure.path / "disclosure.json").read_bytes()
            )
            self.assertEqual(
                envelope["core"]["source_disclosure_retention"],
                "DIGEST_ONLY",
            )
            self.assertFalse(
                (disclosure.path / "source.bin").exists()
            )
            self.assertEqual(
                source_record["content_identity"],
                source_identity,
            )


if __name__ == "__main__":
    unittest.main()
