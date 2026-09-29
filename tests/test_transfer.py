from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from provenance_core import (
    ClockAssurance,
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
)
from provenance_custody import ClockObservation, LocalCustodyLedger
from provenance_export import create_forensic_package
from provenance_store import LocalEvidenceStore
from provenance_transfer.protocol import (
    TransferError,
    create_transfer_bundle,
    receive_transfer,
)
from provenance_verify import (
    verify_transfer_bundle,
    verify_transfer_receipt,
)


def _key(path: Path) -> None:
    completed = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))


def _sender_package(root: Path) -> Path:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    custody = LocalCustodyLedger(custody_root)

    artifact = store.put_artifact(
        b"distributed custody evidence\n",
        media_type="text/plain",
        retain_content=True,
    )
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="sender-system",
            operation="distributed.capture",
            outputs=(artifact.content_identity,),
        )
    )
    store.put_event(event)
    snapshot = store.finalize(scope="closed")

    sender_clock = ClockObservation(
        recorded_at="2026-09-29T10:00:00.000000Z",
        clock_source="sender-local-clock",
        clock_assurance=ClockAssurance.LOCAL,
    )
    for subject in (
        artifact.content_identity,
        event.event_identity,
        snapshot.manifest_identity,
    ):
        custody.append(
            subject,
            CustodyAction.VERIFIED,
            actor="sender-system",
            source="sender-store",
            related_identity=(
                None
                if subject == snapshot.manifest_identity
                else snapshot.manifest_identity
            ),
            clock=sender_clock,
        )

    package = create_forensic_package(
        store_root,
        custody_root,
        root / "package",
    )
    return package.path


class DistributedCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise RuntimeError("Phase 15 tests require ssh-keygen")

    def test_offline_transfer_preserves_identity_and_partial_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)

            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            offered_at = ClockObservation(
                recorded_at="2030-01-01T00:00:00.000000Z",
                clock_source="sender-clock",
                clock_assurance=ClockAssurance.LOCAL,
            )
            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="org-a/system-1",
                destination_system="org-b/system-9",
                sender_key=sender_key,
                offered_at=offered_at,
            )
            bundle_report = verify_transfer_bundle(bundle.path)
            self.assertTrue(
                bundle_report.integrity_verified,
                bundle_report.errors,
            )
            self.assertEqual(bundle_report.ordering, "PARTIAL")
            self.assertEqual(bundle_report.sender_signature, "VERIFIED")
            self.assertEqual(
                bundle_report.source_package_verification,
                "VERIFIED",
            )

            # Simulate a network partition / sneaker-net handoff. The receiver
            # sees only a copied transfer bundle; no live sender service exists.
            offline_copy = receiver / "offline-transfer"
            shutil.copytree(bundle.path, offline_copy)
            shutil.rmtree(bundle.path)

            accepted_at = ClockObservation(
                # Intentionally earlier wall clock than offered_at. Causality
                # comes from offer -> receipt, not timestamp comparison.
                recorded_at="2025-01-01T00:00:00.000000Z",
                clock_source="receiver-clock",
                clock_assurance=ClockAssurance.LOCAL,
            )
            receipt = receive_transfer(
                offline_copy,
                receiver / "received-package",
                receiver / "receipt",
                receiver / "custody",
                receiver_system="org-b/system-9",
                receiver_key=receiver_key,
                accepted_at=accepted_at,
            )
            self.assertFalse(receipt.duplicate_delivery)

            report = verify_transfer_receipt(
                receipt.path,
                transfer_bundle=offline_copy,
                received_package=receiver / "received-package",
            )
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.ordering, "PARTIAL")
            self.assertEqual(report.receiver_signature, "VERIFIED")
            self.assertEqual(report.receiver_custody, "VERIFIED")
            self.assertEqual(report.transfer_bundle_binding, "VERIFIED")
            self.assertEqual(report.received_package_binding, "VERIFIED")
            self.assertEqual(
                report.package_identity,
                bundle.package_identity,
            )
            self.assertEqual(
                report.accepted_at["recorded_at"],
                "2025-01-01T00:00:00.000000Z",
            )
            self.assertEqual(
                bundle_report.offered_at["recorded_at"],
                "2030-01-01T00:00:00.000000Z",
            )
            edge_kinds = {edge[2] for edge in report.causal_edges}
            self.assertIn("offered_for_transfer", edge_kinds)
            self.assertIn("acknowledged_by_receiver", edge_kinds)

    def test_duplicate_delivery_is_idempotent_for_receiver_custody(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            first = receive_transfer(
                bundle.path,
                receiver / "package",
                receiver / "receipt",
                receiver / "custody",
                receiver_system="receiver",
                receiver_key=receiver_key,
            )
            ledger = LocalCustodyLedger(receiver / "custody")
            before = ledger.record_bytes_for_subject(
                bundle.package_identity
            )
            second = receive_transfer(
                bundle.path,
                receiver / "package",
                receiver / "receipt",
                receiver / "custody",
                receiver_system="receiver",
                receiver_key=receiver_key,
            )
            after = ledger.record_bytes_for_subject(
                bundle.package_identity
            )

            self.assertFalse(first.duplicate_delivery)
            self.assertTrue(second.duplicate_delivery)
            self.assertEqual(first.receipt_identity, second.receipt_identity)
            self.assertEqual(before, after)
            self.assertEqual(len(after), 3)

    def test_partial_receiver_custody_prefix_resumes_without_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            recovery_clock = ClockObservation(
                recorded_at="2026-09-29T12:34:56.000000Z",
                clock_source="receiver-recovery-clock",
                clock_assurance=ClockAssurance.LOCAL,
            )
            ledger = LocalCustodyLedger(receiver / "custody")
            first = ledger.append(
                bundle.package_identity,
                CustodyAction.CAPTURED,
                actor="receiver",
                source="sender",
                related_identity=bundle.offer_identity,
                clock=recovery_clock,
            )

            receipt = receive_transfer(
                bundle.path,
                receiver / "package",
                receiver / "receipt",
                receiver / "custody",
                receiver_system="receiver",
                receiver_key=receiver_key,
                accepted_at=ClockObservation(
                    recorded_at="2035-01-01T00:00:00.000000Z",
                    clock_source="should-not-replace-recovery-clock",
                    clock_assurance=ClockAssurance.LOCAL,
                ),
            )
            report = verify_transfer_receipt(
                receipt.path,
                transfer_bundle=bundle.path,
                received_package=receiver / "package",
            )
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(
                report.accepted_at["recorded_at"],
                recovery_clock.recorded_at,
            )
            records = ledger.record_bytes_for_subject(
                bundle.package_identity
            )
            self.assertEqual(len(records), 3)
            identities = {
                str(
                    __import__("json").loads(
                        raw.decode("utf-8")
                    )["custody_identity"]
                )
                for raw in records
            }
            self.assertIn(first.custody_identity, identities)

    def test_duplicate_delivery_refuses_to_hide_live_custody_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            receive_transfer(
                bundle.path,
                receiver / "package",
                receiver / "receipt",
                receiver / "custody",
                receiver_system="receiver",
                receiver_key=receiver_key,
            )
            shutil.rmtree(receiver / "custody")

            with self.assertRaisesRegex(
                TransferError,
                "live receiver custody ledger is unavailable",
            ):
                receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                )
            self.assertFalse((receiver / "custody").exists())

    def test_wrong_receiver_is_rejected_without_local_custody(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="sender",
                destination_system="intended-receiver",
                sender_key=sender_key,
            )
            with self.assertRaisesRegex(
                TransferError,
                "different destination system",
            ):
                receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="other-receiver",
                    receiver_key=receiver_key,
                )
            self.assertFalse((receiver / "custody").exists())
            self.assertFalse((receiver / "package").exists())
            self.assertFalse((receiver / "receipt").exists())

    def test_offer_tamper_breaks_transfer_before_receiver_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            offer = bundle.path / "offer.json"
            offer.write_bytes(offer.read_bytes() + b" ")

            report = verify_transfer_bundle(bundle.path)
            self.assertFalse(report.integrity_verified)
            with self.assertRaisesRegex(
                TransferError,
                "failed verification",
            ):
                receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                )
            self.assertFalse((receiver / "custody").exists())

    def test_receiver_receipt_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            receiver = root / "receiver"
            sender.mkdir()
            receiver.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package,
                sender / "transfer",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            receipt = receive_transfer(
                bundle.path,
                receiver / "package",
                receiver / "receipt",
                receiver / "custody",
                receiver_system="receiver",
                receiver_key=receiver_key,
            )
            receipt_json = receipt.path / "receipt.json"
            receipt_json.write_bytes(receipt_json.read_bytes() + b" ")

            report = verify_transfer_receipt(receipt.path)
            self.assertFalse(report.integrity_verified)


if __name__ == "__main__":
    unittest.main()
