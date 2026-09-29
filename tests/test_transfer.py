from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

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
from provenance_transfer.model import transfer_signature_identity
from provenance_transfer.protocol import (
    TransferError,
    create_transfer_bundle,
    receive_transfer,
)
from provenance_transfer.signing import (
    sign_transfer_envelope,
    verify_transfer_signature,
)
from provenance_verify import (
    verify_forensic_package,
    verify_transfer_bundle,
    verify_transfer_bundle_fd,
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


def _sender_fingerprint(transfer: Path) -> str:
    report = verify_transfer_bundle(transfer)
    if not report.integrity_verified or report.sender_key_fingerprint is None:
        raise RuntimeError("test transfer did not expose a verified sender fingerprint")
    return report.sender_key_fingerprint


def _sender_package(
    root: Path,
    *,
    content: bytes = b"distributed custody evidence\n",
) -> Path:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    custody = LocalCustodyLedger(custody_root)

    artifact = store.put_artifact(
        content,
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
                expected_sender_fingerprint=_sender_fingerprint(offline_copy),
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
                expected_sender_fingerprint=_sender_fingerprint(bundle.path),
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
                expected_sender_fingerprint=_sender_fingerprint(bundle.path),
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
                expected_sender_fingerprint=_sender_fingerprint(bundle.path),
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
                expected_sender_fingerprint=_sender_fingerprint(bundle.path),
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
                    expected_sender_fingerprint=_sender_fingerprint(bundle.path),
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
                    expected_sender_fingerprint=_sender_fingerprint(bundle.path),
                )
            self.assertFalse((receiver / "custody").exists())
            self.assertFalse((receiver / "package").exists())
            self.assertFalse((receiver / "receipt").exists())

    def test_receiver_state_roots_must_be_disjoint_from_transfer_and_each_other(self) -> None:
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

            with self.assertRaisesRegex(
                TransferError,
                "receiver custody destination must be outside the transfer bundle",
            ):
                receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "receipt",
                    bundle.path / "receiver-custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=_sender_fingerprint(bundle.path),
                )

            (receiver / "state").mkdir()
            with self.assertRaisesRegex(
                TransferError,
                "receipt and receiver custody destinations must be disjoint",
            ):
                receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "state" / "receipt",
                    receiver / "state",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=_sender_fingerprint(bundle.path),
                )

            self.assertFalse((bundle.path / "receiver-custody").exists())
            self.assertFalse((receiver / "package").exists())

    def test_transfer_destination_inside_source_package_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender = root / "sender"
            sender.mkdir()
            package = _sender_package(sender)
            sender_key = sender / "sender-key"
            _key(sender_key)

            with self.assertRaisesRegex(
                TransferError,
                "outside the source package",
            ):
                create_transfer_bundle(
                    package,
                    package / "nested-transfer",
                    source_system="sender",
                    destination_system="receiver",
                    sender_key=sender_key,
                )
            self.assertFalse((package / "nested-transfer").exists())

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
            sender_fingerprint = _sender_fingerprint(bundle.path)
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
                    expected_sender_fingerprint=sender_fingerprint,
                )
            self.assertFalse((receiver / "custody").exists())

    def test_receive_holds_verified_transfer_descriptor_during_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender_a = root / "sender-a"
            sender_b = root / "sender-b"
            receiver = root / "receiver"
            sender_a.mkdir()
            sender_b.mkdir()
            receiver.mkdir()
            package_a = _sender_package(
                sender_a,
                content=b"descriptor-pinned package A\n",
            )
            package_b = _sender_package(
                sender_b,
                content=b"path-replacement package B\n",
            )
            sender_key = root / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle_a = create_transfer_bundle(
                package_a,
                sender_a / "transfer-a",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            bundle_b = create_transfer_bundle(
                package_b,
                sender_b / "transfer-b",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            sender_fingerprint = _sender_fingerprint(bundle_a.path)
            saved_a = sender_a / "verified-transfer-a"

            real_verify_fd = verify_transfer_bundle_fd
            swapped = False

            def verify_then_swap(
                transfer_fd: int,
                *,
                expected_sender_fingerprint: str | None = None,
                _package_fd: int | None = None,
            ):
                nonlocal swapped
                report = real_verify_fd(
                    transfer_fd,
                    expected_sender_fingerprint=expected_sender_fingerprint,
                    _package_fd=_package_fd,
                )
                if not swapped:
                    os.rename(bundle_a.path, saved_a)
                    os.rename(bundle_b.path, bundle_a.path)
                    swapped = True
                return report

            with patch(
                "provenance_transfer.protocol.verify_transfer_bundle_fd",
                side_effect=verify_then_swap,
            ):
                receipt = receive_transfer(
                    bundle_a.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=sender_fingerprint,
                )

            copied = verify_forensic_package(receiver / "package")
            self.assertTrue(copied.integrity_verified, copied.errors)
            self.assertEqual(
                copied.package_identity,
                bundle_a.package_identity,
            )
            self.assertNotEqual(
                bundle_a.package_identity,
                bundle_b.package_identity,
            )
            self.assertEqual(
                receipt.package_identity,
                bundle_a.package_identity,
            )

    def test_receive_pins_embedded_package_child_before_bundle_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender_a = root / "sender-a"
            sender_b = root / "sender-b"
            receiver = root / "receiver"
            sender_a.mkdir()
            sender_b.mkdir()
            receiver.mkdir()
            package_a = _sender_package(
                sender_a,
                content=b"pinned embedded package A\n",
            )
            package_b = _sender_package(
                sender_b,
                content=b"replacement embedded package B\n",
            )
            sender_key = root / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle_a = create_transfer_bundle(
                package_a,
                sender_a / "transfer-a",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            bundle_b = create_transfer_bundle(
                package_b,
                sender_b / "transfer-b",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            sender_fingerprint = _sender_fingerprint(bundle_a.path)
            saved_package_a = sender_a / "verified-package-a"

            real_verify_fd = verify_transfer_bundle_fd
            swapped = False

            def verify_then_swap_child(
                transfer_fd: int,
                *,
                expected_sender_fingerprint: str | None = None,
                _package_fd: int | None = None,
            ):
                nonlocal swapped
                report = real_verify_fd(
                    transfer_fd,
                    expected_sender_fingerprint=expected_sender_fingerprint,
                    _package_fd=_package_fd,
                )
                if not swapped:
                    os.rename(bundle_a.path / "package", saved_package_a)
                    os.rename(
                        bundle_b.path / "package",
                        bundle_a.path / "package",
                    )
                    swapped = True
                return report

            with patch(
                "provenance_transfer.protocol.verify_transfer_bundle_fd",
                side_effect=verify_then_swap_child,
            ):
                receipt = receive_transfer(
                    bundle_a.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=sender_fingerprint,
                )

            copied = verify_forensic_package(receiver / "package")
            self.assertTrue(copied.integrity_verified, copied.errors)
            self.assertEqual(
                copied.package_identity,
                bundle_a.package_identity,
            )
            self.assertNotEqual(
                copied.package_identity,
                bundle_b.package_identity,
            )
            self.assertEqual(
                receipt.package_identity,
                bundle_a.package_identity,
            )

    def test_existing_received_package_swap_is_rejected_before_custody(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sender_a = root / "sender-a"
            sender_b = root / "sender-b"
            receiver = root / "receiver"
            sender_a.mkdir()
            sender_b.mkdir()
            receiver.mkdir()
            package_a = _sender_package(
                sender_a,
                content=b"existing received package A\n",
            )
            package_b = _sender_package(
                sender_b,
                content=b"replacement received package B\n",
            )
            sender_key = sender_a / "sender-key"
            receiver_key = receiver / "receiver-key"
            _key(sender_key)
            _key(receiver_key)

            bundle = create_transfer_bundle(
                package_a,
                sender_a / "transfer",
                source_system="sender",
                destination_system="receiver",
                sender_key=sender_key,
            )
            sender_fingerprint = _sender_fingerprint(bundle.path)
            shutil.copytree(package_a, receiver / "package")
            shutil.copytree(package_b, receiver / "replacement-package")

            from provenance_transfer import protocol as transfer_protocol

            real_verify_package_fd = transfer_protocol.verify_forensic_package_fd
            calls = 0

            def verify_then_swap_destination(package_fd: int):
                nonlocal calls
                calls += 1
                report = real_verify_package_fd(package_fd)
                if calls == 2:
                    os.rename(
                        receiver / "package",
                        receiver / "verified-package-a",
                    )
                    os.rename(
                        receiver / "replacement-package",
                        receiver / "package",
                    )
                return report

            with patch(
                "provenance_transfer.protocol.verify_forensic_package_fd",
                side_effect=verify_then_swap_destination,
            ):
                with self.assertRaisesRegex(
                    TransferError,
                    "filesystem identity changed after verification",
                ):
                    receive_transfer(
                        bundle.path,
                        receiver / "package",
                        receiver / "receipt",
                        receiver / "custody",
                        receiver_system="receiver",
                        receiver_key=receiver_key,
                        expected_sender_fingerprint=sender_fingerprint,
                    )

            self.assertFalse((receiver / "receipt").exists())
            self.assertFalse((receiver / "custody").exists())
            replacement = verify_forensic_package(receiver / "package")
            self.assertTrue(replacement.integrity_verified, replacement.errors)
            self.assertEqual(
                replacement.package_identity,
                verify_forensic_package(package_b).package_identity,
            )

    def test_concurrent_first_acceptance_uses_one_custody_sequence(self) -> None:
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
            sender_fingerprint = _sender_fingerprint(bundle.path)
            shutil.copytree(bundle.path / "package", receiver / "package")

            barrier = threading.Barrier(2)
            real_ensure = LocalCustodyLedger.ensure_action_sequence

            def synchronized_ensure(self, *args, **kwargs):
                barrier.wait(timeout=10)
                return real_ensure(self, *args, **kwargs)

            clocks = (
                ClockObservation(
                    recorded_at="2026-09-30T00:00:01.000000Z",
                    clock_source="receiver-a",
                    clock_assurance=ClockAssurance.LOCAL,
                ),
                ClockObservation(
                    recorded_at="2026-09-30T00:00:02.000000Z",
                    clock_source="receiver-b",
                    clock_assurance=ClockAssurance.LOCAL,
                ),
            )

            def accept(index: int):
                return receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / f"receipt-{index}",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=sender_fingerprint,
                    accepted_at=clocks[index],
                )

            with patch.object(
                LocalCustodyLedger,
                "ensure_action_sequence",
                new=synchronized_ensure,
            ):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(accept, (0, 1)))

            ledger = LocalCustodyLedger(receiver / "custody")
            records = ledger.record_bytes_for_subject(
                bundle.package_identity
            )
            self.assertEqual(len(records), 3)
            self.assertEqual(
                results[0].receipt_identity,
                results[1].receipt_identity,
            )
            for result in results:
                report = verify_transfer_receipt(
                    result.path,
                    transfer_bundle=bundle.path,
                    received_package=receiver / "package",
                    expected_sender_fingerprint=sender_fingerprint,
                )
                self.assertTrue(report.integrity_verified, report.errors)

    def test_concurrent_receipt_publish_collision_is_duplicate_delivery(self) -> None:
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
            sender_fingerprint = _sender_fingerprint(bundle.path)
            seed = receive_transfer(
                bundle.path,
                receiver / "package",
                receiver / "seed-receipt",
                receiver / "custody",
                receiver_system="receiver",
                receiver_key=receiver_key,
                expected_sender_fingerprint=sender_fingerprint,
            )
            shutil.rmtree(seed.path)

            barrier = threading.Barrier(2)
            from provenance_transfer import protocol as transfer_protocol

            real_publish = transfer_protocol._publish_directory

            def synchronized_publish(**kwargs):
                if kwargs.get("label") == "transfer receipt":
                    barrier.wait(timeout=10)
                return real_publish(**kwargs)

            def accept_again(_index: int):
                return receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=sender_fingerprint,
                )

            with patch(
                "provenance_transfer.protocol._publish_directory",
                side_effect=synchronized_publish,
            ):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(accept_again, (0, 1)))

            self.assertEqual(
                {result.duplicate_delivery for result in results},
                {False, True},
            )
            self.assertEqual(
                results[0].receipt_identity,
                results[1].receipt_identity,
            )
            ledger = LocalCustodyLedger(receiver / "custody")
            self.assertEqual(
                len(
                    ledger.record_bytes_for_subject(
                        bundle.package_identity
                    )
                ),
                3,
            )

    def test_receive_rejects_untrusted_sender_fingerprint_before_mutation(self) -> None:
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
                source_system="trusted-bank",
                destination_system="receiver",
                sender_key=sender_key,
            )
            with self.assertRaisesRegex(
                TransferError,
                "expected fingerprint",
            ):
                receive_transfer(
                    bundle.path,
                    receiver / "package",
                    receiver / "receipt",
                    receiver / "custody",
                    receiver_system="receiver",
                    receiver_key=receiver_key,
                    expected_sender_fingerprint=(
                        _sender_fingerprint(bundle.path) + "-wrong"
                    ),
                )

            self.assertFalse((receiver / "package").exists())
            self.assertFalse((receiver / "receipt").exists())
            self.assertFalse((receiver / "custody").exists())

    def test_signature_rejects_unsupported_canonicalization_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "sender-key"
            _key(key)
            envelope = {"payload": "canonicalization-regression"}
            subject_identity = "sha256:" + ("0" * 64)
            signature = sign_transfer_envelope(
                envelope,
                role="sender",
                subject_kind="transfer_offer",
                subject_identity=subject_identity,
                key_file=key,
            )
            signature["core"]["canonicalization"] = (
                "unsupported.canonicalization.v999"
            )
            signature["signature_identity"] = transfer_signature_identity(
                signature["core"]
            )

            ok, errors = verify_transfer_signature(
                envelope,
                signature,
                expected_role="sender",
                expected_subject_kind="transfer_offer",
                expected_subject_identity=subject_identity,
            )
            self.assertFalse(ok)
            self.assertTrue(
                any("canonicalization" in error for error in errors),
                errors,
            )

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
                expected_sender_fingerprint=_sender_fingerprint(bundle.path),
            )
            receipt_json = receipt.path / "receipt.json"
            receipt_json.write_bytes(receipt_json.read_bytes() + b" ")

            report = verify_transfer_receipt(receipt.path)
            self.assertFalse(report.integrity_verified)


if __name__ == "__main__":
    unittest.main()
