from __future__ import annotations

import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from provenance_core import (
    EvidenceClass,
    EventCore,
    EventEnvelope,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from provenance_custody import LocalCustodyLedger
from provenance_export import create_forensic_package
from provenance_store import LocalEvidenceStore
from provenance_verify import (
    verify_bundle,
    verify_bundle_reference,
    verify_forensic_package,
    verify_forensic_package_reference,
)
from provenance_verify._parallel import ordered_bounded_map


def _make_snapshot(
    root: Path,
    *,
    artifact_count: int = 12,
    artifact_bytes: int = 128 * 1024,
) -> tuple[Path, list[str], list[str]]:
    store = LocalEvidenceStore(root / "store")
    artifact_ids: list[str] = []
    event_ids: list[str] = []

    for index in range(artifact_count):
        prefix = index.to_bytes(4, "big")
        payload = prefix + bytes([index % 251]) * (artifact_bytes - len(prefix))
        artifact = store.put_artifact(
            payload,
            media_type="application/octet-stream",
            retain_content=True,
        )
        artifact_ids.append(artifact.content_identity)
        event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="phase13:test",
                operation=f"performance.capture.{index}",
                outputs=(artifact.content_identity,),
            )
        )
        store.put_event(event)
        event_ids.append(event.event_identity)

    snapshot = store.finalize(scope="closed")
    return snapshot.path, artifact_ids, event_ids


def _artifact_path(snapshot: Path, identity: str) -> Path:
    return snapshot / "artifacts" / "sha256" / identity.split(":", 1)[1]


def _event_path(snapshot: Path, identity: str) -> Path:
    return (
        snapshot
        / "events"
        / "sha256"
        / f"{identity.split(':', 1)[1]}.json"
    )


class Phase13PerformanceTests(unittest.TestCase):
    def test_bounded_scheduler_preserves_order_and_observed_worker_cap(self) -> None:
        lock = threading.Lock()
        active = 0
        peak = 0

        def work(value: int) -> int:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.02)
                return value * value
            finally:
                with lock:
                    active -= 1

        values = list(range(18))
        result = ordered_bounded_map(
            work,
            values,
            max_workers=3,
        )

        self.assertEqual(result, [value * value for value in values])
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 3)

    def test_bundle_parallel_result_equals_serial_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _artifacts, _events = _make_snapshot(Path(tmp))

            reference = verify_bundle_reference(snapshot)
            optimized = verify_bundle(snapshot)

            self.assertEqual(optimized, reference)
            self.assertTrue(optimized.integrity_verified, optimized.errors)

    def test_bundle_parallel_failure_order_equals_serial_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, artifacts, events = _make_snapshot(Path(tmp))

            for identity in artifacts[:2]:
                path = _artifact_path(snapshot, identity)
                path.write_bytes(path.read_bytes() + b"tamper")

            event_path = _event_path(snapshot, events[-1])
            event = parse_canonical_json_bytes(event_path.read_bytes())
            event["core"]["operation"] = "tampered.operation"
            event_path.write_bytes(canonical_json_bytes(event))

            reference = verify_bundle_reference(snapshot)
            optimized = verify_bundle(snapshot)

            self.assertEqual(optimized, reference)
            self.assertFalse(optimized.integrity_verified)
            self.assertGreaterEqual(len(optimized.errors), 3)

    def test_package_parallel_result_equals_serial_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, _artifacts, _events = _make_snapshot(root)
            # Package producer works from the store root that owns the snapshot.
            custody = LocalCustodyLedger(root / "custody")
            self.assertTrue(custody.verify().integrity_verified)
            package = create_forensic_package(
                root / "store",
                root / "custody",
                root / "package",
            )

            reference = verify_forensic_package_reference(package.path)
            optimized = verify_forensic_package(package.path)

            self.assertEqual(optimized, reference)
            self.assertTrue(optimized.integrity_verified, optimized.errors)
            self.assertTrue(snapshot.is_dir())

    def test_package_parallel_failure_order_equals_serial_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _snapshot, _artifacts, _events = _make_snapshot(root)
            LocalCustodyLedger(root / "custody")
            package = create_forensic_package(
                root / "store",
                root / "custody",
                root / "package",
            )

            evidence_artifacts = sorted(
                path
                for path in (
                    package.path / "evidence" / "artifacts" / "sha256"
                ).iterdir()
                if path.is_file()
            )
            for path in evidence_artifacts[:2]:
                path.write_bytes(path.read_bytes() + b"tamper")

            reference = verify_forensic_package_reference(package.path)
            optimized = verify_forensic_package(package.path)

            self.assertEqual(optimized, reference)
            self.assertFalse(optimized.integrity_verified)

    @unittest.skipUnless(
        (os.cpu_count() or 1) >= 2,
        "effective overlap requires at least two logical CPUs",
    )
    def test_scheduler_overlap_is_not_inferred_from_worker_configuration(self) -> None:
        barrier = threading.Barrier(3)
        lock = threading.Lock()
        overlap = 0

        def work(value: int) -> int:
            nonlocal overlap
            try:
                barrier.wait(timeout=2)
            except threading.BrokenBarrierError:
                pass
            with lock:
                overlap += 1
            time.sleep(0.01)
            return value

        result = ordered_bounded_map(
            work,
            [1, 2, 3],
            max_workers=3,
        )
        self.assertEqual(result, [1, 2, 3])
        self.assertEqual(overlap, 3)


if __name__ == "__main__":
    unittest.main()
