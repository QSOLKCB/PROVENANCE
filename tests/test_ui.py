from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from provenance_core import (
    ClockAssurance,
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    sha256_identity,
)
from provenance_custody import ClockObservation, LocalCustodyLedger
from provenance_store import LocalEvidenceStore
from provenance_ui import build_view
from provenance_ui.server import _validate_bind_host, make_server


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


def _fixture(root: Path) -> tuple[Path, Path, str, str, str]:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    custody = LocalCustodyLedger(custody_root)

    artifact = store.put_artifact(
        b"Phase 9 read-only viewer evidence\n",
        media_type="text/plain",
        retain_content=True,
    )
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="operator:test",
            operation="phase9.capture",
            outputs=(artifact.content_identity,),
        )
    )
    store.put_event(event)
    snapshot = store.finalize(scope="closed")

    clock = ClockObservation(
        recorded_at="2026-09-29T11:30:00.000000Z",
        clock_source="test-fixture",
        clock_assurance=ClockAssurance.LOCAL,
    )
    custody.append(
        artifact.content_identity,
        CustodyAction.VERIFIED,
        actor="operator:test",
        source="phase9-test",
        clock=clock,
    )
    custody.append(
        event.event_identity,
        CustodyAction.VERIFIED,
        actor="operator:test",
        source="phase9-test",
        clock=clock,
    )
    custody.append(
        snapshot.manifest_identity,
        CustodyAction.VERIFIED,
        actor="operator:test",
        source="phase9-test",
        clock=clock,
    )
    return (
        store_root,
        custody_root,
        artifact.content_identity,
        event.event_identity,
        snapshot.manifest_identity,
    )


class ProvenanceUiTests(unittest.TestCase):
    def test_projection_is_read_only_and_separates_verification_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, artifact, event, manifest = _fixture(root)
            before_store = _fingerprint(store)
            before_custody = _fingerprint(custody)

            view = build_view(store, custody)

            self.assertEqual(view["authority"], "READ_ONLY_PRESENTATION")
            self.assertEqual(view["summary"]["manifest_identity"], manifest)
            self.assertEqual(view["verification"]["integrity"], "VERIFIED")
            self.assertEqual(view["verification"]["custody"], "VERIFIED")
            self.assertEqual(view["verification"]["signature"], "NOT_PRESENT")
            self.assertEqual(view["verification"]["replay"], "NOT_ATTEMPTED")
            self.assertEqual(view["artifacts"][0]["identity"], artifact)
            self.assertEqual(
                view["artifacts"][0]["verification"],
                {"integrity": "VERIFIED", "custody": "VERIFIED"},
            )
            self.assertEqual(view["events"][0]["identity"], event)
            self.assertTrue(
                any(gap["kind"] == "UNTIMED_EVENTS" for gap in view["gaps"])
            )
            self.assertEqual(before_store, _fingerprint(store))
            self.assertEqual(before_custody, _fingerprint(custody))

    def test_open_collection_and_missing_artifact_are_visible_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"
            store = LocalEvidenceStore(store_root)
            LocalCustodyLedger(custody_root)

            missing = sha256_identity(b"declared but unavailable")
            store.mark_missing(missing)
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="adapter:test",
                    operation="capture.gap",
                    outputs=(missing,),
                )
            )
            store.put_event(event)
            store.finalize(scope="open")

            view = build_view(store_root, custody_root)
            kinds = {gap["kind"] for gap in view["gaps"]}
            self.assertIn("OPEN_COLLECTION", kinds)
            self.assertIn("MISSING_ARTIFACT", kinds)
            self.assertIn("PARTIAL_CUSTODY_COVERAGE", kinds)
            self.assertEqual(view["verification"]["integrity"], "VERIFIED")
            self.assertEqual(view["verification"]["custody"], "NOT_PRESENT")

    def test_http_surface_is_get_head_only_and_does_not_mutate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, custody, *_ = _fixture(root)
            before_store = _fingerprint(store)
            before_custody = _fingerprint(custody)
            server = make_server(store, custody, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            base = f"http://{host}:{port}"
            try:
                with urlopen(base + "/api/view", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertTrue(payload["ok"])
                self.assertEqual(
                    payload["view"]["authority"],
                    "READ_ONLY_PRESENTATION",
                )

                request = Request(base + "/api/view", data=b"{}", method="POST")
                with self.assertRaises(HTTPError) as raised:
                    urlopen(request, timeout=5)
                self.assertEqual(raised.exception.code, 405)

                request = Request(base + "/api/view", method="HEAD")
                with urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            self.assertEqual(before_store, _fingerprint(store))
            self.assertEqual(before_custody, _fingerprint(custody))

    def test_non_loopback_binding_requires_explicit_operator_action(self) -> None:
        _validate_bind_host("127.0.0.1", False)
        _validate_bind_host("::1", False)
        with self.assertRaisesRegex(ValueError, "explicit"):
            _validate_bind_host("0.0.0.0", False)
        _validate_bind_host("0.0.0.0", True)


if __name__ == "__main__":
    unittest.main()
