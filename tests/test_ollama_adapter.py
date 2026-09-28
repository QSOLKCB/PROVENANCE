from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

from provenance_adapters import ADAPTER_ID, OllamaAdapter, OllamaAdapterError
from provenance_core import (
    CollectionStatus,
    EvidenceClass,
    parse_canonical_json_bytes,
    sha256_identity,
)
from provenance_custody import LocalCustodyLedger
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


class _FakeOllamaHandler(BaseHTTPRequestHandler):
    received: bytes | None = None
    status = 200
    response_bytes = (
        b'{"model":"qwen2.5:0.5b","created_at":"2026-09-29T00:00:00Z",'
        b'"response":"PROVENANCE smoke response","done":true}'
    )

    def do_POST(self) -> None:
        if self.path != "/api/generate":
            self.send_error(404)
            return
        length = int(self.headers["Content-Length"])
        type(self).received = self.rfile.read(length)
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_bytes)))
        self.end_headers()
        self.wfile.write(self.response_bytes)

    def log_message(self, format: str, *args: object) -> None:
        return


class OllamaAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeOllamaHandler.received = None
        _FakeOllamaHandler.status = 200
        _FakeOllamaHandler.response_bytes = (
            b'{"model":"qwen2.5:0.5b","created_at":"2026-09-29T00:00:00Z",'
            b'"response":"PROVENANCE smoke response","done":true}'
        )
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _FakeOllamaHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_generate_captures_exact_exchange_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            observation = adapter.observe_generate(
                model="qwen2.5:0.5b",
                prompt="Return one short sentence.",
                options={"num_predict": 8, "temperature": 0},
                store=store,
                custody=custody,
            )

            request_bytes = _FakeOllamaHandler.received
            self.assertIsNotNone(request_bytes)
            assert request_bytes is not None
            request_payload = json.loads(request_bytes)
            self.assertEqual(request_payload["model"], "qwen2.5:0.5b")
            self.assertEqual(request_payload["stream"], False)

            request_path = (
                observation.snapshot.path
                / "artifacts"
                / "sha256"
                / observation.request.content_identity.split(":", 1)[1]
            )
            response_path = (
                observation.snapshot.path
                / "artifacts"
                / "sha256"
                / observation.response.content_identity.split(":", 1)[1]
            )

            self.assertEqual(request_path.read_bytes(), request_bytes)
            self.assertEqual(
                response_path.read_bytes(),
                _FakeOllamaHandler.response_bytes,
            )
            self.assertEqual(observation.declared_model, "qwen2.5:0.5b")
            self.assertEqual(
                observation.request_event.core.evidence_class,
                EvidenceClass.OBSERVED,
            )
            self.assertEqual(
                observation.response_event.core.evidence_class,
                EvidenceClass.OBSERVED,
            )
            self.assertEqual(observation.response_event.core.actor, ADAPTER_ID)
            self.assertEqual(
                observation.declaration_event.core.evidence_class,
                EvidenceClass.DECLARED,
            )
            self.assertTrue(
                observation.snapshot.verification.integrity_verified
            )
            self.assertTrue(
                verify_bundle(observation.snapshot.path).integrity_verified
            )
            self.assertTrue(custody.verify().integrity_verified)

    def _current_snapshot_path(
        self,
        store: LocalEvidenceStore,
    ) -> Path:
        self.assertIsNotNone(store.current_manifest_identity)
        assert store.current_manifest_identity is not None
        digest = store.current_manifest_identity.split(":", 1)[1]
        return store.root / "snapshots" / "sha256" / digest

    def _assert_failure_evidence(
        self,
        *,
        store: LocalEvidenceStore,
        custody: LocalCustodyLedger,
        response_bytes: bytes | None,
    ) -> None:
        snapshot = self._current_snapshot_path(store)
        report = verify_bundle(snapshot)
        self.assertTrue(report.integrity_verified, report.errors)
        self.assertTrue(custody.verify().integrity_verified)

        events_dir = snapshot / "events" / "sha256"
        events = []
        for path in events_dir.iterdir():
            value = parse_canonical_json_bytes(path.read_bytes())
            assert isinstance(value, dict)
            core = value["core"]
            assert isinstance(core, dict)
            events.append(core)

        failed = [
            core
            for core in events
            if core["collection_status"]
            == CollectionStatus.COLLECTION_FAILED.value
        ]
        self.assertEqual(len(failed), 1, events)

        if response_bytes is not None:
            response_identity = sha256_identity(response_bytes)
            response_path = (
                snapshot
                / "artifacts"
                / "sha256"
                / response_identity.split(":", 1)[1]
            )
            self.assertEqual(response_path.read_bytes(), response_bytes)
            self.assertIn(response_identity, failed[0]["outputs"])

    def test_malformed_response_is_retained_before_parse_failure(self) -> None:
        malformed = b'{"model":"qwen2.5:0.5b","response":'
        _FakeOllamaHandler.response_bytes = malformed

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            with self.assertRaisesRegex(
                OllamaAdapterError,
                "not valid JSON",
            ):
                adapter.observe_generate(
                    model="qwen2.5:0.5b",
                    prompt="hello",
                    store=store,
                    custody=custody,
                )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=malformed,
            )

    def test_duplicate_json_key_is_retained_and_rejected(self) -> None:
        duplicate = (
            b'{"model":"first","model":"second",'
            b'"response":"ok","done":true}'
        )
        _FakeOllamaHandler.response_bytes = duplicate

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            with self.assertRaisesRegex(
                OllamaAdapterError,
                "duplicate JSON key",
            ):
                adapter.observe_generate(
                    model="qwen2.5:0.5b",
                    prompt="hello",
                    store=store,
                    custody=custody,
                )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=duplicate,
            )

    def test_nonfinite_json_is_retained_and_rejected(self) -> None:
        nonfinite = (
            b'{"model":"qwen2.5:0.5b","response":"ok",'
            b'"done":true,"load_duration":NaN}'
        )
        _FakeOllamaHandler.response_bytes = nonfinite

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            with self.assertRaisesRegex(
                OllamaAdapterError,
                "non-finite JSON token",
            ):
                adapter.observe_generate(
                    model="qwen2.5:0.5b",
                    prompt="hello",
                    store=store,
                    custody=custody,
                )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=nonfinite,
            )

    def test_http_failure_body_is_retained_with_collection_failed(self) -> None:
        failure = b'{"error":"synthetic failure"}'
        _FakeOllamaHandler.status = 500
        _FakeOllamaHandler.response_bytes = failure

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            with self.assertRaisesRegex(
                OllamaAdapterError,
                "HTTP 500",
            ):
                adapter.observe_generate(
                    model="qwen2.5:0.5b",
                    prompt="hello",
                    store=store,
                    custody=custody,
                )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=failure,
            )

    def test_response_capture_custody_actor_is_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )
            observation = adapter.observe_generate(
                model="qwen2.5:0.5b",
                prompt="hello",
                store=store,
                custody=custody,
            )

            captured_actors = []
            records = custody.root / "records" / "sha256"
            for path in records.iterdir():
                value = parse_canonical_json_bytes(path.read_bytes())
                assert isinstance(value, dict)
                core = value["core"]
                assert isinstance(core, dict)
                if (
                    core["subject_identity"]
                    == observation.response.content_identity
                    and core["action"] == "CAPTURED"
                ):
                    captured_actors.append(core["actor"])

            self.assertEqual(captured_actors, [ADAPTER_ID])

    def test_phase5_adapter_rejects_non_loopback_hosts(self) -> None:
        with self.assertRaisesRegex(ValueError, "local-only"):
            OllamaAdapter("http://example.com:11434")

    def test_phase5_adapter_rejects_url_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "credentials"):
            OllamaAdapter("http://user:secret@127.0.0.1:11434")

    def test_response_model_is_declared_by_ollama_not_assumed_from_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            observation = adapter.observe_generate(
                model="requested-alias",
                prompt="hello",
                store=store,
                custody=custody,
            )

            self.assertEqual(observation.declared_model, "qwen2.5:0.5b")
            self.assertEqual(
                observation.declaration_event.core.actor,
                "ollama:local-endpoint",
            )


if __name__ == "__main__":
    unittest.main()
