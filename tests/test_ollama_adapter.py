from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

from provenance_adapters import OllamaAdapter
from provenance_core import EvidenceClass
from provenance_custody import LocalCustodyLedger
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


class _FakeOllamaHandler(BaseHTTPRequestHandler):
    received: bytes | None = None
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
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_bytes)))
        self.end_headers()
        self.wfile.write(self.response_bytes)

    def log_message(self, format: str, *args: object) -> None:
        return


class OllamaAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeOllamaHandler.received = None
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

    def test_phase5_adapter_rejects_non_loopback_hosts(self) -> None:
        with self.assertRaisesRegex(ValueError, "local-only"):
            OllamaAdapter("http://example.com:11434")

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
                "ollama:qwen2.5:0.5b",
            )


if __name__ == "__main__":
    unittest.main()
