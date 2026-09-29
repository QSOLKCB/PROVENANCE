from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

from provenance_adapters import (
    ADAPTER_ARTIFACT_MEDIA_TYPE,
    AdapterContract,
    AdapterContractError,
    GenericHTTPAdapter,
    GenericHTTPAdapterError,
    ProcessAdapter,
    ProcessAdapterError,
    persist_observation,
)
from provenance_core import ClockAssurance, parse_canonical_json_bytes
from provenance_custody import ClockObservation, LocalCustodyLedger
from provenance_store import LocalEvidenceStore


class _HTTPFixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        if self.path == "/truncate":
            payload = b"abc"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "10")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True
            return
        if self.path == "/fail":
            payload = b"provider-failed\n"
            self.send_response(503)
        else:
            payload = body.upper()
            self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class GenericAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPFixture)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _url(self, path: str = "/") -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}{path}"

    @staticmethod
    def _clock() -> ClockObservation:
        return ClockObservation(
            recorded_at="2026-09-29T12:00:00.000000Z",
            clock_source="phase10-test",
            clock_assurance=ClockAssurance.LOCAL,
        )

    def test_two_structurally_different_adapters_share_core_contract(self) -> None:
        http = GenericHTTPAdapter(
            self._url(),
            headers={
                "Authorization": "Bearer super-secret",
                "X-Test": "visible-at-runtime-only",
            },
        )
        http_observation = http.observe(
            b"hello http",
            media_type="text/plain",
            declared_metadata={"model_alias": "not-provider-semantic"},
            extensions={"fixture": "http"},
        )

        process = ProcessAdapter()
        process_observation = process.observe(
            [
                sys.executable,
                "-c",
                (
                    "import sys;"
                    "data=sys.stdin.buffer.read();"
                    "sys.stdout.buffer.write(data[::-1]);"
                    "sys.stderr.buffer.write(b'process-stderr')"
                ),
            ],
            stdin=b"hello process",
            stdin_media_type="text/plain",
            extensions={"fixture": "process"},
        )

        self.assertEqual(http_observation.contract.source_kind, "http")
        self.assertEqual(process_observation.contract.source_kind, "process")
        self.assertNotEqual(
            http_observation.contract.adapter_id,
            process_observation.contract.adapter_id,
        )
        self.assertEqual(
            {event.core.to_dict()["schema"] for event in http_observation.events},
            {"provenance.event.v1"},
        )
        self.assertEqual(
            {event.core.to_dict()["schema"] for event in process_observation.events},
            {"provenance.event.v1"},
        )
        self.assertEqual(http_observation.outputs[0].data, b"HELLO HTTP")
        self.assertEqual(
            http_observation.input_events[0].core.evidence_class.value,
            "DECLARED",
        )
        self.assertEqual(
            http_observation.input_events[1].core.evidence_class.value,
            "OBSERVED",
        )
        self.assertEqual(
            http_observation.completion_event.core.evidence_class.value,
            "DERIVED",
        )
        self.assertTrue(
            all(
                item.media_type == ADAPTER_ARTIFACT_MEDIA_TYPE
                for item in http_observation.artifacts
            )
        )
        self.assertEqual(
            {item.label for item in process_observation.outputs},
            {"stdout", "stderr"},
        )
        self.assertEqual(process_observation.outputs[0].data, b"ssecorp olleh")
        self.assertEqual(process_observation.outputs[1].data, b"process-stderr")
        self.assertEqual(
            process_observation.input_events[0].core.evidence_class.value,
            "DECLARED",
        )
        self.assertEqual(
            process_observation.input_events[1].core.evidence_class.value,
            "OBSERVED",
        )
        self.assertEqual(
            process_observation.completion_event.core.evidence_class.value,
            "DERIVED",
        )
        self.assertTrue(
            all(
                item.media_type == ADAPTER_ARTIFACT_MEDIA_TYPE
                for item in process_observation.artifacts
            )
        )

        http_evidence_bytes = b"\n".join(
            item.data for item in http_observation.artifacts
        )
        self.assertNotIn(b"super-secret", http_evidence_bytes)
        self.assertNotIn(b"visible-at-runtime-only", http_evidence_bytes)

        http_metadata = parse_canonical_json_bytes(
            http_observation.metadata.data
        )
        self.assertEqual(
            http_metadata["extensions"]["provenance.adapter.http"]["fixture"],
            "http",
        )
        process_metadata = parse_canonical_json_bytes(
            process_observation.metadata.data
        )
        self.assertEqual(
            process_metadata["extensions"]["provenance.adapter.process"]["fixture"],
            "process",
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")

            first = persist_observation(
                http_observation,
                store,
                custody,
                clock=self._clock(),
            )
            second = persist_observation(
                process_observation,
                store,
                custody,
                clock=self._clock(),
            )

            self.assertTrue(first.snapshot.verification.integrity_verified)
            self.assertTrue(second.snapshot.verification.integrity_verified)
            self.assertTrue(store.verify_current().integrity_verified)
            self.assertTrue(custody.verify().integrity_verified)
            self.assertGreater(store.event_count, len(http_observation.events))
            self.assertGreater(
                store.artifact_count,
                len(http_observation.artifacts),
            )

    def test_http_failure_returns_persistable_failure_observation(self) -> None:
        adapter = GenericHTTPAdapter(self._url("/fail"))
        with self.assertRaises(GenericHTTPAdapterError) as raised:
            adapter.observe(b"request")
        observation = raised.exception.observation

        self.assertFalse(observation.succeeded)
        self.assertEqual(observation.failure.category, "http_status")
        self.assertEqual(observation.failure.code, 503)
        self.assertEqual(
            observation.completion_event.core.collection_status.value,
            "COLLECTION_FAILED",
        )
        self.assertEqual(observation.outputs[0].data, b"provider-failed\n")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stored = persist_observation(
                observation,
                LocalEvidenceStore(root / "store"),
                LocalCustodyLedger(root / "custody"),
                clock=self._clock(),
            )
            self.assertTrue(stored.snapshot.verification.integrity_verified)

    def test_truncated_http_body_is_retained_only_as_observed_prefix(self) -> None:
        adapter = GenericHTTPAdapter(self._url("/truncate"))
        with self.assertRaises(GenericHTTPAdapterError) as raised:
            adapter.observe(b"request")
        observation = raised.exception.observation

        self.assertEqual(observation.failure.category, "truncated_response")
        self.assertEqual(len(observation.outputs), 1)
        self.assertEqual(observation.outputs[0].label, "response_prefix")
        self.assertEqual(observation.outputs[0].data, b"abc")

    def test_process_nonzero_exit_returns_persistable_failure_observation(self) -> None:
        adapter = ProcessAdapter()
        with self.assertRaises(ProcessAdapterError) as raised:
            adapter.observe(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys;"
                        "sys.stdout.buffer.write(b'partial-output');"
                        "sys.exit(7)"
                    ),
                ]
            )
        observation = raised.exception.observation

        self.assertFalse(observation.succeeded)
        self.assertEqual(observation.failure.category, "nonzero_exit")
        self.assertEqual(observation.failure.code, 7)
        self.assertEqual(
            observation.completion_event.core.collection_status.value,
            "COLLECTION_FAILED",
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stored = persist_observation(
                observation,
                LocalEvidenceStore(root / "store"),
                LocalCustodyLedger(root / "custody"),
                clock=self._clock(),
            )
            self.assertTrue(stored.snapshot.verification.integrity_verified)

    def test_http_rejects_adapter_controlled_framing_headers(self) -> None:
        with self.assertRaisesRegex(ValueError, "adapter-controlled"):
            GenericHTTPAdapter(
                self._url(),
                headers={"Content-Type": "text/plain"},
            )
        with self.assertRaisesRegex(ValueError, "adapter-controlled"):
            GenericHTTPAdapter(
                self._url(),
                headers={"Content-Length": "999"},
            )

    def test_contract_rejects_non_namespaced_extensions(self) -> None:
        with self.assertRaisesRegex(
            AdapterContractError,
            "extension_namespace",
        ):
            AdapterContract(
                adapter_id="adapter:test/v1",
                source_kind="test",
                observation_boundary="test boundary",
                extension_namespace="vendor.test",
            )


if __name__ == "__main__":
    unittest.main()
