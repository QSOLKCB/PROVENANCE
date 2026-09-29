from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client as http_client
import json
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from unittest import mock

import provenance_adapters.ollama as ollama_module
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
    request_count = 0
    status = 200
    content_length_override: int | None = None
    echo_request = False
    response_bytes = (
        b'{"model":"qwen2.5:0.5b","created_at":"2026-09-29T00:00:00Z",'
        b'"response":"PROVENANCE smoke response","done":true}'
    )

    def do_POST(self) -> None:
        if self.path != "/api/generate":
            self.send_error(404)
            return
        length = int(self.headers["Content-Length"])
        received = self.rfile.read(length)
        type(self).received = received
        type(self).request_count += 1
        body = received if type(self).echo_request else type(self).response_bytes
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        advertised = (
            type(self).content_length_override
            if type(self).content_length_override is not None
            else len(body)
        )
        self.send_header("Content-Length", str(advertised))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _multiprocess_observe_worker(
    store_root: str,
    custody_root: str,
    base_url: str,
    start_event,
    ready_queue,
    result_queue,
) -> None:
    try:
        store = LocalEvidenceStore(Path(store_root))
        custody = LocalCustodyLedger(Path(custody_root))
        adapter = OllamaAdapter(base_url, timeout_seconds=5)
        ready_queue.put("ready")
        if not start_event.wait(timeout=10):
            result_queue.put(("error", "start event timeout"))
            return

        observation = adapter.observe_generate(
            model="qwen2.5:0.5b",
            prompt="same multiprocess request",
            store=store,
            custody=custody,
        )
        result_queue.put(
            ("ok", observation.snapshot.manifest_identity)
        )
    except BaseException as exc:
        result_queue.put(
            ("error", f"{type(exc).__name__}: {exc}")
        )


class OllamaAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeOllamaHandler.received = None
        _FakeOllamaHandler.request_count = 0
        _FakeOllamaHandler.status = 200
        _FakeOllamaHandler.content_length_override = None
        _FakeOllamaHandler.echo_request = False
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
        failure_category: str | None = None,
        failure_status: int | None = None,
    ) -> dict[str, object]:
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

        detail: dict[str, object] | None = None
        for identity in failed[0]["outputs"]:
            artifact_path = (
                snapshot
                / "artifacts"
                / "sha256"
                / str(identity).split(":", 1)[1]
            )
            raw = artifact_path.read_bytes()
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                isinstance(value, dict)
                and value.get("schema") == "provenance.ollama-failure.v1"
            ):
                detail = value
                break

        self.assertIsNotNone(detail, failed[0])
        assert detail is not None
        if failure_category is not None:
            self.assertEqual(detail["category"], failure_category)
        if failure_status is not None:
            self.assertEqual(detail["http_status"], failure_status)
        return detail

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

            detail = self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=failure,
                failure_category="http_error",
                failure_status=500,
            )
            self.assertIn("HTTP 500", str(detail["detail"]))

    def test_truncated_http_response_retains_partial_bytes_and_failure(self) -> None:
        partial = b"{}"
        _FakeOllamaHandler.response_bytes = partial
        _FakeOllamaHandler.content_length_override = 10

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
                "truncated",
            ):
                adapter.observe_generate(
                    model="m",
                    prompt="p",
                    store=store,
                    custody=custody,
                )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=partial,
                failure_category="incomplete_read",
                failure_status=200,
            )

    def test_excessive_json_nesting_finalizes_parse_failure(self) -> None:
        nested = (
            b'{"model":"m","response":"ok","done":true,"extra":'
            + b"[" * 2000
            + b"0"
            + b"]" * 2000
            + b"}"
        )
        _FakeOllamaHandler.response_bytes = nested

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            real_json_loads = json.loads

            def fail_only_nested_response(value, *args, **kwargs):
                if value == nested.decode("utf-8"):
                    raise RecursionError("synthetic parser depth limit")
                return real_json_loads(value, *args, **kwargs)

            with mock.patch.object(
                ollama_module.json,
                "loads",
                side_effect=fail_only_nested_response,
            ):
                with self.assertRaisesRegex(
                    OllamaAdapterError,
                    "nesting depth",
                ):
                    adapter.observe_generate(
                        model="m",
                        prompt="p",
                        store=store,
                        custody=custody,
                    )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=nested,
                failure_category="response_invalid",
                failure_status=200,
            )

    def test_echoed_request_bytes_do_not_conflict_on_artifact_metadata(self) -> None:
        _FakeOllamaHandler.echo_request = True

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
                "response field",
            ):
                adapter.observe_generate(
                    model="m",
                    prompt="p",
                    store=store,
                    custody=custody,
                )

            request_bytes = _FakeOllamaHandler.received
            self.assertIsNotNone(request_bytes)
            assert request_bytes is not None
            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=request_bytes,
                failure_category="response_invalid",
                failure_status=200,
            )
            self.assertEqual(store.artifact_count, 2)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_fork_during_observation_reservation_resets_child_mutexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"
            store = LocalEvidenceStore(store_root)
            custody = LocalCustodyLedger(custody_root)

            reservation_entered = threading.Event()
            release_reservation = threading.Event()
            holder_errors: list[BaseException] = []

            def hold_reservation() -> None:
                try:
                    with ollama_module._observation_reservation(store, custody):
                        reservation_entered.set()
                        if not release_reservation.wait(timeout=5):
                            raise AssertionError(
                                "fork regression reservation release timed out"
                            )
                except BaseException as exc:
                    holder_errors.append(exc)

            holder = threading.Thread(target=hold_reservation)
            holder.start()
            self.assertTrue(
                reservation_entered.wait(timeout=5),
                "holder thread never acquired observation reservation",
            )

            read_fd, write_fd = os.pipe()
            release_timer = threading.Timer(0.2, release_reservation.set)
            release_timer.start()

            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                signal.alarm(3)
                exit_code = 1
                try:
                    child_store = LocalEvidenceStore(store_root)
                    child_custody = LocalCustodyLedger(custody_root)
                    with ollama_module._observation_reservation(
                        child_store,
                        child_custody,
                    ):
                        os.write(write_fd, b"acquired")
                    exit_code = 0
                except BaseException as exc:
                    try:
                        os.write(
                            write_fd,
                            (
                                f"error:{type(exc).__name__}:{exc}"
                            ).encode("utf-8", "replace"),
                        )
                    except OSError:
                        pass
                finally:
                    signal.alarm(0)
                    os.close(write_fd)
                    os._exit(exit_code)

            os.close(write_fd)
            try:
                child_result = os.read(read_fd, 4096)
            finally:
                os.close(read_fd)

            _, child_status = os.waitpid(pid, 0)
            release_timer.join(timeout=5)
            holder.join(timeout=5)

            self.assertFalse(holder.is_alive(), "reservation holder did not exit")
            self.assertEqual(holder_errors, [])
            self.assertTrue(
                os.WIFEXITED(child_status),
                f"forked child did not exit normally: status={child_status}",
            )
            self.assertEqual(os.WEXITSTATUS(child_status), 0, child_result)
            self.assertEqual(child_result, b"acquired")

            # The parent registry remains usable after its after-fork handler.
            with ollama_module._observation_reservation(store, custody):
                pass

    def test_multiprocess_observations_reserve_fresh_pair_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"

            # Pre-create the exact shared roots before either worker constructs
            # its own store/custody instances, matching the executed review case.
            LocalEvidenceStore(store_root)
            LocalCustodyLedger(custody_root)

            ctx = multiprocessing.get_context("spawn")
            start_event = ctx.Event()
            ready_queue = ctx.Queue()
            result_queue = ctx.Queue()
            base_url = f"http://127.0.0.1:{self.server.server_port}"

            workers = [
                ctx.Process(
                    target=_multiprocess_observe_worker,
                    args=(
                        str(store_root),
                        str(custody_root),
                        base_url,
                        start_event,
                        ready_queue,
                        result_queue,
                    ),
                )
                for _ in range(2)
            ]

            for worker_process in workers:
                worker_process.start()

            self.assertEqual(ready_queue.get(timeout=10), "ready")
            self.assertEqual(ready_queue.get(timeout=10), "ready")
            start_event.set()

            for worker_process in workers:
                worker_process.join(timeout=15)
                self.assertFalse(
                    worker_process.is_alive(),
                    "multiprocess observation worker did not exit",
                )
                self.assertEqual(worker_process.exitcode, 0)

            results = [
                result_queue.get(timeout=5),
                result_queue.get(timeout=5),
            ]

            successes = [item for item in results if item[0] == "ok"]
            errors = [item for item in results if item[0] == "error"]

            self.assertEqual(_FakeOllamaHandler.request_count, 1)
            self.assertEqual(len(successes), 1, results)
            self.assertEqual(len(errors), 1, results)
            self.assertIn(
                "requires a fresh store and custody ledger",
                errors[0][1],
            )

            reopened_store = LocalEvidenceStore(store_root)
            reopened_custody = LocalCustodyLedger(custody_root)
            self.assertEqual(
                reopened_store.current_manifest_identity,
                successes[0][1],
            )
            self.assertTrue(reopened_store.verify_current().integrity_verified)
            self.assertTrue(reopened_custody.verify().integrity_verified)

    def test_concurrent_observations_atomically_reserve_fresh_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            entered_transport = threading.Event()
            release_transport = threading.Event()
            transport_calls = 0
            transport_guard = threading.Lock()
            results = []
            errors: list[BaseException] = []

            def fake_post(request_bytes: bytes) -> bytes:
                nonlocal transport_calls
                with transport_guard:
                    transport_calls += 1
                entered_transport.set()
                if not release_transport.wait(timeout=5):
                    raise AssertionError("transport release timed out")
                return _FakeOllamaHandler.response_bytes

            def worker() -> None:
                try:
                    results.append(
                        adapter.observe_generate(
                            model="qwen2.5:0.5b",
                            prompt="same concurrent request",
                            store=store,
                            custody=custody,
                        )
                    )
                except BaseException as exc:
                    errors.append(exc)

            with mock.patch.object(
                adapter,
                "_post_generate",
                side_effect=fake_post,
            ):
                first = threading.Thread(target=worker)
                second = threading.Thread(target=worker)
                first.start()
                self.assertTrue(
                    entered_transport.wait(timeout=5),
                    "first observation never reached transport",
                )
                second.start()

                # The second thread may block on the observation reservation,
                # but it must never enter transport while the first owns it.
                second.join(timeout=0.2)
                self.assertTrue(
                    second.is_alive(),
                    "second observation unexpectedly completed before release",
                )
                with transport_guard:
                    self.assertEqual(transport_calls, 1)

                release_transport.set()
                first.join(timeout=5)
                second.join(timeout=5)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            with transport_guard:
                self.assertEqual(transport_calls, 1)
            self.assertEqual(len(results), 1)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], OllamaAdapterError)
            self.assertIn(
                "requires a fresh store and custody ledger",
                str(errors[0]),
            )
            self.assertTrue(results[0].snapshot.verification.integrity_verified)
            self.assertTrue(custody.verify().integrity_verified)

    def test_repeated_observation_requires_fresh_evidence_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            adapter.observe_generate(
                model="qwen2.5:0.5b",
                prompt="same",
                store=store,
                custody=custody,
            )
            self.assertEqual(_FakeOllamaHandler.request_count, 1)

            with self.assertRaisesRegex(
                OllamaAdapterError,
                "requires a fresh store and custody ledger",
            ):
                adapter.observe_generate(
                    model="qwen2.5:0.5b",
                    prompt="same",
                    store=store,
                    custody=custody,
                )

            self.assertEqual(_FakeOllamaHandler.request_count, 1)

    def test_zero_length_http_error_body_is_retained(self) -> None:
        _FakeOllamaHandler.status = 500
        _FakeOllamaHandler.response_bytes = b""

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
                    model="m",
                    prompt="p",
                    store=store,
                    custody=custody,
                )

            self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=b"",
                failure_category="http_error",
                failure_status=500,
            )

    def test_malformed_http_status_finalizes_protocol_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalEvidenceStore(root / "store")
            custody = LocalCustodyLedger(root / "custody")
            adapter = OllamaAdapter(
                f"http://127.0.0.1:{self.server.server_port}",
                timeout_seconds=5,
            )

            with mock.patch.object(
                adapter._opener,
                "open",
                side_effect=http_client.BadStatusLine("NOT HTTP"),
            ):
                with self.assertRaisesRegex(
                    OllamaAdapterError,
                    "HTTP protocol failure",
                ):
                    adapter.observe_generate(
                        model="m",
                        prompt="p",
                        store=store,
                        custody=custody,
                    )

            detail = self._assert_failure_evidence(
                store=store,
                custody=custody,
                response_bytes=None,
                failure_category="http_protocol_error",
            )
            self.assertIsNone(detail["http_status"])
            self.assertIn("NOT HTTP", str(detail["detail"]))

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
