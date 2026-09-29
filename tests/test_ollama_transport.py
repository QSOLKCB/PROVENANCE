from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import socket
from queue import Queue
import threading
from typing import Iterator
import unittest
from unittest import mock
from urllib import request as urllib_request

import provenance_adapters.ollama as ollama_module
from provenance_adapters import OllamaAdapter, OllamaAdapterError


_REQUEST_BYTES = (
    '{"model": "test-model", "prompt": "café", "stream": false}\n'
).encode("utf-8")

_RESPONSE_BYTES = (
    b'{ "model": "test-model", "response": "ok", "done": true }\n'
)


@dataclass(frozen=True)
class _ReceivedRequest:
    method: str
    path: str
    body: bytes
    content_type: str | None
    accept: str | None


@dataclass(frozen=True)
class _Endpoint:
    url: str
    received: Queue[_ReceivedRequest]


@contextmanager
def _serve(
    *,
    status: int = 200,
    body: bytes = _RESPONSE_BYTES,
    location: str | None = None,
    content_length_override: int | None = None,
) -> Iterator[_Endpoint]:
    received: Queue[_ReceivedRequest] = Queue()

    class Handler(BaseHTTPRequestHandler):
        def _respond(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            request_body = self.rfile.read(length)
            received.put(
                _ReceivedRequest(
                    method=self.command,
                    path=self.path,
                    body=request_body,
                    content_type=self.headers.get("Content-Type"),
                    accept=self.headers.get("Accept"),
                )
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            advertised = (
                content_length_override
                if content_length_override is not None
                else len(body)
            )
            self.send_header("Content-Length", str(advertised))
            if location is not None:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            self._respond()

        def do_GET(self) -> None:
            self._respond()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield _Endpoint(
            url=f"http://127.0.0.1:{server.server_port}",
            received=received,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _serve_raw(response_bytes: bytes) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                received = b""
                while b"\r\n\r\n" not in received:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    received += chunk
                connection.sendall(response_bytes)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        listener.close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise AssertionError("raw HTTP server thread did not exit")
        if errors:
            raise errors[0]


class OllamaTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = mock.patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

        global_opener = mock.patch.object(urllib_request, "_opener", None)
        global_opener.start()
        self.addCleanup(global_opener.stop)

    def _assert_exact_request(self, endpoint: _Endpoint) -> None:
        request = endpoint.received.get(timeout=1)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/api/generate")
        self.assertEqual(request.body, _REQUEST_BYTES)
        self.assertEqual(request.content_type, "application/json")
        self.assertEqual(request.accept, "application/json")
        self.assertTrue(endpoint.received.empty(), "unexpected extra request")

    def test_direct_post_preserves_exact_request_and_response_bytes(self) -> None:
        with _serve() as endpoint:
            adapter = OllamaAdapter(endpoint.url, timeout_seconds=2)
            response = adapter._post_generate(_REQUEST_BYTES)

            self.assertEqual(response, _RESPONSE_BYTES)
            self._assert_exact_request(endpoint)

    def test_environment_proxy_is_not_used(self) -> None:
        for variable in ("http_proxy", "HTTP_PROXY"):
            with self.subTest(variable=variable):
                with _serve() as endpoint, _serve() as proxy:
                    environment = {
                        variable: proxy.url,
                        "no_proxy": "",
                        "NO_PROXY": "",
                    }
                    with (
                        mock.patch.dict(os.environ, environment, clear=True),
                        mock.patch.object(urllib_request, "_opener", None),
                        mock.patch.object(
                            urllib_request,
                            "proxy_bypass",
                            return_value=False,
                        ),
                    ):
                        adapter = OllamaAdapter(
                            endpoint.url,
                            timeout_seconds=2,
                        )
                        response = adapter._post_generate(_REQUEST_BYTES)

                    self.assertEqual(response, _RESPONSE_BYTES)
                    self._assert_exact_request(endpoint)
                    self.assertTrue(
                        proxy.received.empty(),
                        "the prompt was sent to the configured proxy",
                    )

    def test_redirects_are_rejected_without_contacting_destination(self) -> None:
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                redirect_body = f"redirect-{status}".encode("ascii")
                with _serve() as destination:
                    with _serve(
                        status=status,
                        body=redirect_body,
                        location=destination.url + "/redirect-target",
                    ) as endpoint:
                        adapter = OllamaAdapter(
                            endpoint.url,
                            timeout_seconds=2,
                        )
                        with self.assertRaises(
                            ollama_module._TransportFailure,
                        ) as raised:
                            adapter._post_generate(_REQUEST_BYTES)

                        self.assertEqual(
                            raised.exception.category,
                            "redirect_rejected",
                        )
                        self.assertEqual(raised.exception.status, status)
                        self.assertEqual(
                            raised.exception.response_bytes,
                            redirect_body,
                        )
                        self._assert_exact_request(endpoint)
                        self.assertTrue(
                            destination.received.empty(),
                            "redirect destination received a request",
                        )

    def test_process_global_opener_is_not_used(self) -> None:
        global_opener = mock.Mock(spec=urllib_request.OpenerDirector)
        global_opener.open.side_effect = AssertionError(
            "process-global opener must not be used"
        )

        with _serve() as endpoint:
            with mock.patch.object(
                urllib_request,
                "_opener",
                global_opener,
            ):
                adapter = OllamaAdapter(endpoint.url, timeout_seconds=2)
                response = adapter._post_generate(_REQUEST_BYTES)

            self.assertEqual(response, _RESPONSE_BYTES)
            self._assert_exact_request(endpoint)
            global_opener.open.assert_not_called()

    def test_http_error_still_raises_adapter_error(self) -> None:
        with _serve(
            status=500,
            body=b'{"error":"test failure"}',
        ) as endpoint:
            adapter = OllamaAdapter(endpoint.url, timeout_seconds=2)
            with self.assertRaisesRegex(
                OllamaAdapterError,
                r"Ollama generate returned HTTP 500",
            ):
                adapter._post_generate(_REQUEST_BYTES)

            self._assert_exact_request(endpoint)

    def test_truncated_http_error_is_incomplete_read_with_partial_bytes(self) -> None:
        partial = b"{}"
        with _serve(
            status=500,
            body=partial,
            content_length_override=10,
        ) as endpoint:
            adapter = OllamaAdapter(endpoint.url, timeout_seconds=2)

            with self.assertRaises(
                ollama_module._TransportFailure,
            ) as raised:
                adapter._post_generate(_REQUEST_BYTES)

            self.assertEqual(raised.exception.category, "incomplete_read")
            self.assertEqual(raised.exception.status, 500)
            self.assertEqual(raised.exception.response_bytes, partial)
            self._assert_exact_request(endpoint)

    def test_malformed_http_status_line_is_normalized_transport_failure(self) -> None:
        with _serve_raw(b"THIS IS NOT HTTP\r\n\r\n") as url:
            adapter = OllamaAdapter(url, timeout_seconds=2)

            with self.assertRaises(
                ollama_module._TransportFailure,
            ) as raised:
                adapter._post_generate(_REQUEST_BYTES)

            self.assertEqual(
                raised.exception.category,
                "http_protocol_error",
            )
            self.assertIsNone(raised.exception.status)
            self.assertIsNone(raised.exception.response_bytes)
            self.assertIn(
                "HTTP protocol failure",
                str(raised.exception),
            )

    def test_localhost_is_canonicalized_to_literal_loopback(self) -> None:
        adapter = OllamaAdapter("http://localhost:11434")
        self.assertEqual(adapter.base_url, "http://127.0.0.1:11434")


if __name__ == "__main__":
    unittest.main()
