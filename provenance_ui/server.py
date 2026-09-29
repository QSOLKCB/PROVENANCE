"""Small dependency-free read-only HTTP server for PROVENANCE."""
from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import posixpath
from urllib.parse import urlsplit

from .viewer import ProvenanceViewer, ViewerError


_STATIC_ROOT = Path(__file__).resolve().parent / "static"
_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def _validate_bind_host(host: str, allow_non_loopback: bool) -> None:
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")
    if allow_non_loopback:
        return
    if host == "localhost":
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "non-literal hostnames require --allow-non-loopback; "
            "default viewer binding is loopback-only"
        ) from exc
    if not address.is_loopback:
        raise ValueError(
            "non-loopback binding requires explicit --allow-non-loopback"
        )


class _ViewerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        viewer: ProvenanceViewer,
    ):
        self.viewer = viewer
        super().__init__(server_address, ProvenanceRequestHandler)


class ProvenanceRequestHandler(BaseHTTPRequestHandler):
    server_version = "PROVENANCE-Viewer/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        head_only: bool = False,
    ) -> None:
        self._headers(status, content_type, len(body))
        if not head_only:
            self.wfile.write(body)

    def _send_json(
        self,
        status: int,
        payload: object,
        *,
        head_only: bool = False,
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            head_only=head_only,
        )

    def _normalized_path(self) -> str:
        path = urlsplit(self.path).path
        normalized = posixpath.normpath(path)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    def _serve(self, *, head_only: bool) -> None:
        path = self._normalized_path()
        if path == "/api/view":
            try:
                payload = self.server.viewer.snapshot()  # type: ignore[attr-defined]
            except ViewerError as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"ok": False, "error": str(exc)},
                    head_only=head_only,
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "view": payload},
                head_only=head_only,
            )
            return

        asset = _STATIC.get(path)
        if asset is None:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "not found"},
                head_only=head_only,
            )
            return
        name, content_type = asset
        candidate = _STATIC_ROOT / name
        if candidate.is_symlink() or not candidate.is_file():
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "viewer static asset unavailable"},
                head_only=head_only,
            )
            return
        try:
            body = candidate.read_bytes()
        except OSError:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "viewer static asset unreadable"},
                head_only=head_only,
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            head_only=head_only,
        )

    def do_GET(self) -> None:
        self._serve(head_only=False)

    def do_HEAD(self) -> None:
        self._serve(head_only=True)

    def _method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"ok": False, "error": "read-only viewer accepts GET and HEAD only"},
        )

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed


def make_server(
    store_root: Path | str,
    custody_root: Path | str,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    allow_non_loopback: bool = False,
) -> ThreadingHTTPServer:
    _validate_bind_host(host, allow_non_loopback)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535")
    viewer = ProvenanceViewer(store_root, custody_root)
    viewer.snapshot()
    return _ViewerHTTPServer((host, port), viewer)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenance-ui",
        description="Read-only localhost viewer for finalized PROVENANCE evidence.",
    )
    parser.add_argument("--store", required=True, help="Local PROVENANCE store root")
    parser.add_argument("--custody", required=True, help="Local custody ledger root")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Explicitly permit LAN/public binding; viewer remains read-only.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        server = make_server(
            args.store,
            args.custody,
            host=args.host,
            port=args.port,
            allow_non_loopback=args.allow_non_loopback,
        )
    except (OSError, ValueError, ViewerError) as exc:
        raise SystemExit(f"provenance-ui: {exc}") from exc

    host, port = server.server_address[:2]
    print(f"PROVENANCE read-only viewer: http://{host}:{port}/")
    print("Authority: READ_ONLY_PRESENTATION")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
