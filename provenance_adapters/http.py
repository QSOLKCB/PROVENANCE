"""Generic HTTP adapter implemented through the Phase 10 adapter contract."""
from __future__ import annotations

import http.client as http_client
from typing import Any, Mapping
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from provenance_core import canonical_json_bytes

from .base import (
    AdapterContract,
    AdapterExecutionError,
    AdapterFailure,
    AdapterObservation,
    CapturedArtifact,
    build_observation,
)


HTTP_ADAPTER_CONTRACT = AdapterContract(
    adapter_id="provenance-adapter:http/v1",
    source_kind="http",
    observation_boundary=(
        "request bytes and response bytes visible to the generic HTTP client; "
        "provider-internal execution is not observed"
    ),
    extension_namespace="provenance.adapter.http",
)

_DEFAULT_MAX_BYTES = 16 * 1024 * 1024


class GenericHTTPAdapterError(AdapterExecutionError):
    """HTTP operation failed after a provider-neutral observation was built."""


class _RejectRedirects(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_bounded(response, max_bytes: int) -> tuple[bytes, AdapterFailure | None]:
    try:
        data = response.read(max_bytes + 1)
    except http_client.IncompleteRead as exc:
        partial = bytes(exc.partial)
        return partial, AdapterFailure(
            category="truncated_response",
            detail="HTTP response body terminated before declared transfer completed",
        )
    except http_client.HTTPException as exc:
        return b"", AdapterFailure(
            category="response_read_failed",
            detail=f"HTTP response body could not be read: {exc}",
        )
    if len(data) > max_bytes:
        return data[:max_bytes], AdapterFailure(
            category="response_too_large",
            detail=(
                "HTTP response exceeded the configured capture limit; "
                "only the observed prefix is retained"
            ),
        )
    return data, None


class GenericHTTPAdapter:
    """Observe one ordinary HTTP request/response exchange without provider semantics."""

    contract = HTTP_ADAPTER_CONTRACT

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: int = 30,
        max_request_bytes: int = _DEFAULT_MAX_BYTES,
        max_response_bytes: int = _DEFAULT_MAX_BYTES,
        headers: Mapping[str, str] | None = None,
    ):
        if not isinstance(url, str) or not url:
            raise ValueError("HTTP adapter URL must be a non-empty string")
        parsed = urllib_parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("HTTP adapter URL scheme must be http or https")
        if not parsed.hostname:
            raise ValueError("HTTP adapter URL must contain a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("HTTP adapter URL must not contain userinfo credentials")
        if parsed.fragment:
            raise ValueError("HTTP adapter URL must not contain a fragment")
        if type(timeout_seconds) is not int or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")
        if type(max_request_bytes) is not int or max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be a positive integer")
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive integer")

        normalized_headers: dict[str, str] = {}
        for key, value in dict(headers or {}).items():
            if not isinstance(key, str) or not key:
                raise ValueError("HTTP header names must be non-empty strings")
            if not isinstance(value, str):
                raise ValueError("HTTP header values must be strings")
            if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                raise ValueError("HTTP headers must not contain CR or LF")
            normalized_headers[key] = value

        self.url = url
        self.timeout_seconds = timeout_seconds
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self.headers = normalized_headers
        self._parsed = parsed
        self._opener = urllib_request.build_opener(_RejectRedirects())

    def _source_actor(self) -> str:
        authority = self._parsed.hostname or "unknown"
        if self._parsed.port is not None:
            authority += f":{self._parsed.port}"
        return f"http:{self._parsed.scheme}://{authority}"

    def _inputs(
        self,
        *,
        method: str,
        body: bytes,
        media_type: str,
    ) -> tuple[CapturedArtifact, ...]:
        descriptor = {
            "method": method,
            "url": self.url,
            "header_names": sorted(self.headers),
            "header_values_retained": False,
        }
        return (
            CapturedArtifact(
                label="request_descriptor",
                data=canonical_json_bytes(descriptor),
                media_type="application/json",
            ),
            CapturedArtifact(
                label="request_body",
                data=body,
                media_type=media_type,
            ),
        )

    def _observation(
        self,
        *,
        method: str,
        inputs: tuple[CapturedArtifact, ...],
        outputs: tuple[CapturedArtifact, ...],
        status: int | None,
        declared_metadata: Mapping[str, Any] | None,
        extensions: Mapping[str, Any] | None,
        failure: AdapterFailure | None,
    ) -> AdapterObservation:
        metadata = {
            "http": {
                "method": method,
                "status": status,
                "target_scheme": self._parsed.scheme,
                "target_host": self._parsed.hostname,
                "target_port": self._parsed.port,
                "redirects_followed": False,
                "request_header_values_retained": False,
            },
            "caller": dict(declared_metadata or {}),
        }
        return build_observation(
            self.contract,
            source_actor=self._source_actor(),
            operation="http.exchange",
            inputs=inputs,
            outputs=outputs,
            declared_metadata=metadata,
            extensions=extensions,
            failure=failure,
        )

    def observe(
        self,
        body: bytes,
        *,
        method: str = "POST",
        media_type: str = "application/octet-stream",
        declared_metadata: Mapping[str, Any] | None = None,
        extensions: Mapping[str, Any] | None = None,
    ) -> AdapterObservation:
        if not isinstance(body, bytes):
            raise TypeError("HTTP request body must be bytes")
        if len(body) > self.max_request_bytes:
            raise ValueError("HTTP request body exceeds configured capture limit")
        if not isinstance(method, str) or not method or not method.isascii():
            raise ValueError("HTTP method must be a non-empty ASCII string")
        method = method.upper()
        if not all(char.isalnum() or char in "-_" for char in method):
            raise ValueError("HTTP method contains unsupported characters")
        if not isinstance(media_type, str) or not media_type:
            raise ValueError("media_type must be a non-empty string")

        inputs = self._inputs(method=method, body=body, media_type=media_type)
        headers = dict(self.headers)
        headers.setdefault("Content-Type", media_type)
        request = urllib_request.Request(
            self.url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            response = self._opener.open(
                request,
                timeout=self.timeout_seconds,
            )
        except urllib_error.HTTPError as exc:
            try:
                response_body, read_failure = _read_bounded(
                    exc,
                    self.max_response_bytes,
                )
                response_type = (
                    exc.headers.get_content_type()
                    if exc.headers is not None
                    else "application/octet-stream"
                )
            finally:
                exc.close()
            failure = read_failure or AdapterFailure(
                category=(
                    "redirect_rejected"
                    if 300 <= exc.code < 400
                    else "http_status"
                ),
                code=exc.code,
                detail=f"HTTP exchange returned status {exc.code}",
            )
            outputs = (
                CapturedArtifact(
                    label=(
                        "response_prefix"
                        if read_failure is not None
                        and read_failure.category == "response_too_large"
                        else "response_body"
                    ),
                    data=response_body,
                    media_type=response_type,
                ),
            )
            observation = self._observation(
                method=method,
                inputs=inputs,
                outputs=outputs,
                status=exc.code,
                declared_metadata=declared_metadata,
                extensions=extensions,
                failure=failure,
            )
            raise GenericHTTPAdapterError(
                str(failure.detail),
                observation=observation,
            ) from exc
        except (urllib_error.URLError, OSError, http_client.HTTPException) as exc:
            failure = AdapterFailure(
                category="transport_failure",
                detail=f"HTTP transport failed: {exc}",
            )
            observation = self._observation(
                method=method,
                inputs=inputs,
                outputs=(),
                status=None,
                declared_metadata=declared_metadata,
                extensions=extensions,
                failure=failure,
            )
            raise GenericHTTPAdapterError(
                failure.detail,
                observation=observation,
            ) from exc

        try:
            status = response.status
            response_body, read_failure = _read_bounded(
                response,
                self.max_response_bytes,
            )
            response_type = response.headers.get_content_type()
        finally:
            response.close()

        outputs = (
            CapturedArtifact(
                label=(
                    "response_prefix"
                    if read_failure is not None
                    and read_failure.category == "response_too_large"
                    else "response_body"
                ),
                data=response_body,
                media_type=response_type,
            ),
        )
        observation = self._observation(
            method=method,
            inputs=inputs,
            outputs=outputs,
            status=status,
            declared_metadata=declared_metadata,
            extensions=extensions,
            failure=read_failure,
        )
        if read_failure is not None:
            raise GenericHTTPAdapterError(
                read_failure.detail,
                observation=observation,
            )
        return observation
