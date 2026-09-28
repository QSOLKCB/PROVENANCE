"""Local Ollama reference adapter for PROVENANCE Phase 5."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Mapping
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from provenance_core import (
    ArtifactRecord,
    CollectionStatus,
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    Relationship,
)
from provenance_custody import ClockObservation, LocalCustodyLedger, observe_clock
from provenance_store import LocalEvidenceStore, StoredSnapshot

ADAPTER_ID = "provenance-adapter:ollama/v1"
_ENDPOINT_ACTOR = "ollama:local-endpoint"
_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


class OllamaAdapterError(RuntimeError):
    """Raised when the local Ollama observation cannot satisfy its contract."""


class _TransportFailure(OllamaAdapterError):
    """Transport failure with any raw HTTP response bytes already observed."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        response_bytes: bytes | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.response_bytes = response_bytes


class _RejectRedirects(urllib_request.HTTPRedirectHandler):
    """Reject redirects without issuing a request to their destination."""

    def http_error_302(self, req, fp, code, msg, headers):
        try:
            fp.close()
        finally:
            raise _TransportFailure(
                f"Ollama endpoint returned forbidden HTTP redirect {code}",
                status=code,
            )

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


@dataclass(frozen=True, slots=True)
class OllamaObservation:
    declared_model: str
    request: ArtifactRecord
    response: ArtifactRecord
    request_event: EventEnvelope
    response_event: EventEnvelope
    declaration_event: EventEnvelope
    snapshot: StoredSnapshot
    response_text: str


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise OllamaAdapterError(
                f"Ollama response contains duplicate JSON key {key!r}"
            )
        value[key] = item
    return value


def _parse_response(data: bytes) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OllamaAdapterError("Ollama response is not UTF-8 JSON") from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                OllamaAdapterError(
                    f"Ollama response contains non-finite JSON token {token}"
                )
            ),
        )
    except OllamaAdapterError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise OllamaAdapterError("Ollama response is not valid JSON") from exc

    if not isinstance(value, dict):
        raise OllamaAdapterError("Ollama response root must be an object")
    model = value.get("model")
    if not isinstance(model, str) or not model:
        raise OllamaAdapterError(
            "Ollama response must declare a non-empty model identifier"
        )
    response = value.get("response")
    if not isinstance(response, str):
        raise OllamaAdapterError(
            "Ollama response must contain a string response field"
        )
    if value.get("done") is not True:
        raise OllamaAdapterError(
            "non-streaming Ollama response must report done=true"
        )
    return value


class OllamaAdapter:
    """Observe one local Ollama /api/generate request/response exchange."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        *,
        timeout_seconds: int = 120,
    ):
        parsed = urllib_parse.urlsplit(base_url)
        if parsed.scheme != "http":
            raise ValueError("Phase 5 Ollama adapter requires local HTTP")
        if parsed.hostname not in _ALLOWED_HOSTS:
            raise ValueError(
                "Phase 5 Ollama adapter is local-only; host must be loopback"
            )
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Phase 5 Ollama adapter does not accept URL credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("Ollama base URL must not contain query or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("Ollama base URL must not contain an API path")
        if type(timeout_seconds) is not int or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Ollama base URL contains an invalid port") from exc

        # Avoid DNS entirely for the documented localhost spelling.
        host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
        display_host = f"[{host}]" if host == "::1" else host
        port_suffix = f":{port}" if port is not None else ""
        self.base_url = f"http://{display_host}{port_suffix}"
        self.timeout_seconds = timeout_seconds
        self._opener = urllib_request.build_opener(
            urllib_request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def _post_generate(self, request_bytes: bytes) -> bytes:
        request = urllib_request.Request(
            self.base_url + "/api/generate",
            data=request_bytes,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                status = getattr(response, "status", None)
                body = response.read()
                if status != 200:
                    raise _TransportFailure(
                        f"Ollama generate returned HTTP status {status}",
                        status=status,
                        response_bytes=body,
                    )
                return body
        except _TransportFailure:
            raise
        except urllib_error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:
                body = b""
            raise _TransportFailure(
                f"Ollama generate returned HTTP {exc.code}",
                status=exc.code,
                response_bytes=body or None,
            ) from exc
        except urllib_error.URLError as exc:
            raise _TransportFailure(
                f"local Ollama endpoint is unavailable: {exc.reason}"
            ) from exc
        except OSError as exc:
            raise _TransportFailure(
                f"local Ollama request failed: {exc}"
            ) from exc

    def _append_verified_custody(
        self,
        *,
        custody: LocalCustodyLedger,
        snapshot: StoredSnapshot,
        subjects: tuple[str, ...],
    ) -> None:
        for subject in (*subjects, snapshot.manifest_identity):
            custody.append(
                subject,
                CustodyAction.VERIFIED,
                actor="provenance-verify",
                source=ADAPTER_ID,
                related_identity=(
                    snapshot.manifest_identity
                    if subject != snapshot.manifest_identity
                    else None
                ),
            )

        report = custody.verify()
        if not report.integrity_verified:
            raise OllamaAdapterError(
                "Ollama observation custody chain failed verification: "
                + "; ".join(report.errors)
            )

    def _finalize_failure(
        self,
        *,
        store: LocalEvidenceStore,
        custody: LocalCustodyLedger,
        request_record: ArtifactRecord,
        request_event: EventEnvelope,
        operation: str,
        original_error: OllamaAdapterError,
        response_record: ArtifactRecord | None = None,
    ) -> None:
        outputs = (
            (response_record.content_identity,)
            if response_record is not None
            else ()
        )
        failure_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor=ADAPTER_ID,
                operation=operation,
                inputs=(request_record.content_identity,),
                outputs=outputs,
                relationships=(
                    Relationship(
                        "attempted_from",
                        request_event.event_identity,
                    ),
                ),
                collection_status=CollectionStatus.COLLECTION_FAILED,
            )
        )
        store.put_event(failure_event)

        try:
            snapshot = store.finalize(scope="closed")
            subjects = (request_record.content_identity,) + outputs
            self._append_verified_custody(
                custody=custody,
                snapshot=snapshot,
                subjects=subjects,
            )
        except Exception as evidence_error:
            raise OllamaAdapterError(
                f"{original_error}; evidence finalization failed: {evidence_error}"
            ) from original_error

        raise OllamaAdapterError(
            f"{original_error}; evidence_manifest={snapshot.manifest_identity}"
        ) from original_error

    def observe_generate(
        self,
        *,
        model: str,
        prompt: str,
        store: LocalEvidenceStore,
        custody: LocalCustodyLedger,
        options: Mapping[str, object] | None = None,
    ) -> OllamaObservation:
        if not isinstance(model, str) or not model:
            raise ValueError("model must be a non-empty string")
        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")
        if not isinstance(store, LocalEvidenceStore):
            raise TypeError("store must be a LocalEvidenceStore")
        if not isinstance(custody, LocalCustodyLedger):
            raise TypeError("custody must be a LocalCustodyLedger")
        if options is not None and not isinstance(options, Mapping):
            raise TypeError("options must be a mapping when supplied")

        payload: dict[str, object] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if options:
            payload["options"] = dict(options)
        request_bytes = _json_bytes(payload)

        request_clock: ClockObservation = observe_clock()
        request_record = store.put_artifact(
            request_bytes,
            media_type="application/json",
            retain_content=True,
        )
        custody.append(
            request_record.content_identity,
            CustodyAction.CAPTURED,
            actor=ADAPTER_ID,
            source="adapter-prepared:/api/generate request body",
            clock=request_clock,
        )
        custody.append(
            request_record.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=ADAPTER_ID,
        )

        request_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor=ADAPTER_ID,
                operation="ollama.generate.request.prepared",
                outputs=(request_record.content_identity,),
            )
        )
        store.put_event(request_event)

        try:
            response_bytes = self._post_generate(request_bytes)
        except _TransportFailure as exc:
            response_record: ArtifactRecord | None = None
            if exc.response_bytes is not None:
                response_record = store.put_artifact(
                    exc.response_bytes,
                    media_type="application/octet-stream",
                    retain_content=True,
                )
                custody.append(
                    response_record.content_identity,
                    CustodyAction.CAPTURED,
                    actor=ADAPTER_ID,
                    source="ollama:/api/generate error response bytes",
                )
                custody.append(
                    response_record.content_identity,
                    CustodyAction.STORED,
                    actor="provenance-store:local",
                    source=ADAPTER_ID,
                )
            self._finalize_failure(
                store=store,
                custody=custody,
                request_record=request_record,
                request_event=request_event,
                operation="ollama.generate.transport.failed",
                original_error=exc,
                response_record=response_record,
            )
            raise AssertionError("unreachable")

        response_clock: ClockObservation = observe_clock()

        # Retain exactly what was observed before parsing or deriving claims.
        response_record = store.put_artifact(
            response_bytes,
            media_type="application/octet-stream",
            retain_content=True,
        )
        custody.append(
            response_record.content_identity,
            CustodyAction.CAPTURED,
            actor=ADAPTER_ID,
            source="ollama:/api/generate response bytes",
            clock=response_clock,
        )
        custody.append(
            response_record.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=ADAPTER_ID,
        )

        try:
            parsed_response = _parse_response(response_bytes)
        except OllamaAdapterError as exc:
            self._finalize_failure(
                store=store,
                custody=custody,
                request_record=request_record,
                request_event=request_event,
                operation="ollama.generate.response.invalid",
                original_error=exc,
                response_record=response_record,
            )
            raise AssertionError("unreachable")

        declared_model = str(parsed_response["model"])
        response_text = str(parsed_response["response"])

        response_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor=ADAPTER_ID,
                operation="ollama.generate.response.received",
                inputs=(request_record.content_identity,),
                outputs=(response_record.content_identity,),
                relationships=(
                    Relationship(
                        "responds_to",
                        request_event.event_identity,
                    ),
                ),
            )
        )
        store.put_event(response_event)

        declaration_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.DECLARED,
                actor=_ENDPOINT_ACTOR,
                operation="ollama.model.declared",
                inputs=(response_record.content_identity,),
                relationships=(
                    Relationship(
                        "declared_by",
                        response_event.event_identity,
                    ),
                ),
            )
        )
        store.put_event(declaration_event)

        snapshot = store.finalize(scope="closed")
        if not snapshot.verification.integrity_verified:
            raise OllamaAdapterError(
                "Ollama observation snapshot failed independent verification"
            )

        self._append_verified_custody(
            custody=custody,
            snapshot=snapshot,
            subjects=(
                request_record.content_identity,
                response_record.content_identity,
            ),
        )

        return OllamaObservation(
            declared_model=declared_model,
            request=request_record,
            response=response_record,
            request_event=request_event,
            response_event=response_event,
            declaration_event=declaration_event,
            snapshot=snapshot,
            response_text=response_text,
        )
