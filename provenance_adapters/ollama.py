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
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    Relationship,
)
from provenance_custody import ClockObservation, LocalCustodyLedger, observe_clock
from provenance_store import LocalEvidenceStore, StoredSnapshot

ADAPTER_ID = "provenance-adapter:ollama/v1"
_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


class OllamaAdapterError(RuntimeError):
    """Raised when the local Ollama observation cannot satisfy its contract."""


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

        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

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
            with urllib_request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                status = getattr(response, "status", None)
                if status != 200:
                    raise OllamaAdapterError(
                        f"Ollama generate returned HTTP status {status}"
                    )
                return response.read()
        except urllib_error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            suffix = f": {detail}" if detail else ""
            raise OllamaAdapterError(
                f"Ollama generate returned HTTP {exc.code}{suffix}"
            ) from exc
        except urllib_error.URLError as exc:
            raise OllamaAdapterError(
                f"local Ollama endpoint is unavailable: {exc.reason}"
            ) from exc
        except OSError as exc:
            raise OllamaAdapterError(
                f"local Ollama request failed: {exc}"
            ) from exc

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
            source="ollama:/api/generate request",
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
                operation="ollama.generate.request",
                outputs=(request_record.content_identity,),
            )
        )
        store.put_event(request_event)

        response_bytes = self._post_generate(request_bytes)
        response_clock: ClockObservation = observe_clock()
        parsed_response = _parse_response(response_bytes)
        declared_model = str(parsed_response["model"])
        response_text = str(parsed_response["response"])

        response_record = store.put_artifact(
            response_bytes,
            media_type="application/json",
            retain_content=True,
        )
        custody.append(
            response_record.content_identity,
            CustodyAction.CAPTURED,
            actor=f"ollama:{declared_model}",
            source="ollama:/api/generate response",
            clock=response_clock,
        )
        custody.append(
            response_record.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=ADAPTER_ID,
        )

        response_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor=f"ollama:{declared_model}",
                operation="ollama.generate.response",
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
                actor=f"ollama:{declared_model}",
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

        for subject in (
            request_record.content_identity,
            response_record.content_identity,
            snapshot.manifest_identity,
        ):
            custody.append(
                subject,
                CustodyAction.VERIFIED,
                actor="provenance-verify",
                source=ADAPTER_ID,
                related_identity=snapshot.manifest_identity
                if subject != snapshot.manifest_identity
                else None,
            )

        custody_report = custody.verify()
        if not custody_report.integrity_verified:
            raise OllamaAdapterError(
                "Ollama observation custody chain failed verification: "
                + "; ".join(custody_report.errors)
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
