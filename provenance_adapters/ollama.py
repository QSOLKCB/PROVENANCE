"""Local Ollama reference adapter for PROVENANCE Phase 5."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import http.client as http_client
import json
import os
import stat
import threading
from typing import Iterator, Mapping
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

_OBSERVATION_LOCK_NAME = ".ollama-observation.lock"
_OBSERVATION_LOCKS_GUARD = threading.RLock()
_OBSERVATION_LOCKS: dict[
    tuple[int, int],
    threading.RLock,
] = {}
_OBSERVATION_LOCKS_HELD_FOR_FORK: tuple[threading.RLock, ...] = ()
_OBSERVATION_AT_FORK_REGISTERED = globals().get(
    "_OBSERVATION_AT_FORK_REGISTERED",
    False,
)


class OllamaAdapterError(RuntimeError):
    """Raised when the local Ollama observation cannot satisfy its contract."""


class _TransportFailure(OllamaAdapterError):
    """Transport failure with any raw HTTP response bytes already observed."""

    def __init__(
        self,
        message: str,
        *,
        category: str,
        status: int | None = None,
        response_bytes: bytes | None = None,
    ):
        super().__init__(message)
        self.category = category
        self.status = status
        self.response_bytes = response_bytes


class _RejectRedirects(urllib_request.HTTPRedirectHandler):
    """Reject redirects without issuing a request to their destination."""

    def http_error_302(self, req, fp, code, msg, headers):
        response_bytes: bytes | None
        detail = f"Ollama endpoint returned forbidden HTTP redirect {code}"
        try:
            try:
                response_bytes = fp.read()
            except http_client.IncompleteRead as exc:
                response_bytes = bytes(exc.partial)
                detail += "; redirect body was truncated"
            except http_client.HTTPException as exc:
                response_bytes = None
                detail += f"; redirect body read failed: {exc}"
        finally:
            fp.close()

        raise _TransportFailure(
            detail,
            category="redirect_rejected",
            status=code,
            response_bytes=response_bytes,
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


@dataclass(frozen=True, slots=True)
class _ObservationReservationLease:
    pid: int

    def require_current_process(self) -> None:
        current_pid = os.getpid()
        if current_pid != self.pid:
            raise OllamaAdapterError(
                "Ollama observation cannot continue after fork; "
                "the child must start a fresh observation reservation"
            )


def _reservation_call(
    reservation: _ObservationReservationLease,
    operation,
    /,
    *args,
    **kwargs,
):
    reservation.require_current_process()
    result = operation(*args, **kwargs)
    reservation.require_current_process()
    return result


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
    except RecursionError as exc:
        raise OllamaAdapterError(
            "Ollama response exceeds supported JSON nesting depth"
        ) from exc
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


def _failure_detail_bytes(
    *,
    category: str,
    status: int | None,
    detail: str,
) -> bytes:
    return _json_bytes(
        {
            "schema": "provenance.ollama-failure.v1",
            "category": category,
            "http_status": status,
            "detail": detail,
        }
    )


def _process_observation_locks(
    keys: list[tuple[int, int]],
) -> list[threading.RLock]:
    with _OBSERVATION_LOCKS_GUARD:
        locks: list[threading.RLock] = []
        for key in keys:
            lock = _OBSERVATION_LOCKS.get(key)
            if lock is None:
                lock = threading.RLock()
                _OBSERVATION_LOCKS[key] = lock
            locks.append(lock)
        return locks


def _process_observation_lock(
    key: tuple[int, int],
) -> threading.RLock:
    return _process_observation_locks([key])[0]


def _before_observation_fork() -> None:
    global _OBSERVATION_LOCKS_HELD_FOR_FORK

    _OBSERVATION_LOCKS_GUARD.acquire()
    acquired: list[threading.RLock] = []
    try:
        for key in sorted(_OBSERVATION_LOCKS):
            lock = _OBSERVATION_LOCKS[key]
            lock.acquire()
            acquired.append(lock)
    except BaseException:
        for lock in reversed(acquired):
            lock.release()
        _OBSERVATION_LOCKS_GUARD.release()
        raise

    _OBSERVATION_LOCKS_HELD_FOR_FORK = tuple(acquired)


def _after_observation_fork_parent() -> None:
    global _OBSERVATION_LOCKS_HELD_FOR_FORK

    for lock in reversed(_OBSERVATION_LOCKS_HELD_FOR_FORK):
        lock.release()
    _OBSERVATION_LOCKS_HELD_FOR_FORK = ()
    _OBSERVATION_LOCKS_GUARD.release()


def _after_observation_fork_child() -> None:
    global _OBSERVATION_LOCKS
    global _OBSERVATION_LOCKS_GUARD
    global _OBSERVATION_LOCKS_HELD_FOR_FORK

    # The child has only the forking thread. Discard every inherited
    # process-local mutex rather than attempting to reuse copied lock state.
    _OBSERVATION_LOCKS = {}
    _OBSERVATION_LOCKS_GUARD = threading.RLock()
    _OBSERVATION_LOCKS_HELD_FOR_FORK = ()


if hasattr(os, "register_at_fork") and not _OBSERVATION_AT_FORK_REGISTERED:
    os.register_at_fork(
        before=_before_observation_fork,
        after_in_parent=_after_observation_fork_parent,
        after_in_child=_after_observation_fork_child,
    )
    _OBSERVATION_AT_FORK_REGISTERED = True


@contextmanager
def _observation_reservation(
    store: LocalEvidenceStore,
    custody: LocalCustodyLedger,
) -> Iterator[_ObservationReservationLease]:
    reservation_pid = os.getpid()
    lease = _ObservationReservationLease(pid=reservation_pid)
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    root_fds: dict[tuple[int, int], int] = {}
    process_locks: list[threading.RLock] = []
    lock_fds: list[int] = []

    try:
        for root in (store.root, custody.root):
            try:
                root_fd = os.open(root, directory_flags)
            except OSError as exc:
                raise OllamaAdapterError(
                    f"observation reservation root cannot be opened safely: {exc}"
                ) from exc

            root_stat = os.fstat(root_fd)
            key = (root_stat.st_dev, root_stat.st_ino)
            if key in root_fds:
                os.close(root_fd)
            else:
                root_fds[key] = root_fd

        ordered_keys = sorted(root_fds)

        reservation_locks = _process_observation_locks(ordered_keys)
        for process_lock in reservation_locks:
            process_lock.acquire()
            process_locks.append(process_lock)

        for key in ordered_keys:
            root_fd = root_fds[key]
            try:
                lock_fd = os.open(
                    _OBSERVATION_LOCK_NAME,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise OllamaAdapterError(
                    f"observation reservation lock cannot be opened safely: {exc}"
                ) from exc

            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                os.close(lock_fd)
                raise OllamaAdapterError(
                    "observation reservation lock must be a regular file"
                )

            try:
                fcntl.lockf(
                    lock_fd,
                    fcntl.LOCK_EX,
                    0,
                    0,
                    os.SEEK_SET,
                )
            except OSError as exc:
                os.close(lock_fd)
                raise OllamaAdapterError(
                    f"observation reservation POSIX lock failed: {exc}"
                ) from exc

            lock_fds.append(lock_fd)

        lease.require_current_process()
        yield lease
    finally:
        inherited_after_fork = os.getpid() != reservation_pid

        for lock_fd in reversed(lock_fds):
            try:
                if not inherited_after_fork:
                    fcntl.lockf(
                        lock_fd,
                        fcntl.LOCK_UN,
                        0,
                        0,
                        os.SEEK_SET,
                    )
            finally:
                os.close(lock_fd)

        if not inherited_after_fork:
            for process_lock in reversed(process_locks):
                process_lock.release()

        for root_fd in root_fds.values():
            os.close(root_fd)


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
                try:
                    body = response.read()
                except http_client.IncompleteRead as exc:
                    raise _TransportFailure(
                        "Ollama response body was truncated",
                        category="incomplete_read",
                        status=status,
                        response_bytes=bytes(exc.partial),
                    ) from exc
                except http_client.HTTPException as exc:
                    raise _TransportFailure(
                        f"Ollama HTTP protocol failure: {exc}",
                        category="http_protocol_error",
                        status=status,
                    ) from exc
                if status != 200:
                    raise _TransportFailure(
                        f"Ollama generate returned HTTP status {status}",
                        category="http_status",
                        status=status,
                        response_bytes=body,
                    )
                return body
        except _TransportFailure:
            raise
        except urllib_error.HTTPError as exc:
            body: bytes | None
            try:
                body = exc.read()
            except http_client.IncompleteRead as read_exc:
                raise _TransportFailure(
                    "Ollama HTTP error response body was truncated",
                    category="incomplete_read",
                    status=exc.code,
                    response_bytes=bytes(read_exc.partial),
                ) from read_exc
            except http_client.HTTPException as read_exc:
                raise _TransportFailure(
                    f"Ollama HTTP error response protocol failure: {read_exc}",
                    category="http_protocol_error",
                    status=exc.code,
                ) from read_exc
            except Exception:
                body = None
            raise _TransportFailure(
                f"Ollama generate returned HTTP {exc.code}",
                category="http_error",
                status=exc.code,
                response_bytes=body,
            ) from exc
        except urllib_error.URLError as exc:
            raise _TransportFailure(
                f"local Ollama endpoint is unavailable: {exc.reason}",
                category="endpoint_unavailable",
            ) from exc
        except http_client.HTTPException as exc:
            raise _TransportFailure(
                f"Ollama HTTP protocol failure: {exc}",
                category="http_protocol_error",
            ) from exc
        except OSError as exc:
            raise _TransportFailure(
                f"local Ollama request failed: {exc}",
                category="transport_os_error",
            ) from exc

    def _require_fresh_evidence_targets(
        self,
        *,
        store: LocalEvidenceStore,
        custody: LocalCustodyLedger,
    ) -> None:
        try:
            disk_store = LocalEvidenceStore(store.root)
            disk_custody = LocalCustodyLedger(custody.root)
        except Exception as exc:
            raise OllamaAdapterError(
                f"evidence targets could not be refreshed safely: {exc}"
            ) from exc

        custody_report = disk_custody.verify()
        if not custody_report.integrity_verified:
            raise OllamaAdapterError(
                "custody target failed verification before observation: "
                + "; ".join(custody_report.errors)
            )
        if (
            disk_store.artifact_count != 0
            or disk_store.event_count != 0
            or disk_store.current_manifest_identity is not None
            or custody_report.record_count != 0
        ):
            raise OllamaAdapterError(
                "Phase 5 Ollama observation requires a fresh store and custody ledger"
            )

    def _append_verified_custody(
        self,
        *,
        custody: LocalCustodyLedger,
        snapshot: StoredSnapshot,
        subjects: tuple[str, ...],
        reservation: _ObservationReservationLease,
    ) -> None:
        for subject in (*subjects, snapshot.manifest_identity):
            _reservation_call(
                reservation,
                custody.append,
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

        report = _reservation_call(
            reservation,
            custody.verify,
        )
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
        failure_category: str,
        failure_status: int | None = None,
        response_record: ArtifactRecord | None = None,
        reservation: _ObservationReservationLease,
    ) -> None:
        reservation.require_current_process()
        failure_detail = _reservation_call(
            reservation,
            store.put_artifact,
            _failure_detail_bytes(
                category=failure_category,
                status=failure_status,
                detail=str(original_error),
            ),
            media_type="application/octet-stream",
            retain_content=True,
        )
        _reservation_call(
            reservation,
            custody.append,
            failure_detail.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=ADAPTER_ID,
        )

        outputs_list = [failure_detail.content_identity]
        if response_record is not None:
            outputs_list.insert(0, response_record.content_identity)
        outputs = tuple(outputs_list)

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
        _reservation_call(
            reservation,
            store.put_event,
            failure_event,
        )

        try:
            snapshot = _reservation_call(
                reservation,
                store.finalize,
                scope="closed",
            )
            subjects = (request_record.content_identity,) + outputs
            self._append_verified_custody(
                custody=custody,
                snapshot=snapshot,
                subjects=subjects,
                reservation=reservation,
            )
            reservation.require_current_process()
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
        if not isinstance(store, LocalEvidenceStore):
            raise TypeError("store must be a LocalEvidenceStore")
        if not isinstance(custody, LocalCustodyLedger):
            raise TypeError("custody must be a LocalCustodyLedger")

        with _observation_reservation(store, custody) as reservation:
            return self._observe_generate_reserved(
                model=model,
                prompt=prompt,
                store=store,
                custody=custody,
                options=options,
                reservation=reservation,
            )

    def _observe_generate_reserved(
        self,
        *,
        model: str,
        prompt: str,
        store: LocalEvidenceStore,
        custody: LocalCustodyLedger,
        options: Mapping[str, object] | None = None,
        reservation: _ObservationReservationLease,
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

        reservation.require_current_process()
        self._require_fresh_evidence_targets(
            store=store,
            custody=custody,
        )
        reservation.require_current_process()

        payload: dict[str, object] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if options:
            payload["options"] = dict(options)
        request_bytes = _json_bytes(payload)

        request_clock: ClockObservation = observe_clock()
        request_record = _reservation_call(
            reservation,
            store.put_artifact,
            request_bytes,
            media_type="application/octet-stream",
            retain_content=True,
        )
        _reservation_call(
            reservation,
            custody.append,
            request_record.content_identity,
            CustodyAction.CAPTURED,
            actor=ADAPTER_ID,
            source="adapter-prepared:/api/generate request body",
            clock=request_clock,
        )
        _reservation_call(
            reservation,
            custody.append,
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
        _reservation_call(
            reservation,
            store.put_event,
            request_event,
        )

        reservation.require_current_process()
        try:
            response_bytes = self._post_generate(request_bytes)
        except _TransportFailure as exc:
            reservation.require_current_process()
            response_record: ArtifactRecord | None = None
            if exc.response_bytes is not None:
                response_record = _reservation_call(
                    reservation,
                    store.put_artifact,
                    exc.response_bytes,
                    media_type="application/octet-stream",
                    retain_content=True,
                )
                _reservation_call(
                    reservation,
                    custody.append,
                    response_record.content_identity,
                    CustodyAction.CAPTURED,
                    actor=ADAPTER_ID,
                    source="ollama:/api/generate error response bytes",
                )
                _reservation_call(
                    reservation,
                    custody.append,
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
                failure_category=exc.category,
                failure_status=exc.status,
                response_record=response_record,
                reservation=reservation,
            )
            raise AssertionError("unreachable")

        reservation.require_current_process()
        response_clock: ClockObservation = observe_clock()

        # Retain exactly what was observed before parsing or deriving claims.
        response_record = _reservation_call(
            reservation,
            store.put_artifact,
            response_bytes,
            media_type="application/octet-stream",
            retain_content=True,
        )
        _reservation_call(
            reservation,
            custody.append,
            response_record.content_identity,
            CustodyAction.CAPTURED,
            actor=ADAPTER_ID,
            source="ollama:/api/generate response bytes",
            clock=response_clock,
        )
        _reservation_call(
            reservation,
            custody.append,
            response_record.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=ADAPTER_ID,
        )

        reservation.require_current_process()
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
                failure_category="response_invalid",
                failure_status=200,
                response_record=response_record,
                reservation=reservation,
            )
            raise AssertionError("unreachable")

        reservation.require_current_process()
        declared_model = str(parsed_response["model"])
        response_text = str(parsed_response["response"])

        reservation.require_current_process()
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
        _reservation_call(
            reservation,
            store.put_event,
            response_event,
        )

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
        _reservation_call(
            reservation,
            store.put_event,
            declaration_event,
        )

        snapshot = _reservation_call(
            reservation,
            store.finalize,
            scope="closed",
        )
        if not snapshot.verification.integrity_verified:
            raise OllamaAdapterError(
                "Ollama observation snapshot failed independent verification"
            )

        reservation.require_current_process()
        self._append_verified_custody(
            custody=custody,
            snapshot=snapshot,
            subjects=(
                request_record.content_identity,
                response_record.content_identity,
            ),
            reservation=reservation,
        )

        reservation.require_current_process()
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
