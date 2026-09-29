"""Dependency-free MCP stdio interface for PROVENANCE Phase 7."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any, BinaryIO, Iterator, TextIO
from urllib.parse import urlsplit
import uuid

from provenance_core import (
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    Relationship,
    artifact_record_identity,
    canonical_json_bytes,
    custody_identity,
    event_identity,
    manifest_identity,
    parse_canonical_json_bytes,
    require_sha256_identity,
    sha256_identity,
)
from provenance_custody import LocalCustodyLedger, observe_clock
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


MCP_INTERFACE_ID = "provenance-mcp:stdio/v1"
MCP_SERVER_INFO = {
    "name": "provenance-mcp",
    "version": "0.1.0",
}
MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (
    MODERN_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSION,
)
_SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
_PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
_CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
_CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_DIGEST_LENGTH = 64

_CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {
        "subscribe": False,
        "listChanged": False,
    },
}
_INSTRUCTIONS = (
    "PROVENANCE records evidence. Values supplied through provenance.record "
    "remain DECLARED; the MCP call receipt is recorded separately as OBSERVED."
)


class MCPProtocolError(ValueError):
    """JSON-RPC/MCP protocol error."""

    def __init__(self, code: int, message: str, data: object | None = None):
        super().__init__(message)
        self.code = code
        self.data = data


class ToolFailure(RuntimeError):
    """Expected tool failure returned as an MCP tool result."""


class ResourceNotFoundError(LookupError):
    """Requested provenance resource does not exist."""


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _reject_duplicate_json_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_nonfinite_json(token: str):
    raise ValueError(f"non-finite JSON token {token}")


def _require_object(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    *,
    required: set[str] = frozenset(),
    optional: set[str] = frozenset(),
    label: str,
) -> None:
    actual = set(value)
    missing = required - actual
    extra = actual - required - optional
    if missing:
        raise ValueError(
            f"{label} missing required fields: {', '.join(sorted(missing))}"
        )
    if extra:
        raise ValueError(
            f"{label} contains unsupported fields: {', '.join(sorted(extra))}"
        )


def _require_nonempty_string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _digest(identity: object, *, label: str) -> str:
    try:
        require_sha256_identity(identity, label=label)
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    assert isinstance(identity, str)
    return identity.split(":", 1)[1]


def _directory_flags() -> int:
    missing = [
        name
        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
        if not hasattr(os, name)
    ]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if missing:
        raise RuntimeError(
            "MCP evidence resources require secure descriptor-relative reads: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0)
    )


def _read_regular(root: Path, parts: tuple[str, ...], *, label: str) -> bytes:
    if not parts or any(
        not part or part in {".", ".."} or "/" in part
        for part in parts
    ):
        raise ValueError(f"unsafe {label} path")
    try:
        current_fd = os.open(root, _directory_flags())
    except OSError as exc:
        raise ValueError(f"{label} root cannot be opened safely: {exc}") from exc
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current_fd,
                )
            except FileNotFoundError as exc:
                raise ResourceNotFoundError(
                    f"{label} does not exist"
                ) from exc
            except OSError as exc:
                raise ValueError(
                    f"{label} parent is unsafe: {exc}"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd

        try:
            fd = os.open(
                parts[-1],
                _file_flags(),
                dir_fd=current_fd,
            )
        except FileNotFoundError as exc:
            raise ResourceNotFoundError(
                f"{label} does not exist"
            ) from exc
        except OSError as exc:
            raise ValueError(f"{label} is unsafe: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError(f"{label} must be a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        finally:
            os.close(fd)
    finally:
        os.close(current_fd)


def _canonical_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = parse_canonical_json_bytes(data)
    except Exception as exc:
        raise ValueError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_envelope_identity(
    value: dict[str, Any],
    *,
    expected_identity: str,
    identity_field: str,
    identity_function,
    label: str,
) -> None:
    if value.get("self_hash_exclusion") != identity_field:
        raise ValueError(f"{label} self_hash_exclusion changed")
    if value.get(identity_field) != expected_identity:
        raise ValueError(f"{label} claimed identity does not match resource URI")
    core = value.get("core")
    if not isinstance(core, dict):
        raise ValueError(f"{label} core must be an object")
    try:
        computed = identity_function(core)
    except Exception as exc:
        raise ValueError(f"{label} identity cannot be recomputed: {exc}") from exc
    if computed != expected_identity:
        raise ValueError(f"{label} content does not match resource identity")


def _tool_text(payload: object, *, is_error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": _json_text(payload)}],
    }
    if isinstance(payload, (dict, list)):
        result["structuredContent"] = payload
    if is_error:
        result["isError"] = True
    return result


TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "provenance.finalize",
        "description": (
            "Finalize the current local evidence store through the existing "
            "verifier and record VERIFIED custody."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["open", "closed"],
                    "default": "closed",
                }
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    },
    {
        "name": "provenance.inspect",
        "description": (
            "Inspect the current manifest or resolve an evidence identity to "
            "its provenance:// resource."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "provenance.record",
        "description": (
            "Record caller-supplied JSON as DECLARED evidence and separately "
            "record the MCP call occurrence as an OBSERVED receipt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "actor": {"type": "string", "minLength": 1},
                "operation": {"type": "string", "minLength": 1},
                "value": {},
                "retainContent": {
                    "type": "boolean",
                    "default": True,
                },
            },
            "required": ["actor", "operation", "value"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    },
    {
        "name": "provenance.verify",
        "description": (
            "Independently verify the current finalized evidence snapshot and "
            "the local custody ledger."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "provenance.export",
        "description": (
            "Copy the current immutable verified evidence snapshot to a new "
            "destination directory and record EXPORTED custody for its manifest."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string", "minLength": 1},
            },
            "required": ["destination"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    },
)

RESOURCE_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "uriTemplate": "provenance://artifact/{identity}",
        "name": "PROVENANCE artifact",
        "description": "Retained artifact bytes or explicit retention metadata.",
    },
    {
        "uriTemplate": "provenance://custody/{identity}",
        "name": "PROVENANCE custody record",
        "description": "Canonical custody envelope by custody identity.",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "provenance://event/{identity}",
        "name": "PROVENANCE event",
        "description": "Canonical event envelope by event identity.",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "provenance://manifest/{identity}",
        "name": "PROVENANCE manifest",
        "description": "Canonical immutable snapshot manifest.",
        "mimeType": "application/json",
    },
)


class ProvenanceMCPServer:
    """One stdio MCP server process backed by local PROVENANCE modules."""

    def __init__(self, store_root: Path | str, custody_root: Path | str):
        self.store = LocalEvidenceStore(store_root)
        self.custody = LocalCustodyLedger(custody_root)
        self._era: str | None = None
        self._legacy_initialized = False
        self._pending_artifacts: set[str] = set()

    def _append_custody(
        self,
        subject_identity: str,
        action: CustodyAction,
        *,
        actor: str,
        source: str,
        related_identity: str | None = None,
    ) -> str:
        envelope = self.custody.append(
            subject_identity,
            action,
            actor=actor,
            source=source,
            related_identity=related_identity,
            clock=observe_clock(),
        )
        return envelope.custody_identity

    def _record(self, arguments: object) -> dict[str, Any]:
        args = _require_object(arguments, label="provenance.record arguments")
        _require_exact_keys(
            args,
            required={"actor", "operation", "value"},
            optional={"retainContent"},
            label="provenance.record arguments",
        )
        actor = _require_nonempty_string(args["actor"], label="actor")
        operation = _require_nonempty_string(
            args["operation"],
            label="operation",
        )
        retain_content = args.get("retainContent", True)
        if type(retain_content) is not bool:
            raise ValueError("retainContent must be a boolean")

        declaration_bytes = canonical_json_bytes(
            {
                "schema": "provenance.mcp-declaration.v1",
                "actor": actor,
                "operation": operation,
                "value": args["value"],
            }
        )
        declaration = self.store.put_artifact(
            declaration_bytes,
            media_type="application/json",
            retain_content=retain_content,
        )
        self._append_custody(
            declaration.content_identity,
            CustodyAction.CAPTURED,
            actor=MCP_INTERFACE_ID,
            source="mcp:provenance.record declaration",
        )
        self._append_custody(
            declaration.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=MCP_INTERFACE_ID,
        )

        declaration_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.DECLARED,
                actor=actor,
                operation=operation,
                outputs=(declaration.content_identity,),
            )
        )
        self.store.put_event(declaration_event)

        receipt_bytes = canonical_json_bytes(
            {
                "schema": "provenance.mcp-receipt.v1",
                "interface": MCP_INTERFACE_ID,
                "invocation_id": uuid.uuid4().hex,
                "declaration_identity": declaration.content_identity,
            }
        )
        receipt = self.store.put_artifact(
            receipt_bytes,
            media_type="application/json",
            retain_content=True,
        )
        self._append_custody(
            receipt.content_identity,
            CustodyAction.CAPTURED,
            actor=MCP_INTERFACE_ID,
            source="mcp:provenance.record receipt",
        )
        self._append_custody(
            receipt.content_identity,
            CustodyAction.STORED,
            actor="provenance-store:local",
            source=MCP_INTERFACE_ID,
        )

        receipt_event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor=MCP_INTERFACE_ID,
                operation="provenance.mcp.record.received",
                inputs=(declaration.content_identity,),
                outputs=(receipt.content_identity,),
                relationships=(
                    Relationship(
                        "records_declaration",
                        declaration_event.event_identity,
                    ),
                ),
            )
        )
        self.store.put_event(receipt_event)
        self._pending_artifacts.update(
            (
                declaration.content_identity,
                receipt.content_identity,
            )
        )

        return {
            "classification": "DECLARED",
            "occurrence_classification": "OBSERVED",
            "declaration_artifact_identity": declaration.content_identity,
            "declaration_event_identity": declaration_event.event_identity,
            "receipt_artifact_identity": receipt.content_identity,
            "receipt_event_identity": receipt_event.event_identity,
            "retain_content": retain_content,
        }

    def _finalize(self, arguments: object) -> dict[str, Any]:
        args = _require_object(arguments, label="provenance.finalize arguments")
        _require_exact_keys(
            args,
            optional={"scope"},
            label="provenance.finalize arguments",
        )
        scope = args.get("scope", "closed")
        if scope not in {"open", "closed"}:
            raise ValueError("scope must be 'open' or 'closed'")

        snapshot = self.store.finalize(scope=scope)
        for identity in sorted(self._pending_artifacts):
            self._append_custody(
                identity,
                CustodyAction.VERIFIED,
                actor="provenance-verify",
                source=MCP_INTERFACE_ID,
                related_identity=snapshot.manifest_identity,
            )
        self._append_custody(
            snapshot.manifest_identity,
            CustodyAction.VERIFIED,
            actor="provenance-verify",
            source=MCP_INTERFACE_ID,
        )
        custody_report = self.custody.verify()
        if not custody_report.integrity_verified:
            raise ToolFailure(
                "custody verification failed after finalization: "
                + "; ".join(custody_report.errors)
            )
        self._pending_artifacts.clear()

        return {
            "manifest_identity": snapshot.manifest_identity,
            "resource_uri": (
                f"provenance://manifest/{snapshot.manifest_identity}"
            ),
            "scope": scope,
            "integrity_verified": snapshot.verification.integrity_verified,
            "custody_verified": custody_report.integrity_verified,
        }

    def _verify(self, arguments: object) -> dict[str, Any]:
        args = _require_object(arguments, label="provenance.verify arguments")
        _require_exact_keys(args, label="provenance.verify arguments")
        verification = self.store.verify_current()
        custody_report = self.custody.verify()
        return {
            "bundle": verification.to_dict(),
            "custody": custody_report.to_dict(),
        }

    def _current_manifest_object(self) -> dict[str, Any] | None:
        identity = self.store.current_manifest_identity
        if identity is None:
            return None
        digest = _digest(identity, label="current manifest identity")
        data = _read_regular(
            self.store.root,
            (
                "snapshots",
                "sha256",
                digest,
                "manifest.json",
            ),
            label="manifest resource",
        )
        value = _canonical_object(data, label="manifest resource")
        _require_envelope_identity(
            value,
            expected_identity=identity,
            identity_field="manifest_identity",
            identity_function=manifest_identity,
            label="manifest resource",
        )
        return value

    def _artifact_record_entry(
        self,
        content_identity: str,
    ) -> tuple[str, dict[str, Any]] | None:
        _digest(content_identity, label="artifact identity")
        records = self.store.root / "objects" / "artifact_records" / "sha256"
        try:
            entries = sorted(records.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise ValueError(
                f"artifact record directory cannot be enumerated: {exc}"
            ) from exc

        matches: list[tuple[str, dict[str, Any]]] = []
        for entry in entries:
            if (
                entry.is_symlink()
                or not entry.is_file()
                or not entry.name.endswith(".json")
                or not _SHA256_RE.fullmatch(entry.name[:-5])
            ):
                raise ValueError(
                    f"unsafe or unexpected artifact record entry: {entry.name}"
                )
            data = _read_regular(
                self.store.root,
                (
                    "objects",
                    "artifact_records",
                    "sha256",
                    entry.name,
                ),
                label="artifact record",
            )
            value = _canonical_object(data, label="artifact record")
            try:
                computed_identity = artifact_record_identity(value)
            except Exception as exc:
                raise ValueError(
                    f"artifact record identity cannot be recomputed: {exc}"
                ) from exc
            if entry.name != computed_identity.split(":", 1)[1] + ".json":
                raise ValueError(
                    "artifact record filename does not match record identity"
                )
            if value.get("content_identity") == content_identity:
                matches.append((computed_identity, value))

        if not matches:
            return None
        if len(matches) > 1:
            manifest = self._current_manifest_object()
            if manifest is not None:
                core = manifest.get("core")
                if isinstance(core, dict):
                    artifacts = core.get("artifacts")
                    if isinstance(artifacts, list):
                        for item in artifacts:
                            if (
                                isinstance(item, dict)
                                and item.get("content_identity") == content_identity
                            ):
                                bound = item.get("record_identity")
                                for record_identity_value, value in matches:
                                    if record_identity_value == bound:
                                        return record_identity_value, value
            raise ValueError(
                "artifact identity is bound by multiple record identities "
                "without one current manifest binding"
            )
        return matches[0]

    def _artifact_record(
        self,
        content_identity: str,
    ) -> dict[str, Any] | None:
        entry = self._artifact_record_entry(content_identity)
        return entry[1] if entry is not None else None

    def _inspect(self, arguments: object) -> dict[str, Any]:
        args = _require_object(arguments, label="provenance.inspect arguments")
        _require_exact_keys(
            args,
            optional={"identity"},
            label="provenance.inspect arguments",
        )
        identity = args.get("identity")
        if identity is None:
            manifest = self._current_manifest_object()
            return {
                "current_manifest_identity": self.store.current_manifest_identity,
                "artifact_count": self.store.artifact_count,
                "event_count": self.store.event_count,
                "manifest": manifest,
            }

        digest = _digest(identity, label="inspect identity")
        assert isinstance(identity, str)

        manifest_path = self.store.root / "snapshots" / "sha256" / digest
        if manifest_path.is_dir() and not manifest_path.is_symlink():
            return {
                "kind": "manifest",
                "identity": identity,
                "resource_uri": f"provenance://manifest/{identity}",
            }

        event_path = (
            self.store.root
            / "objects"
            / "events"
            / "sha256"
            / f"{digest}.json"
        )
        if event_path.is_file() and not event_path.is_symlink():
            return {
                "kind": "event",
                "identity": identity,
                "resource_uri": f"provenance://event/{identity}",
            }

        custody_path = (
            self.custody.root
            / "records"
            / "sha256"
            / f"{digest}.json"
        )
        if custody_path.is_file() and not custody_path.is_symlink():
            return {
                "kind": "custody",
                "identity": identity,
                "resource_uri": f"provenance://custody/{identity}",
            }

        record_entry = self._artifact_record_entry(identity)
        if record_entry is not None:
            record_identity_value, record = record_entry
            return {
                "kind": "artifact",
                "identity": identity,
                "retention": record.get("retention"),
                "media_type": record.get("media_type"),
                "byte_count": record.get("byte_count"),
                "record_identity": record_identity_value,
                "resource_uri": f"provenance://artifact/{identity}",
            }

        raise ValueError(f"unknown evidence identity: {identity}")

    def _export(self, arguments: object) -> dict[str, Any]:
        args = _require_object(arguments, label="provenance.export arguments")
        _require_exact_keys(
            args,
            required={"destination"},
            label="provenance.export arguments",
        )
        destination_text = _require_nonempty_string(
            args["destination"],
            label="destination",
        )
        snapshot = self.store.current_snapshot_path()
        manifest_identity = self.store.current_manifest_identity
        if snapshot is None or manifest_identity is None:
            raise ToolFailure("store has no finalized snapshot to export")
        current_report = self.store.verify_current()
        if not current_report.integrity_verified:
            raise ToolFailure("current snapshot failed verification before export")

        supplied = Path(destination_text).expanduser()
        if supplied.is_symlink() or supplied.exists():
            raise ValueError("export destination must not already exist")
        destination = supplied.resolve(strict=False)
        parent = destination.parent
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError(
                "export destination parent must be an existing non-symlink directory"
            )

        try:
            shutil.copytree(snapshot, destination, symlinks=True)
            exported_report = verify_bundle(destination)
            if (
                not exported_report.integrity_verified
                or exported_report.manifest_identity != manifest_identity
            ):
                raise ToolFailure(
                    "exported snapshot failed independent verification"
                )
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise

        custody_identity = self._append_custody(
            manifest_identity,
            CustodyAction.EXPORTED,
            actor=MCP_INTERFACE_ID,
            source=str(destination),
        )
        custody_report = self.custody.verify()
        if not custody_report.integrity_verified:
            raise ToolFailure(
                "custody verification failed after export: "
                + "; ".join(custody_report.errors)
            )
        return {
            "manifest_identity": manifest_identity,
            "destination": str(destination),
            "integrity_verified": exported_report.integrity_verified,
            "custody_identity": custody_identity,
            "custody_verified": custody_report.integrity_verified,
        }

    def call_tool(self, name: str, arguments: object) -> dict[str, Any]:
        handlers = {
            "provenance.record": self._record,
            "provenance.inspect": self._inspect,
            "provenance.verify": self._verify,
            "provenance.finalize": self._finalize,
            "provenance.export": self._export,
        }
        handler = handlers.get(name)
        if handler is None:
            raise MCPProtocolError(-32602, f"unknown tool: {name}")
        try:
            return _tool_text(handler(arguments))
        except MCPProtocolError:
            raise
        except Exception as exc:
            return _tool_text(
                {
                    "error": type(exc).__name__,
                    "detail": str(exc),
                },
                is_error=True,
            )

    def _list_custody_identities(self) -> list[str]:
        report = self.custody.verify()
        if not report.integrity_verified:
            raise ValueError(
                "custody ledger failed verification: "
                + "; ".join(report.errors)
            )
        records = self.custody.root / "records" / "sha256"
        identities: list[str] = []
        for entry in sorted(records.iterdir(), key=lambda item: item.name):
            if (
                entry.is_symlink()
                or not entry.is_file()
                or not entry.name.endswith(".json")
                or not _SHA256_RE.fullmatch(entry.name[:-5])
            ):
                raise ValueError(
                    f"unsafe or unexpected custody entry: {entry.name}"
                )
            identities.append("sha256:" + entry.name[:-5])
        return identities

    def list_resources(self) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        manifest = self._current_manifest_object()
        if manifest is not None:
            manifest_identity = manifest["manifest_identity"]
            assert isinstance(manifest_identity, str)
            resources.append(
                {
                    "uri": f"provenance://manifest/{manifest_identity}",
                    "name": f"Manifest {manifest_identity}",
                    "mimeType": "application/json",
                }
            )
            core = manifest.get("core")
            if isinstance(core, dict):
                events = core.get("events")
                if isinstance(events, list):
                    for identity in events:
                        if isinstance(identity, str):
                            resources.append(
                                {
                                    "uri": f"provenance://event/{identity}",
                                    "name": f"Event {identity}",
                                    "mimeType": "application/json",
                                }
                            )
                artifacts = core.get("artifacts")
                if isinstance(artifacts, list):
                    for item in artifacts:
                        if not isinstance(item, dict):
                            continue
                        identity = item.get("content_identity")
                        if not isinstance(identity, str):
                            continue
                        record = self._artifact_record(identity)
                        media_type = (
                            record.get("media_type")
                            if isinstance(record, dict)
                            else None
                        )
                        resource = {
                            "uri": f"provenance://artifact/{identity}",
                            "name": f"Artifact {identity}",
                        }
                        if isinstance(media_type, str):
                            resource["mimeType"] = media_type
                        resources.append(resource)

        for identity in self._list_custody_identities():
            resources.append(
                {
                    "uri": f"provenance://custody/{identity}",
                    "name": f"Custody {identity}",
                    "mimeType": "application/json",
                }
            )
        return sorted(resources, key=lambda item: str(item["uri"]))

    def _read_resource(self, uri: object) -> dict[str, Any]:
        if not isinstance(uri, str) or not uri:
            raise MCPProtocolError(-32602, "resource uri must be a non-empty string")
        parsed = urlsplit(uri)
        if parsed.scheme != "provenance" or parsed.query or parsed.fragment:
            raise MCPProtocolError(-32602, "unsupported provenance resource uri")
        kind = parsed.netloc
        identity = parsed.path.removeprefix("/")
        try:
            digest = _digest(identity, label="resource identity")
        except ValueError as exc:
            raise MCPProtocolError(-32602, str(exc)) from exc

        if kind == "event":
            data = _read_regular(
                self.store.root,
                (
                    "objects",
                    "events",
                    "sha256",
                    f"{digest}.json",
                ),
                label="event resource",
            )
            value = _canonical_object(data, label="event resource")
            _require_envelope_identity(
                value,
                expected_identity=identity,
                identity_field="event_identity",
                identity_function=event_identity,
                label="event resource",
            )
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": data.decode("utf-8"),
                    }
                ]
            }

        if kind == "custody":
            data = _read_regular(
                self.custody.root,
                (
                    "records",
                    "sha256",
                    f"{digest}.json",
                ),
                label="custody resource",
            )
            value = _canonical_object(data, label="custody resource")
            _require_envelope_identity(
                value,
                expected_identity=identity,
                identity_field="custody_identity",
                identity_function=custody_identity,
                label="custody resource",
            )
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": data.decode("utf-8"),
                    }
                ]
            }

        if kind == "manifest":
            data = _read_regular(
                self.store.root,
                (
                    "snapshots",
                    "sha256",
                    digest,
                    "manifest.json",
                ),
                label="manifest resource",
            )
            value = _canonical_object(data, label="manifest resource")
            _require_envelope_identity(
                value,
                expected_identity=identity,
                identity_field="manifest_identity",
                identity_function=manifest_identity,
                label="manifest resource",
            )
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": data.decode("utf-8"),
                    }
                ]
            }

        if kind == "artifact":
            record = self._artifact_record(identity)
            if record is None:
                raise MCPProtocolError(-32602, "artifact identity is unknown")
            retention = record.get("retention")
            if retention != "CONTENT_RETAINED":
                return {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": _json_text(
                                {
                                    "content_identity": identity,
                                    "retention": retention,
                                    "byte_count": record.get("byte_count"),
                                    "media_type": record.get("media_type"),
                                    "content_available": False,
                                }
                            ),
                        }
                    ]
                }
            data = _read_regular(
                self.store.root,
                (
                    "objects",
                    "artifacts",
                    "sha256",
                    digest,
                ),
                label="artifact resource",
            )
            if len(data) != record.get("byte_count"):
                raise ValueError("artifact byte count changed")
            if sha256_identity(data) != identity:
                raise ValueError(
                    "artifact content does not match resource identity"
                )
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": str(
                            record.get("media_type")
                            or "application/octet-stream"
                        ),
                        "blob": base64.b64encode(data).decode("ascii"),
                    }
                ]
            }

        raise MCPProtocolError(-32602, f"unsupported resource kind: {kind}")

    def read_resource(self, uri: object) -> dict[str, Any]:
        try:
            return self._read_resource(uri)
        except MCPProtocolError:
            raise
        except ResourceNotFoundError as exc:
            data = {"uri": uri} if isinstance(uri, str) else None
            raise MCPProtocolError(
                -32602,
                str(exc),
                data,
            ) from exc

    def _modern_params(self, params: object) -> bool:
        if not isinstance(params, dict):
            return False
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            return False
        return _PROTOCOL_VERSION_META_KEY in meta

    def _validate_modern_envelope(self, params: object) -> None:
        if not isinstance(params, dict):
            raise MCPProtocolError(-32602, "modern request params must be an object")
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            raise MCPProtocolError(-32602, "modern request requires params._meta")
        if meta.get(_PROTOCOL_VERSION_META_KEY) != MODERN_PROTOCOL_VERSION:
            raise MCPProtocolError(
                -32022,
                "unsupported MCP protocol version",
                {"supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS)},
            )
        client_info = meta.get(_CLIENT_INFO_META_KEY)
        if client_info is not None and (
            not isinstance(client_info, dict)
            or not isinstance(client_info.get("name"), str)
            or not isinstance(client_info.get("version"), str)
        ):
            raise MCPProtocolError(-32602, "clientInfo metadata is malformed")
        capabilities = meta.get(_CLIENT_CAPABILITIES_META_KEY)
        if capabilities is not None and not isinstance(capabilities, dict):
            raise MCPProtocolError(
                -32602,
                "clientCapabilities metadata must be an object",
            )

    def _modernize(
        self,
        result: dict[str, Any],
        *,
        cacheable: bool = False,
    ) -> dict[str, Any]:
        value = dict(result)
        value["resultType"] = "complete"
        meta = value.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
        meta[_SERVER_INFO_META_KEY] = dict(MCP_SERVER_INFO)
        value["_meta"] = meta
        if cacheable:
            value["ttlMs"] = 0
            value["cacheScope"] = "private"
        return value

    def _pin_era(self, era: str) -> None:
        if self._era is None:
            self._era = era
            return
        if self._era != era:
            raise MCPProtocolError(
                -32600,
                f"MCP connection is already pinned to {self._era} era",
            )

    def _initialize(self, params: object) -> dict[str, Any]:
        self._pin_era("legacy")
        value = _require_object(params, label="initialize params")
        proposed = value.get("protocolVersion")
        if not isinstance(proposed, str):
            raise MCPProtocolError(
                -32602,
                "initialize protocolVersion must be a string",
            )
        self._legacy_initialized = True
        return {
            "protocolVersion": (
                proposed
                if proposed == LEGACY_PROTOCOL_VERSION
                else LEGACY_PROTOCOL_VERSION
            ),
            "capabilities": _CAPABILITIES,
            "serverInfo": MCP_SERVER_INFO,
            "instructions": _INSTRUCTIONS,
        }

    def _discover(self, params: object) -> dict[str, Any]:
        self._pin_era("modern")
        self._validate_modern_envelope(params)
        return self._modernize(
            {
                "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "capabilities": _CAPABILITIES,
                "instructions": _INSTRUCTIONS,
            },
            cacheable=True,
        )

    def dispatch(self, request: object) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            raise MCPProtocolError(-32600, "JSON-RPC request must be an object")
        if request.get("jsonrpc") != "2.0":
            raise MCPProtocolError(-32600, "jsonrpc must equal '2.0'")
        method = request.get("method")
        if not isinstance(method, str) or not method:
            raise MCPProtocolError(-32600, "method must be a non-empty string")
        params = request.get("params", {})
        request_id = request.get("id", None)
        is_notification = "id" not in request

        if method == "initialize":
            if is_notification:
                raise MCPProtocolError(-32600, "initialize must be a request")
            return self._initialize(params)

        if method == "server/discover":
            if is_notification:
                raise MCPProtocolError(-32600, "server/discover must be a request")
            return self._discover(params)

        if method == "notifications/initialized":
            if not is_notification:
                raise MCPProtocolError(
                    -32600,
                    "notifications/initialized must not contain an id",
                )
            if self._era != "legacy" or not self._legacy_initialized:
                raise MCPProtocolError(
                    -32600,
                    "server is not initialized for legacy MCP",
                )
            return None

        modern = self._modern_params(params)
        if modern:
            self._pin_era("modern")
            self._validate_modern_envelope(params)
        else:
            self._pin_era("legacy")
            if not self._legacy_initialized:
                raise MCPProtocolError(
                    -32600,
                    "legacy MCP request received before initialize",
                )

        if is_notification:
            # Phase 7 has no client notification surface beyond initialized.
            return None

        if method == "ping":
            if modern:
                raise MCPProtocolError(
                    -32601,
                    "method not found: ping",
                )
            result: dict[str, Any] = {}
        elif method == "tools/list":
            result = {"tools": list(TOOLS)}
        elif method == "tools/call":
            value = _require_object(params, label="tools/call params")
            name = _require_nonempty_string(value.get("name"), label="tool name")
            arguments = value.get("arguments", {})
            result = self.call_tool(name, arguments)
        elif method == "resources/list":
            result = {"resources": self.list_resources()}
        elif method == "resources/templates/list":
            result = {"resourceTemplates": list(RESOURCE_TEMPLATES)}
        elif method == "resources/read":
            value = _require_object(params, label="resources/read params")
            result = self.read_resource(value.get("uri"))
        else:
            raise MCPProtocolError(-32601, f"method not found: {method}")

        if modern:
            return self._modernize(
                result,
                cacheable=method in {
                    "tools/list",
                    "resources/list",
                    "resources/templates/list",
                    "resources/read",
                },
            )
        return result


def _response(
    request_id: object,
    *,
    result: object | None = None,
    error: MCPProtocolError | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
    }
    if error is None:
        value["result"] = result
    else:
        error_value: dict[str, Any] = {
            "code": error.code,
            "message": str(error),
        }
        if error.data is not None:
            error_value["data"] = error.data
        value["error"] = error_value
    return value


def serve_stdio(
    server: ProvenanceMCPServer,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    input_stream = stdin if stdin is not None else sys.stdin
    output_stream = stdout if stdout is not None else sys.stdout

    for line in input_stream:
        if not line.strip():
            continue
        request_id: object = None
        has_id = False
        try:
            try:
                request = json.loads(
                    line,
                    object_pairs_hook=_reject_duplicate_json_pairs,
                    parse_constant=_reject_nonfinite_json,
                )
            except (json.JSONDecodeError, ValueError, RecursionError) as exc:
                detail = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
                raise MCPProtocolError(
                    -32700,
                    f"parse error: {detail}",
                ) from exc
            if isinstance(request, dict) and "id" in request:
                has_id = True
                request_id = request.get("id")
            result = server.dispatch(request)
            if not has_id:
                continue
            response = _response(request_id, result=result)
        except MCPProtocolError as exc:
            if not has_id and exc.code != -32700:
                continue
            response = _response(request_id, error=exc)
        except Exception as exc:
            if not has_id:
                continue
            response = _response(
                request_id,
                error=MCPProtocolError(
                    -32603,
                    "internal error",
                    {"type": type(exc).__name__, "detail": str(exc)},
                ),
            )
        output_stream.write(_json_text(response) + "\n")
        output_stream.flush()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m provenance_mcp",
        description="Serve the PROVENANCE Phase 7 MCP interface over stdio.",
    )
    parser.add_argument(
        "--store",
        required=True,
        help="LocalEvidenceStore root directory.",
    )
    parser.add_argument(
        "--custody",
        required=True,
        help="LocalCustodyLedger root directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = ProvenanceMCPServer(args.store, args.custody)
    serve_stdio(server)
    return 0
