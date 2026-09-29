"""Read-only projection of finalized PROVENANCE evidence for human inspection."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Any

from provenance_core import (
    CanonicalizationError,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_verify import verify_bundle, verify_custody_records


class ViewerError(RuntimeError):
    """Raised when evidence cannot be projected safely without mutation."""


_MAX_STRUCTURED_BYTES = 16 * 1024 * 1024


def _digest(identity: str, *, label: str) -> str:
    require_sha256_identity(identity, label=label)
    return identity.split(":", 1)[1]


def _require_directory(path: Path, *, label: str) -> Path:
    if path.is_symlink():
        raise ViewerError(f"{label} must not be a symbolic link")
    try:
        info = path.stat()
    except FileNotFoundError as exc:
        raise ViewerError(f"{label} does not exist: {path}") from exc
    except OSError as exc:
        raise ViewerError(f"{label} cannot be inspected: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ViewerError(f"{label} must be a directory")
    return path


def _read_regular(path: Path, *, label: str, max_bytes: int = _MAX_STRUCTURED_BYTES) -> bytes:
    if path.is_symlink():
        raise ViewerError(f"{label} must not be a symbolic link")
    try:
        info = path.stat()
    except FileNotFoundError as exc:
        raise ViewerError(f"{label} is missing: {path}") from exc
    except OSError as exc:
        raise ViewerError(f"{label} cannot be inspected: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ViewerError(f"{label} must be a regular file")
    if info.st_size > max_bytes:
        raise ViewerError(f"{label} exceeds viewer structured-data limit")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ViewerError(f"{label} cannot be read: {exc}") from exc


def _read_canonical(path: Path, *, label: str) -> dict[str, Any]:
    raw = _read_regular(path, label=label)
    try:
        value = parse_canonical_json_bytes(raw)
    except (CanonicalizationError, RecursionError) as exc:
        raise ViewerError(f"{label} is not canonical PROVENANCE JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ViewerError(f"{label} must contain a JSON object")
    return value


def _read_head(store_root: Path) -> str | None:
    head = store_root / "HEAD"
    if not head.exists():
        return None
    raw = _read_regular(head, label="store HEAD", max_bytes=256)
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ViewerError("store HEAD must be ASCII") from exc
    if not value.endswith("\n") or value.count("\n") != 1:
        raise ViewerError("store HEAD must contain exactly one identity and LF")
    identity = value[:-1]
    _digest(identity, label="store HEAD manifest identity")
    return identity


def _load_snapshot(store_root: Path) -> dict[str, Any]:
    identity = _read_head(store_root)
    if identity is None:
        return {
            "identity": None,
            "path": None,
            "manifest": None,
            "verification": None,
            "artifacts": [],
            "events": [],
        }

    snapshot = (
        store_root
        / "snapshots"
        / "sha256"
        / _digest(identity, label="manifest identity")
    )
    _require_directory(snapshot, label="current snapshot")
    report = verify_bundle(snapshot)
    manifest = _read_canonical(snapshot / "manifest.json", label="snapshot manifest")
    if manifest.get("manifest_identity") != identity:
        raise ViewerError("snapshot manifest identity does not match store HEAD")

    core = manifest.get("core")
    if not isinstance(core, dict):
        raise ViewerError("snapshot manifest core must be an object")

    artifacts: list[dict[str, Any]] = []
    for entry in core.get("artifacts", []):
        if not isinstance(entry, dict):
            raise ViewerError("manifest artifact entry must be an object")
        content_identity = entry.get("content_identity")
        if not isinstance(content_identity, str):
            raise ViewerError("manifest artifact entry lacks content identity")
        _digest(content_identity, label="artifact content identity")
        record_identity = entry.get("record_identity")
        record: dict[str, Any] | None = None
        if record_identity is not None:
            if not isinstance(record_identity, str):
                raise ViewerError("artifact record identity must be a string")
            record_path = (
                snapshot
                / "artifact_records"
                / "sha256"
                / (_digest(record_identity, label="artifact record identity") + ".json")
            )
            record = _read_canonical(
                record_path,
                label=f"artifact record {record_identity}",
            )
        artifacts.append({
            "identity": content_identity,
            "record_identity": record_identity,
            "retention": entry.get("retention"),
            "media_type": None if record is None else record.get("media_type"),
            "byte_count": None if record is None else record.get("byte_count"),
        })

    events: list[dict[str, Any]] = []
    for event_identity in core.get("events", []):
        if not isinstance(event_identity, str):
            raise ViewerError("manifest event identity must be a string")
        event_path = (
            snapshot
            / "events"
            / "sha256"
            / (_digest(event_identity, label="event identity") + ".json")
        )
        envelope = _read_canonical(event_path, label=f"event {event_identity}")
        event_core = envelope.get("core")
        if not isinstance(event_core, dict):
            raise ViewerError(f"event {event_identity} core must be an object")
        relationships = event_core.get("relationships")
        if not isinstance(relationships, list):
            relationships = []
        events.append({
            "identity": event_identity,
            "evidence_class": event_core.get("evidence_class"),
            "actor": event_core.get("actor"),
            "operation": event_core.get("operation"),
            "inputs": event_core.get("inputs") if isinstance(event_core.get("inputs"), list) else [],
            "outputs": event_core.get("outputs") if isinstance(event_core.get("outputs"), list) else [],
            "relationships": relationships,
            "collection_status": event_core.get("collection_status"),
        })

    return {
        "identity": identity,
        "path": snapshot,
        "manifest": manifest,
        "verification": report,
        "artifacts": artifacts,
        "events": events,
    }


def _load_custody(custody_root: Path) -> dict[str, Any]:
    records_root = custody_root / "records" / "sha256"
    if not records_root.exists():
        return {
            "verification": verify_custody_records(()),
            "records": [],
        }
    _require_directory(records_root, label="custody records directory")

    raws: list[bytes] = []
    records: list[dict[str, Any]] = []
    try:
        entries = sorted(records_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise ViewerError(f"custody records cannot be enumerated: {exc}") from exc
    for entry in entries:
        if entry.is_symlink():
            raise ViewerError(f"custody record must not be a symbolic link: {entry.name}")
        if not entry.name.endswith(".json"):
            raise ViewerError(f"unexpected custody record entry: {entry.name}")
        raw = _read_regular(entry, label=f"custody record {entry.name}")
        try:
            value = parse_canonical_json_bytes(raw)
        except (CanonicalizationError, RecursionError) as exc:
            raise ViewerError(f"custody record {entry.name} is not canonical: {exc}") from exc
        if not isinstance(value, dict):
            raise ViewerError(f"custody record {entry.name} must be an object")
        raws.append(raw)
        core = value.get("core")
        if not isinstance(core, dict):
            raise ViewerError(f"custody record {entry.name} core must be an object")
        records.append({
            "identity": value.get("custody_identity"),
            "subject_identity": core.get("subject_identity"),
            "action": core.get("action"),
            "recorded_at": core.get("recorded_at"),
            "clock_source": core.get("clock_source"),
            "clock_assurance": core.get("clock_assurance"),
            "actor": core.get("actor"),
            "source": core.get("source"),
            "previous_custody": core.get("previous_custody"),
            "related_identity": core.get("related_identity"),
        })

    return {
        "verification": verify_custody_records(raws),
        "records": records,
    }


def _actor_role(actor: object) -> str:
    if not isinstance(actor, str):
        return "actor"
    lowered = actor.lower()
    if lowered.startswith(("human:", "operator:", "user:")):
        return "human"
    if lowered.startswith(("adapter:", "tool:", "cli:", "mcp:", "agent:")):
        return "tool"
    return "actor"


def _build_graph(
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    custody: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    for artifact in artifacts:
        identity = artifact["identity"]
        nodes[identity] = {
            "id": identity,
            "kind": "artifact",
            "label": identity,
            "retention": artifact.get("retention"),
        }

    for event in events:
        identity = event["identity"]
        nodes[identity] = {
            "id": identity,
            "kind": "event",
            "label": event.get("operation") or identity,
            "evidence_class": event.get("evidence_class"),
            "collection_status": event.get("collection_status"),
        }
        actor = event.get("actor")
        if isinstance(actor, str) and actor:
            actor_id = "actor:" + actor
            nodes.setdefault(actor_id, {
                "id": actor_id,
                "kind": _actor_role(actor),
                "label": actor,
                "presentation_derived": True,
            })
            edges.append({"from": actor_id, "to": identity, "kind": "actor"})
        for target in event.get("inputs", []):
            if isinstance(target, str):
                edges.append({"from": target, "to": identity, "kind": "input"})
        for target in event.get("outputs", []):
            if isinstance(target, str):
                edges.append({"from": identity, "to": target, "kind": "output"})
        for relationship in event.get("relationships", []):
            if isinstance(relationship, dict):
                target = relationship.get("target")
                kind = relationship.get("kind")
                if isinstance(target, str) and isinstance(kind, str):
                    edges.append({"from": identity, "to": target, "kind": kind})

    for record in custody:
        identity = record.get("identity")
        if not isinstance(identity, str):
            continue
        nodes[identity] = {
            "id": identity,
            "kind": "custody",
            "label": record.get("action") or identity,
            "recorded_at": record.get("recorded_at"),
        }
        subject = record.get("subject_identity")
        if isinstance(subject, str):
            edges.append({"from": identity, "to": subject, "kind": "custody_of"})
        previous = record.get("previous_custody")
        if isinstance(previous, str):
            edges.append({"from": previous, "to": identity, "kind": "next_custody"})

    return {"nodes": list(nodes.values()), "edges": edges}


def build_view(store_root: Path | str, custody_root: Path | str) -> dict[str, Any]:
    """Build one read-only presentation snapshot from on-disk evidence."""
    store = _require_directory(Path(store_root).expanduser(), label="store root")
    custody = _require_directory(Path(custody_root).expanduser(), label="custody root")
    snapshot = _load_snapshot(store)
    custody_view = _load_custody(custody)

    manifest = snapshot["manifest"]
    artifacts = snapshot["artifacts"]
    events = snapshot["events"]
    custody_records = custody_view["records"]

    custody_by_subject: dict[str, list[dict[str, Any]]] = {}
    for record in custody_records:
        subject = record.get("subject_identity")
        if isinstance(subject, str):
            custody_by_subject.setdefault(subject, []).append(record)

    event_links: dict[str, list[str]] = {}
    for event in events:
        identity = event["identity"]
        for target in list(event.get("inputs", [])) + list(event.get("outputs", [])):
            if isinstance(target, str):
                event_links.setdefault(target, []).append(identity)

    for artifact in artifacts:
        identity = artifact["identity"]
        artifact["events"] = sorted(set(event_links.get(identity, [])))
        artifact["custody"] = custody_by_subject.get(identity, [])
        artifact["sources"] = sorted({
            record["source"]
            for record in artifact["custody"]
            if isinstance(record.get("source"), str)
        })

    evidence_subjects: set[str] = set()
    if isinstance(snapshot["identity"], str):
        evidence_subjects.add(snapshot["identity"])
    evidence_subjects.update(item["identity"] for item in artifacts)
    evidence_subjects.update(item["identity"] for item in events)
    custody_subjects = set(custody_by_subject)
    missing_custody = sorted(evidence_subjects - custody_subjects)

    bundle_report = snapshot["verification"]
    custody_report = custody_view["verification"]
    if bundle_report is None:
        integrity_status = "NOT_PRESENT"
    else:
        integrity_status = "VERIFIED" if bundle_report.integrity_verified else "FAILED"

    if not custody_records:
        custody_status = "NOT_PRESENT"
    elif not custody_report.integrity_verified:
        custody_status = "INVALID"
    elif missing_custody:
        custody_status = "PARTIAL"
    else:
        custody_status = "VERIFIED"

    gaps: list[dict[str, Any]] = []
    if manifest is None:
        gaps.append({"kind": "NO_FINALIZED_SNAPSHOT", "detail": "Store has no finalized HEAD snapshot."})
    else:
        core = manifest.get("core")
        if isinstance(core, dict) and core.get("scope") == "open":
            gaps.append({"kind": "OPEN_COLLECTION", "detail": "Manifest scope is open."})
    for artifact in artifacts:
        if artifact.get("retention") == "MISSING":
            gaps.append({
                "kind": "MISSING_ARTIFACT",
                "identity": artifact["identity"],
                "detail": "Manifest declares artifact content as missing.",
            })
    for event in events:
        if event.get("collection_status") != "RECORDED":
            gaps.append({
                "kind": "COLLECTION_STATUS",
                "identity": event["identity"],
                "detail": f"Event collection status is {event.get('collection_status')}.",
            })
    if events:
        gaps.append({
            "kind": "UNTIMED_EVENTS",
            "count": len(events),
            "detail": "Event schema v1 contains no event timestamp; custody timestamps must not be promoted into event times.",
        })
    if missing_custody:
        gaps.append({
            "kind": "PARTIAL_CUSTODY_COVERAGE",
            "count": len(missing_custody),
            "identities": missing_custody,
            "detail": "Verified custody records do not cover every finalized evidence identity.",
        })
    if bundle_report is not None and not bundle_report.integrity_verified:
        gaps.append({
            "kind": "INTEGRITY_VERIFICATION_FAILED",
            "detail": list(bundle_report.errors),
        })
    if not custody_report.integrity_verified:
        gaps.append({
            "kind": "CUSTODY_VERIFICATION_FAILED",
            "detail": list(custody_report.errors),
        })

    timeline = sorted(
        custody_records,
        key=lambda item: (
            "" if item.get("recorded_at") is None else str(item.get("recorded_at")),
            "" if item.get("identity") is None else str(item.get("identity")),
        ),
    )

    return {
        "schema": "provenance.ui-view.v1",
        "authority": "READ_ONLY_PRESENTATION",
        "summary": {
            "manifest_identity": snapshot["identity"],
            "manifest_scope": None if bundle_report is None else bundle_report.manifest_scope,
            "artifact_count": len(artifacts),
            "event_count": len(events),
            "custody_record_count": len(custody_records),
            "known_missing_artifacts": 0 if bundle_report is None else bundle_report.known_missing_artifacts,
        },
        "verification": {
            "integrity": integrity_status,
            "custody": custody_status,
            "signature": "NOT_PRESENT",
            "replay": "NOT_ATTEMPTED",
            "integrity_report": None if bundle_report is None else bundle_report.to_dict(),
            "custody_report": custody_report.to_dict(),
        },
        "graph": _build_graph(artifacts, events, custody_records),
        "timeline": {
            "timestamped_custody": timeline,
            "untimed_events": events,
            "ordering_note": "Custody chains use previous_custody. Event ordering remains partial unless evidence relationships establish it.",
        },
        "artifacts": artifacts,
        "events": events,
        "custody": custody_records,
        "gaps": gaps,
    }


@dataclass(frozen=True, slots=True)
class ProvenanceViewer:
    store_root: Path
    custody_root: Path

    def __init__(self, store_root: Path | str, custody_root: Path | str):
        object.__setattr__(self, "store_root", Path(store_root).expanduser())
        object.__setattr__(self, "custody_root", Path(custody_root).expanduser())

    def snapshot(self) -> dict[str, Any]:
        return build_view(self.store_root, self.custody_root)
