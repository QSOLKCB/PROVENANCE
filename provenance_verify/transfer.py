"""Independent verification for Phase 15 distributed custody."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Any

from provenance_core import (
    CANONICALIZATION_ID,
    ClockAssurance,
    CustodyAction,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_transfer.model import (
    TRANSFER_BUNDLE_SCHEMA,
    TRANSFER_OFFER_SCHEMA,
    TRANSFER_PROTOCOL,
    TRANSFER_RECEIPT_SCHEMA,
    offer_identity,
    receipt_identity,
    transfer_bundle_identity,
)
from provenance_transfer.signing import verify_transfer_signature
from .custody import verify_custody_records
from .package import (
    _canonical_object,
    _directory_flags,
    _hash_member,
    _open_directory_at,
    _physical_files,
    _read_member,
    verify_forensic_package_fd,
)


TRANSFER_BUNDLE_REPORT_SCHEMA = (
    "provenance.transfer-bundle-verification-report.v1"
)
TRANSFER_RECEIPT_REPORT_SCHEMA = (
    "provenance.transfer-receipt-verification-report.v1"
)
_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


@dataclass(frozen=True, slots=True)
class TransferBundleVerificationReport:
    integrity_verified: bool
    transfer_bundle_identity: str | None
    offer_identity: str | None
    package_identity: str | None
    source_system: str | None
    destination_system: str | None
    sender_signature: str
    sender_key_fingerprint: str | None
    sender_identity_binding: str
    source_package_verification: str
    ordering: str
    offered_at: dict[str, str] | None
    causal_edges: tuple[tuple[str, str, str], ...]
    checks: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": TRANSFER_BUNDLE_REPORT_SCHEMA,
            "integrity_verified": self.integrity_verified,
            "transfer_bundle_identity": self.transfer_bundle_identity,
            "offer_identity": self.offer_identity,
            "package_identity": self.package_identity,
            "source_system": self.source_system,
            "destination_system": self.destination_system,
            "sender_signature": self.sender_signature,
            "sender_key_fingerprint": self.sender_key_fingerprint,
            "sender_identity_binding": self.sender_identity_binding,
            "source_package_verification": self.source_package_verification,
            "ordering": self.ordering,
            "offered_at": self.offered_at,
            "causal_edges": [
                {"from": source, "to": target, "kind": kind}
                for source, target, kind in self.causal_edges
            ],
            "checks": list(self.checks),
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class TransferReceiptVerificationReport:
    integrity_verified: bool
    receipt_identity: str | None
    transfer_bundle_identity: str | None
    offer_identity: str | None
    package_identity: str | None
    source_system: str | None
    destination_system: str | None
    receiver_signature: str
    receiver_custody: str
    transfer_bundle_binding: str
    received_package_binding: str
    ordering: str
    accepted_at: dict[str, str] | None
    causal_edges: tuple[tuple[str, str, str], ...]
    checks: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": TRANSFER_RECEIPT_REPORT_SCHEMA,
            "integrity_verified": self.integrity_verified,
            "receipt_identity": self.receipt_identity,
            "transfer_bundle_identity": self.transfer_bundle_identity,
            "offer_identity": self.offer_identity,
            "package_identity": self.package_identity,
            "source_system": self.source_system,
            "destination_system": self.destination_system,
            "receiver_signature": self.receiver_signature,
            "receiver_custody": self.receiver_custody,
            "transfer_bundle_binding": self.transfer_bundle_binding,
            "received_package_binding": self.received_package_binding,
            "ordering": self.ordering,
            "accepted_at": self.accepted_at,
            "causal_edges": [
                {"from": source, "to": target, "kind": kind}
                for source, target, kind in self.causal_edges
            ],
            "checks": list(self.checks),
            "errors": list(self.errors),
        }


def _validate_clock(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "recorded_at",
        "clock_source",
        "clock_assurance",
    }:
        raise ValueError(f"{label} keys changed")
    recorded_at = value.get("recorded_at")
    if (
        not isinstance(recorded_at, str)
        or _TIME_RE.fullmatch(recorded_at) is None
    ):
        raise ValueError(f"{label} recorded_at is not canonical UTC time")
    try:
        datetime.fromisoformat(recorded_at[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} recorded_at is invalid") from exc
    source = value.get("clock_source")
    if not isinstance(source, str) or not source:
        raise ValueError(f"{label} clock_source must be non-empty")
    assurance = value.get("clock_assurance")
    if assurance not in {item.value for item in ClockAssurance}:
        raise ValueError(f"{label} clock_assurance is invalid")
    return {
        "recorded_at": recorded_at,
        "clock_source": source,
        "clock_assurance": str(assurance),
    }


def _safe_system(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ch in value for ch in "\r\n\x00")
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _allowed_bundle_member(path: str) -> bool:
    if path in {"offer.json", "offer.signature.json"}:
        return True
    if path.startswith("package/"):
        return len(PurePosixPath(path).parts) >= 2
    return False


def _parse_custody_raws(
    root_fd: int,
    paths: list[str],
) -> tuple[list[bytes], dict[str, dict[str, Any]]]:
    raws: list[bytes] = []
    parsed: dict[str, dict[str, Any]] = {}
    for path in paths:
        raw = _read_member(root_fd, path)
        value = parse_canonical_json_bytes(raw)
        if not isinstance(value, dict):
            raise ValueError(f"{path} must contain a custody object")
        identity = value.get("custody_identity")
        require_sha256_identity(identity, label=f"{path} custody identity")
        expected = str(identity).split(":", 1)[1] + ".json"
        if PurePosixPath(path).name != expected:
            raise ValueError(f"{path} filename does not match custody identity")
        raws.append(raw)
        parsed[str(identity)] = value
    return raws, parsed


def verify_transfer_bundle(
    transfer_dir: os.PathLike[str] | str,
    *,
    expected_sender_fingerprint: str | None = None,
    _transfer_fd: int | None = None,
) -> TransferBundleVerificationReport:
    checks: list[str] = []
    errors: list[str] = []
    transfer_identity: str | None = None
    offer_identity_value: str | None = None
    package_identity: str | None = None
    source_system: str | None = None
    destination_system: str | None = None
    offered_at: dict[str, str] | None = None
    sender_signature = "FAILED"
    sender_key_fingerprint: str | None = None
    sender_identity_binding = (
        "NOT_ATTEMPTED"
        if expected_sender_fingerprint is None
        else "FAILED"
    )
    source_package_verification = "FAILED"
    causal_edges: list[tuple[str, str, str]] = []

    try:
        if _transfer_fd is None:
            root_fd = os.open(transfer_dir, _directory_flags())
        else:
            root_fd = os.dup(_transfer_fd)
            if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
                os.close(root_fd)
                raise OSError("transfer descriptor is not a directory")
    except OSError as exc:
        return TransferBundleVerificationReport(
            False, None, None, None, None, None,
            "FAILED", None, sender_identity_binding, "FAILED",
            "PARTIAL", None, (), (),
            (f"transfer root cannot be opened safely: {exc}",),
        )

    try:
        try:
            envelope = _canonical_object(root_fd, "transfer.json")
            if set(envelope) != {
                "core",
                "transfer_bundle_identity",
                "self_hash_exclusion",
            }:
                raise ValueError("transfer envelope keys changed")
            core = envelope.get("core")
            if not isinstance(core, dict) or set(core) != {
                "schema",
                "canonicalization",
                "protocol",
                "transfer_state",
                "subject_kind",
                "subject_identity",
                "evidence_manifest_identity",
                "offer_identity",
                "offer_signature_identity",
                "source_system",
                "destination_system",
                "members",
                "ordering",
            }:
                raise ValueError("transfer core keys changed")
            if core.get("schema") != TRANSFER_BUNDLE_SCHEMA:
                raise ValueError("transfer bundle schema changed")
            if core.get("canonicalization") != CANONICALIZATION_ID:
                raise ValueError("transfer canonicalization changed")
            if core.get("protocol") != TRANSFER_PROTOCOL:
                raise ValueError("transfer protocol changed")
            if core.get("transfer_state") != "FINALIZED":
                raise ValueError("transfer_state must be FINALIZED")
            if core.get("subject_kind") != "forensic_package":
                raise ValueError("transfer subject kind changed")
            if core.get("ordering") != "PARTIAL":
                raise ValueError("transfer ordering must be PARTIAL")
            for label, key in (
                ("package identity", "subject_identity"),
                ("evidence manifest identity", "evidence_manifest_identity"),
                ("offer identity", "offer_identity"),
                ("offer signature identity", "offer_signature_identity"),
            ):
                require_sha256_identity(core.get(key), label=label)
            package_identity = str(core["subject_identity"])
            offer_identity_value = str(core["offer_identity"])
            source_system = _safe_system(
                core.get("source_system"), label="source_system"
            )
            destination_system = _safe_system(
                core.get("destination_system"), label="destination_system"
            )
            if source_system == destination_system:
                raise ValueError("source and destination systems must differ")
            members = core.get("members")
            if not isinstance(members, list):
                raise ValueError("transfer members must be a list")
            paths: list[str] = []
            normalized: list[dict[str, object]] = []
            for index, item in enumerate(members):
                if not isinstance(item, dict) or set(item) != {
                    "path", "content_identity", "byte_count"
                }:
                    raise ValueError(
                        f"transfer member[{index}] keys changed"
                    )
                path = item.get("path")
                if not isinstance(path, str) or not _allowed_bundle_member(path):
                    raise ValueError(
                        f"transfer member path is outside v1 layout: {path}"
                    )
                require_sha256_identity(
                    item.get("content_identity"),
                    label=f"transfer member[{index}] identity",
                )
                if (
                    type(item.get("byte_count")) is not int
                    or item["byte_count"] < 0
                ):
                    raise ValueError(
                        f"transfer member[{index}] byte_count is invalid"
                    )
                paths.append(path)
                normalized.append(item)
            if paths != sorted(paths) or len(set(paths)) != len(paths):
                raise ValueError(
                    "transfer members must be sorted and unique"
                )

            claimed = envelope.get("transfer_bundle_identity")
            require_sha256_identity(
                claimed, label="transfer bundle identity"
            )
            if (
                envelope.get("self_hash_exclusion")
                != "transfer_bundle_identity"
            ):
                raise ValueError("transfer self-hash exclusion changed")
            if transfer_bundle_identity(core) != claimed:
                raise ValueError("transfer bundle identity mismatch")
            transfer_identity = str(claimed)
            checks.append("transfer envelope and identity verified")

            files, directories, unsafe = _physical_files(root_fd)
            expected_files = {"transfer.json", *paths}
            expected_dirs = {"package"}
            if unsafe:
                raise ValueError(
                    "unsafe transfer filesystem entries: "
                    + ", ".join(sorted(unsafe))
                )
            missing = sorted(expected_files - files)
            extra = sorted(files - expected_files)
            missing_dirs = sorted(expected_dirs - directories)
            extra_dirs = sorted(
                directory
                for directory in directories
                if (
                    directory not in expected_dirs
                    and not directory.startswith("package/")
                )
            )
            if missing or extra or missing_dirs or extra_dirs:
                raise ValueError(
                    "transfer physical membership mismatch: "
                    f"missing={missing} extra={extra} "
                    f"missing_dirs={missing_dirs} extra_dirs={extra_dirs}"
                )
            for item in normalized:
                identity, byte_count = _hash_member(
                    root_fd, str(item["path"])
                )
                if identity != item["content_identity"]:
                    raise ValueError(
                        f"{item['path']}: member content identity mismatch"
                    )
                if byte_count != item["byte_count"]:
                    raise ValueError(
                        f"{item['path']}: member byte_count mismatch"
                    )
            checks.append("transfer member closure verified")

            offer = _canonical_object(root_fd, "offer.json")
            if set(offer) != {
                "core", "offer_identity", "self_hash_exclusion"
            }:
                raise ValueError("offer envelope keys changed")
            offer_core = offer.get("core")
            if not isinstance(offer_core, dict) or set(offer_core) != {
                "schema",
                "canonicalization",
                "protocol",
                "subject_kind",
                "subject_identity",
                "evidence_manifest_identity",
                "source_system",
                "destination_system",
                "offered_at",
            }:
                raise ValueError("offer core keys changed")
            if offer_core.get("schema") != TRANSFER_OFFER_SCHEMA:
                raise ValueError("offer schema changed")
            if offer_core.get("canonicalization") != CANONICALIZATION_ID:
                raise ValueError("offer canonicalization changed")
            if offer_core.get("protocol") != TRANSFER_PROTOCOL:
                raise ValueError("offer protocol changed")
            if offer_core.get("subject_kind") != "forensic_package":
                raise ValueError("offer subject kind changed")
            if offer_core.get("subject_identity") != package_identity:
                raise ValueError("offer package identity mismatch")
            if (
                offer_core.get("evidence_manifest_identity")
                != core["evidence_manifest_identity"]
            ):
                raise ValueError("offer manifest identity mismatch")
            if offer_core.get("source_system") != source_system:
                raise ValueError("offer source system mismatch")
            if offer_core.get("destination_system") != destination_system:
                raise ValueError("offer destination system mismatch")
            offered_at = _validate_clock(
                offer_core.get("offered_at"), label="offered_at"
            )
            if offer_identity(offer_core) != offer.get("offer_identity"):
                raise ValueError("offer identity mismatch")
            if offer.get("offer_identity") != offer_identity_value:
                raise ValueError("transfer offer identity mismatch")
            if offer.get("self_hash_exclusion") != "offer_identity":
                raise ValueError("offer self-hash exclusion changed")

            signature_record = _canonical_object(
                root_fd, "offer.signature.json"
            )
            ok, signature_errors = verify_transfer_signature(
                offer,
                signature_record,
                expected_role="sender",
                expected_subject_kind="transfer_offer",
                expected_subject_identity=offer_identity_value,
            )
            if not ok:
                raise ValueError(
                    "sender signature failed: "
                    + "; ".join(signature_errors)
                )
            if (
                signature_record.get("signature_identity")
                != core["offer_signature_identity"]
            ):
                raise ValueError("offer signature identity mismatch")
            sender_signature = "VERIFIED"
            signature_core = signature_record.get("core")
            assert isinstance(signature_core, dict)
            sender_key_fingerprint = str(
                signature_core.get("key_fingerprint")
            )
            checks.append("sender offer signature verified")
            if expected_sender_fingerprint is not None:
                if (
                    sender_key_fingerprint
                    != expected_sender_fingerprint
                ):
                    raise ValueError(
                        "sender signing key fingerprint does not match "
                        "the independently supplied expected fingerprint"
                    )
                sender_identity_binding = "VERIFIED"
                checks.append(
                    "sender key fingerprint binding verified"
                )

            package_fd = _open_directory_at(root_fd, ("package",))
            try:
                package_report = verify_forensic_package_fd(package_fd)
            finally:
                os.close(package_fd)
            if not package_report.integrity_verified:
                raise ValueError(
                    "embedded package failed verification: "
                    + "; ".join(package_report.errors)
                )
            if package_report.package_identity != package_identity:
                raise ValueError("embedded package identity mismatch")
            if (
                package_report.evidence_manifest_identity
                != core["evidence_manifest_identity"]
            ):
                raise ValueError("embedded manifest identity mismatch")
            checks.append("embedded package independently verified")

            # The Phase 11 package is the authority for sender-side
            # custody. Its verifier already checks the embedded custody snapshot.
            source_package_verification = "VERIFIED"
            checks.append("source package custody verified")

            causal_edges.append(
                (
                    package_identity,
                    offer_identity_value,
                    "offered_for_transfer",
                )
            )
        except Exception as exc:
            errors.append(str(exc))

        return TransferBundleVerificationReport(
            integrity_verified=not errors,
            transfer_bundle_identity=transfer_identity,
            offer_identity=offer_identity_value,
            package_identity=package_identity,
            source_system=source_system,
            destination_system=destination_system,
            sender_signature=sender_signature,
            sender_key_fingerprint=sender_key_fingerprint,
            sender_identity_binding=sender_identity_binding,
            source_package_verification=source_package_verification,
            ordering="PARTIAL",
            offered_at=offered_at,
            causal_edges=tuple(causal_edges),
            checks=tuple(checks),
            errors=tuple(errors),
        )
    finally:
        os.close(root_fd)


def verify_transfer_bundle_fd(
    transfer_fd: int,
    *,
    expected_sender_fingerprint: str | None = None,
) -> TransferBundleVerificationReport:
    """Verify an already-open transfer directory descriptor."""

    return verify_transfer_bundle(
        ".",
        expected_sender_fingerprint=expected_sender_fingerprint,
        _transfer_fd=transfer_fd,
    )


def verify_transfer_receipt(
    receipt_dir: os.PathLike[str] | str,
    *,
    transfer_bundle: os.PathLike[str] | str | None = None,
    received_package: os.PathLike[str] | str | None = None,
    expected_sender_fingerprint: str | None = None,
) -> TransferReceiptVerificationReport:
    checks: list[str] = []
    errors: list[str] = []
    receipt_identity_value: str | None = None
    transfer_identity: str | None = None
    offer_identity_value: str | None = None
    package_identity: str | None = None
    source_system: str | None = None
    destination_system: str | None = None
    accepted_at: dict[str, str] | None = None
    receiver_signature = "FAILED"
    receiver_custody = "FAILED"
    transfer_binding = (
        "NOT_ATTEMPTED" if transfer_bundle is None else "FAILED"
    )
    package_binding = (
        "NOT_ATTEMPTED" if received_package is None else "FAILED"
    )
    causal_edges: list[tuple[str, str, str]] = []

    try:
        root_fd = os.open(receipt_dir, _directory_flags())
    except OSError as exc:
        return TransferReceiptVerificationReport(
            False, None, None, None, None, None, None,
            "FAILED", "FAILED", transfer_binding, package_binding,
            "PARTIAL", None, (), (),
            (f"receipt root cannot be opened safely: {exc}",),
        )

    try:
        try:
            receipt = _canonical_object(root_fd, "receipt.json")
            if set(receipt) != {
                "core", "receipt_identity", "self_hash_exclusion"
            }:
                raise ValueError("receipt envelope keys changed")
            core = receipt.get("core")
            if not isinstance(core, dict) or set(core) != {
                "schema",
                "canonicalization",
                "protocol",
                "transfer_bundle_identity",
                "offer_identity",
                "subject_kind",
                "subject_identity",
                "source_system",
                "destination_system",
                "receipt_status",
                "accepted_at",
                "receiver_custody_identities",
                "ordering",
            }:
                raise ValueError("receipt core keys changed")
            if core.get("schema") != TRANSFER_RECEIPT_SCHEMA:
                raise ValueError("receipt schema changed")
            if core.get("canonicalization") != CANONICALIZATION_ID:
                raise ValueError("receipt canonicalization changed")
            if core.get("protocol") != TRANSFER_PROTOCOL:
                raise ValueError("receipt protocol changed")
            if core.get("subject_kind") != "forensic_package":
                raise ValueError("receipt subject kind changed")
            if core.get("receipt_status") != "ACCEPTED":
                raise ValueError("receipt status is not ACCEPTED")
            if core.get("ordering") != "PARTIAL":
                raise ValueError("receipt ordering must be PARTIAL")
            for label, key in (
                ("transfer bundle identity", "transfer_bundle_identity"),
                ("offer identity", "offer_identity"),
                ("package identity", "subject_identity"),
            ):
                require_sha256_identity(core.get(key), label=label)
            transfer_identity = str(core["transfer_bundle_identity"])
            offer_identity_value = str(core["offer_identity"])
            package_identity = str(core["subject_identity"])
            source_system = _safe_system(
                core.get("source_system"), label="source_system"
            )
            destination_system = _safe_system(
                core.get("destination_system"), label="destination_system"
            )
            if source_system == destination_system:
                raise ValueError(
                    "receipt source and destination systems must differ"
                )
            accepted_at = _validate_clock(
                core.get("accepted_at"), label="accepted_at"
            )
            custody_ids = core.get("receiver_custody_identities")
            if not isinstance(custody_ids, list) or not custody_ids:
                raise ValueError(
                    "receipt receiver custody identities are invalid"
                )
            for index, identity in enumerate(custody_ids):
                require_sha256_identity(
                    identity,
                    label=f"receiver custody identity[{index}]",
                )
            if len(set(custody_ids)) != len(custody_ids):
                raise ValueError(
                    "receiver custody identities must be unique"
                )
            claimed = receipt.get("receipt_identity")
            require_sha256_identity(claimed, label="receipt identity")
            if receipt.get("self_hash_exclusion") != "receipt_identity":
                raise ValueError("receipt self-hash exclusion changed")
            if receipt_identity(core) != claimed:
                raise ValueError("receipt identity mismatch")
            receipt_identity_value = str(claimed)
            checks.append("receipt envelope and identity verified")

            expected_files = {
                "receipt.json",
                "receipt.signature.json",
                *{
                    "receiver_custody/sha256/"
                    + identity.split(":", 1)[1]
                    + ".json"
                    for identity in custody_ids
                },
            }
            expected_dirs = {"receiver_custody", "receiver_custody/sha256"}
            files, directories, unsafe = _physical_files(root_fd)
            if unsafe:
                raise ValueError(
                    "unsafe receipt filesystem entries: "
                    + ", ".join(sorted(unsafe))
                )
            if files != expected_files or directories != expected_dirs:
                raise ValueError(
                    "receipt physical membership does not match receipt core"
                )

            signature = _canonical_object(
                root_fd, "receipt.signature.json"
            )
            ok, signature_errors = verify_transfer_signature(
                receipt,
                signature,
                expected_role="receiver",
                expected_subject_kind="transfer_receipt",
                expected_subject_identity=receipt_identity_value,
            )
            if not ok:
                raise ValueError(
                    "receiver signature failed: "
                    + "; ".join(signature_errors)
                )
            receiver_signature = "VERIFIED"
            checks.append("receiver receipt signature verified")

            custody_paths = sorted(
                path
                for path in files
                if path.startswith("receiver_custody/sha256/")
            )
            raws, parsed = _parse_custody_raws(root_fd, custody_paths)
            if set(parsed) != set(custody_ids):
                raise ValueError(
                    "receipt custody members differ from declared identities"
                )
            custody_report = verify_custody_records(raws)
            if not custody_report.integrity_verified:
                raise ValueError(
                    "receiver custody chain failed verification: "
                    + "; ".join(custody_report.errors)
                )

            cores_by_identity = {
                identity: value["core"]
                for identity, value in parsed.items()
                if isinstance(value.get("core"), dict)
            }
            roots = [
                identity
                for identity, custody_core in cores_by_identity.items()
                if custody_core.get("previous_custody") is None
            ]
            if len(roots) != 1:
                raise ValueError(
                    "receiver custody chain must have exactly one root"
                )
            child_of: dict[str, str] = {}
            for identity, custody_core in cores_by_identity.items():
                previous = custody_core.get("previous_custody")
                if previous is not None:
                    child_of[str(previous)] = identity
            ordered_cores: list[dict[str, Any]] = []
            current: str | None = roots[0]
            visited: set[str] = set()
            while current is not None:
                if current in visited or current not in cores_by_identity:
                    raise ValueError(
                        "receiver custody chain traversal failed"
                    )
                visited.add(current)
                ordered_cores.append(cores_by_identity[current])
                current = child_of.get(current)
            if len(visited) != len(cores_by_identity):
                raise ValueError(
                    "receiver custody chain is disconnected"
                )

            matching = [
                custody_core
                for custody_core in ordered_cores
                if (
                    custody_core.get("subject_identity")
                    == package_identity
                    and custody_core.get("related_identity")
                    == offer_identity_value
                    and custody_core.get("actor") == destination_system
                    and custody_core.get("source") == source_system
                )
            ]
            actions = [
                str(custody_core.get("action"))
                for custody_core in matching
            ]
            if actions != [
                CustodyAction.CAPTURED.value,
                CustodyAction.STORED.value,
                CustodyAction.VERIFIED.value,
            ]:
                raise ValueError(
                    "receiver acknowledgement custody must be exactly "
                    "CAPTURED/STORED/VERIFIED in local chain order"
                )
            for custody_core in matching:
                if custody_core.get("recorded_at") != accepted_at["recorded_at"]:
                    raise ValueError(
                        "receiver acknowledgement clock differs from receipt"
                    )
                if custody_core.get("clock_source") != accepted_at["clock_source"]:
                    raise ValueError(
                        "receiver acknowledgement clock source differs from receipt"
                    )
                if (
                    custody_core.get("clock_assurance")
                    != accepted_at["clock_assurance"]
                ):
                    raise ValueError(
                        "receiver acknowledgement assurance differs from receipt"
                    )
            receiver_custody = "VERIFIED"
            checks.append("receiver local custody chain verified")

            causal_edges.append(
                (
                    offer_identity_value,
                    receipt_identity_value,
                    "acknowledged_by_receiver",
                )
            )

            if transfer_bundle is not None:
                transfer_report = verify_transfer_bundle(
                    transfer_bundle,
                    expected_sender_fingerprint=(
                        expected_sender_fingerprint
                    ),
                )
                if not transfer_report.integrity_verified:
                    errors.append(
                        "transfer bundle failed verification: "
                        + "; ".join(transfer_report.errors)
                    )
                elif (
                    transfer_report.transfer_bundle_identity
                    != transfer_identity
                    or transfer_report.offer_identity
                    != offer_identity_value
                    or transfer_report.package_identity
                    != package_identity
                    or transfer_report.source_system != source_system
                    or transfer_report.destination_system
                    != destination_system
                ):
                    errors.append(
                        "receipt does not bind the supplied transfer bundle"
                    )
                else:
                    transfer_binding = "VERIFIED"
                    checks.append("transfer bundle binding verified")
                    causal_edges.extend(transfer_report.causal_edges)

            if received_package is not None:
                package_fd = os.open(
                    received_package, _directory_flags()
                )
                try:
                    package_report = verify_forensic_package_fd(package_fd)
                finally:
                    os.close(package_fd)
                if not package_report.integrity_verified:
                    errors.append(
                        "received package failed verification: "
                        + "; ".join(package_report.errors)
                    )
                elif package_report.package_identity != package_identity:
                    errors.append(
                        "received package identity differs from receipt"
                    )
                else:
                    package_binding = "VERIFIED"
                    checks.append("received package binding verified")
        except Exception as exc:
            errors.append(str(exc))

        return TransferReceiptVerificationReport(
            integrity_verified=(
                not errors
                and receiver_signature == "VERIFIED"
                and receiver_custody == "VERIFIED"
            ),
            receipt_identity=receipt_identity_value,
            transfer_bundle_identity=transfer_identity,
            offer_identity=offer_identity_value,
            package_identity=package_identity,
            source_system=source_system,
            destination_system=destination_system,
            receiver_signature=receiver_signature,
            receiver_custody=receiver_custody,
            transfer_bundle_binding=transfer_binding,
            received_package_binding=package_binding,
            ordering="PARTIAL",
            accepted_at=accepted_at,
            causal_edges=tuple(causal_edges),
            checks=tuple(checks),
            errors=tuple(errors),
        )
    finally:
        os.close(root_fd)
