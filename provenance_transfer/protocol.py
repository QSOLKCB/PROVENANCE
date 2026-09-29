"""Offline signed transfer protocol for Phase 15 distributed custody."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import uuid
from typing import Any

from provenance_core import (
    CustodyAction,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from provenance_custody import (
    ClockObservation,
    LocalCustodyLedger,
    observe_clock,
)
from provenance_export.package import (
    _copy_tree,
    _directory_flags,
    _directory_identity,
    _remove_tree_at,
    _rename_noreplace_at,
    _write_member,
)
from provenance_transfer.model import (
    offer_core,
    offer_identity,
    receipt_core,
    receipt_identity,
    transfer_bundle_core,
    transfer_bundle_identity,
)
from provenance_transfer.signing import sign_transfer_envelope
from provenance_verify import (
    verify_forensic_package,
    verify_forensic_package_fd,
)
from provenance_verify.transfer import (
    verify_transfer_bundle,
    verify_transfer_bundle_fd,
    verify_transfer_receipt,
)


class TransferError(RuntimeError):
    """Raised when a distributed transfer cannot preserve its contract."""


@dataclass(frozen=True, slots=True)
class TransferBundle:
    path: Path
    transfer_bundle_identity: str
    offer_identity: str
    package_identity: str
    source_system: str
    destination_system: str


@dataclass(frozen=True, slots=True)
class TransferReceipt:
    path: Path
    receipt_identity: str
    transfer_bundle_identity: str
    offer_identity: str
    package_identity: str
    duplicate_delivery: bool


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise TransferError("short transfer write")
        offset += written


def _paths_overlap(left: Path, right: Path) -> bool:
    return (
        left == right
        or left in right.parents
        or right in left.parents
    )


def _path_identity(path: Path) -> tuple[int, int]:
    fd = os.open(path, _directory_flags())
    try:
        return _directory_identity(fd)
    finally:
        os.close(fd)


def _canonical_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = parse_canonical_json_bytes(raw)
    if not isinstance(value, dict):
        raise TransferError(f"{path.name} must contain an object")
    return value


def _publish_directory(
    *,
    parent: Path,
    parent_fd: int,
    staging_name: str,
    destination_name: str,
    staging_identity: tuple[int, int],
    label: str,
) -> Path:
    try:
        _rename_noreplace_at(
            parent_fd,
            staging_name,
            parent_fd,
            destination_name,
        )
    except Exception as exc:
        raise TransferError(str(exc)) from exc
    os.fsync(parent_fd)
    final_fd = os.open(
        destination_name,
        _directory_flags(),
        dir_fd=parent_fd,
    )
    try:
        if _directory_identity(final_fd) != staging_identity:
            raise TransferError(
                f"published {label} filesystem identity changed"
            )
    finally:
        os.close(final_fd)
    return parent / destination_name


def _copy_package_directory(
    source_package: Path,
    destination: Path,
    *,
    expected_package_identity: str,
    source_package_fd: int | None = None,
) -> tuple[Path, tuple[int, int], int]:
    if destination.exists() or destination.is_symlink():
        existing_fd = os.open(destination, _directory_flags())
        try:
            report = verify_forensic_package_fd(existing_fd)
            if (
                not report.integrity_verified
                or report.package_identity != expected_package_identity
            ):
                raise TransferError(
                    "existing received package conflicts with transfer"
                )
            return (
                destination,
                _directory_identity(existing_fd),
                existing_fd,
            )
        except Exception:
            os.close(existing_fd)
            raise

    parent = destination.parent.resolve(strict=True)
    parent_fd = os.open(parent, _directory_flags())
    staging_name = f".{destination.name}.{uuid.uuid4().hex}.tmp"
    created = False
    staging_fd: int | None = None
    returned_fd = False
    try:
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        created = True
        staging_fd = os.open(
            staging_name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
        staging_identity = _directory_identity(staging_fd)
        source_fd = (
            os.open(source_package, _directory_flags())
            if source_package_fd is None
            else os.dup(source_package_fd)
        )
        try:
            _copy_tree(
                source_fd,
                staging_fd,
                prefix="package",
                members=[],
            )
            os.fsync(staging_fd)
        finally:
            os.close(source_fd)

        staged = verify_forensic_package_fd(staging_fd)
        if (
            not staged.integrity_verified
            or staged.package_identity != expected_package_identity
        ):
            detail = (
                "; ".join(staged.errors)
                if not staged.integrity_verified
                else "package identity differs from transfer subject"
            )
            raise TransferError(
                "staged received package failed transfer binding: "
                + detail
            )

        try:
            final = _publish_directory(
                parent=parent,
                parent_fd=parent_fd,
                staging_name=staging_name,
                destination_name=destination.name,
                staging_identity=staging_identity,
                label="received package",
            )
        except TransferError as exc:
            if (
                str(exc) == "package destination must not already exist"
                and (destination.exists() or destination.is_symlink())
            ):
                existing_fd = os.open(destination, _directory_flags())
                try:
                    existing = verify_forensic_package_fd(existing_fd)
                    if (
                        existing.integrity_verified
                        and existing.package_identity
                        == expected_package_identity
                    ):
                        _remove_tree_at(parent_fd, staging_name)
                        os.fsync(parent_fd)
                        created = False
                        os.close(staging_fd)
                        staging_fd = None
                        returned_fd = True
                        return (
                            destination,
                            _directory_identity(existing_fd),
                            existing_fd,
                        )
                except Exception:
                    os.close(existing_fd)
                    raise
                os.close(existing_fd)
            raise

        created = False
        final_report = verify_forensic_package_fd(staging_fd)
        if (
            not final_report.integrity_verified
            or final_report.package_identity != expected_package_identity
        ):
            raise TransferError(
                "published received package no longer matches transfer subject"
            )
        returned_fd = True
        return final, staging_identity, staging_fd
    except Exception:
        if created:
            try:
                _remove_tree_at(parent_fd, staging_name)
                os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        if staging_fd is not None and not returned_fd:
            os.close(staging_fd)
        os.close(parent_fd)

def create_transfer_bundle(
    package_dir: Path | str,
    destination: Path | str,
    *,
    source_system: str,
    destination_system: str,
    sender_key: Path | str,
    offered_at: ClockObservation | None = None,
) -> TransferBundle:
    """Prepare a signed offline transfer bundle without network activity."""

    package_path = Path(package_dir).expanduser()
    package_report = verify_forensic_package(package_path)
    if (
        not package_report.integrity_verified
        or package_report.package_identity is None
        or package_report.evidence_manifest_identity is None
    ):
        raise TransferError(
            "source package failed verification before transfer: "
            + "; ".join(package_report.errors)
        )
    clock = offered_at or observe_clock()
    offer_core_value = offer_core(
        package_identity=package_report.package_identity,
        evidence_manifest_identity=package_report.evidence_manifest_identity,
        source_system=source_system,
        destination_system=destination_system,
        offered_at=clock,
    )
    offer_identity_value = offer_identity(offer_core_value)
    offer = {
        "core": offer_core_value,
        "offer_identity": offer_identity_value,
        "self_hash_exclusion": "offer_identity",
    }
    signature = sign_transfer_envelope(
        offer,
        role="sender",
        subject_kind="transfer_offer",
        subject_identity=offer_identity_value,
        key_file=sender_key,
    )

    supplied = Path(destination).expanduser()
    if supplied.name in {"", ".", ".."}:
        raise TransferError("transfer destination name is invalid")
    if supplied.exists() or supplied.is_symlink():
        raise TransferError("transfer destination must not already exist")
    parent = supplied.parent.resolve(strict=True)
    source_resolved = package_path.resolve(strict=True)
    if parent == source_resolved or source_resolved in parent.parents:
        raise TransferError(
            "transfer destination must be outside the source package"
        )
    parent_fd = os.open(parent, _directory_flags())
    staging_name = f".{supplied.name}.{uuid.uuid4().hex}.tmp"
    created = False
    try:
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        created = True
        staging_fd = os.open(
            staging_name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
        staging_identity = _directory_identity(staging_fd)
        members: list[dict[str, object]] = []
        try:
            package_fd = os.open(package_path, _directory_flags())
            try:
                package_dest_fd = os.open(
                    ".",
                    _directory_flags(),
                    dir_fd=staging_fd,
                )
                try:
                    os.mkdir("package", mode=0o700, dir_fd=package_dest_fd)
                    nested_fd = os.open(
                        "package",
                        _directory_flags(),
                        dir_fd=package_dest_fd,
                    )
                    try:
                        _copy_tree(
                            package_fd,
                            nested_fd,
                            prefix="package",
                            members=members,
                        )
                        os.fsync(nested_fd)
                    finally:
                        os.close(nested_fd)
                finally:
                    os.close(package_dest_fd)
            finally:
                os.close(package_fd)

            _write_member(
                staging_fd,
                "offer.json",
                canonical_json_bytes(offer),
                members,
            )
            _write_member(
                staging_fd,
                "offer.signature.json",
                canonical_json_bytes(signature),
                members,
            )
            members.sort(key=lambda item: str(item["path"]))
            core = transfer_bundle_core(
                package_identity=package_report.package_identity,
                evidence_manifest_identity=(
                    package_report.evidence_manifest_identity
                ),
                offer_identity_value=offer_identity_value,
                offer_signature_identity=str(
                    signature["signature_identity"]
                ),
                source_system=source_system,
                destination_system=destination_system,
                members=members,
            )
            identity = transfer_bundle_identity(core)
            envelope = {
                "core": core,
                "transfer_bundle_identity": identity,
                "self_hash_exclusion": "transfer_bundle_identity",
            }
            fd = os.open(
                "transfer.json",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=staging_fd,
            )
            try:
                _write_all(fd, canonical_json_bytes(envelope))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)

        staging_path = parent / staging_name
        report = verify_transfer_bundle(staging_path)
        if (
            not report.integrity_verified
            or report.transfer_bundle_identity != identity
        ):
            raise TransferError(
                "staged transfer bundle failed verification: "
                + "; ".join(report.errors)
            )

        final = _publish_directory(
            parent=parent,
            parent_fd=parent_fd,
            staging_name=staging_name,
            destination_name=supplied.name,
            staging_identity=staging_identity,
            label="transfer bundle",
        )
        created = False
        final_report = verify_transfer_bundle(final)
        if (
            not final_report.integrity_verified
            or final_report.transfer_bundle_identity != identity
        ):
            raise TransferError(
                "published transfer bundle failed verification: "
                + "; ".join(final_report.errors)
            )
        return TransferBundle(
            path=final,
            transfer_bundle_identity=identity,
            offer_identity=offer_identity_value,
            package_identity=package_report.package_identity,
            source_system=source_system,
            destination_system=destination_system,
        )
    except Exception:
        if created:
            try:
                _remove_tree_at(parent_fd, staging_name)
                os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_fd)


def _existing_acceptance_clock(
    records: tuple[bytes, ...],
    *,
    offer_identity_value: str,
    receiver_system: str,
    source_system: str,
) -> ClockObservation | None:
    clocks: set[tuple[str, str, str]] = set()
    for raw in records:
        value = parse_canonical_json_bytes(raw)
        core = value.get("core") if isinstance(value, dict) else None
        if not isinstance(core, dict):
            continue
        if (
            core.get("related_identity") == offer_identity_value
            and core.get("actor") == receiver_system
            and core.get("source") == source_system
        ):
            clocks.add(
                (
                    str(core.get("recorded_at")),
                    str(core.get("clock_source")),
                    str(core.get("clock_assurance")),
                )
            )
    if not clocks:
        return None
    if len(clocks) != 1:
        raise TransferError(
            "existing receiver acknowledgement custody uses inconsistent clocks"
        )
    recorded_at, source, assurance = next(iter(clocks))
    from provenance_core import ClockAssurance

    return ClockObservation(
        recorded_at=recorded_at,
        clock_source=source,
        clock_assurance=ClockAssurance(assurance),
    )


def _ordered_subject_cores(
    records: tuple[bytes, ...],
) -> list[dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    child_of: dict[str, str] = {}
    root: str | None = None
    for raw in records:
        value = parse_canonical_json_bytes(raw)
        if not isinstance(value, dict) or not isinstance(
            value.get("core"), dict
        ):
            raise TransferError("receiver custody record is malformed")
        identity = str(value.get("custody_identity"))
        core = value["core"]
        parsed[identity] = core
    for identity, core in parsed.items():
        previous = core.get("previous_custody")
        if previous is None:
            if root is not None:
                raise TransferError(
                    "receiver custody subject has multiple roots"
                )
            root = identity
        else:
            child_of[str(previous)] = identity
    if not parsed:
        return []
    if root is None:
        raise TransferError("receiver custody subject lacks a root")
    ordered: list[dict[str, object]] = []
    current: str | None = root
    seen: set[str] = set()
    while current is not None:
        if current in seen or current not in parsed:
            raise TransferError(
                "receiver custody subject chain is invalid"
            )
        seen.add(current)
        ordered.append(parsed[current])
        current = child_of.get(current)
    if len(seen) != len(parsed):
        raise TransferError(
            "receiver custody subject chain is disconnected"
        )
    return ordered


def _existing_acceptance_actions(
    records: tuple[bytes, ...],
    *,
    offer_identity_value: str,
    receiver_system: str,
    source_system: str,
) -> list[str]:
    actions: list[str] = []
    for core in _ordered_subject_cores(records):
        if (
            core.get("related_identity") == offer_identity_value
            and core.get("actor") == receiver_system
            and core.get("source") == source_system
        ):
            actions.append(str(core.get("action")))
    expected = [
        CustodyAction.CAPTURED.value,
        CustodyAction.STORED.value,
        CustodyAction.VERIFIED.value,
    ]
    if actions != expected[: len(actions)]:
        raise TransferError(
            "existing receiver acknowledgement custody is not a valid "
            "CAPTURED/STORED/VERIFIED prefix"
        )
    return actions


def receive_transfer(
    transfer_dir: Path | str,
    package_destination: Path | str,
    receipt_destination: Path | str,
    receiver_custody_root: Path | str,
    *,
    receiver_system: str,
    receiver_key: Path | str,
    expected_sender_fingerprint: str,
    accepted_at: ClockObservation | None = None,
) -> TransferReceipt:
    """Accept an offline transfer exactly once; duplicates are idempotent."""

    if (
        not isinstance(expected_sender_fingerprint, str)
        or not expected_sender_fingerprint
        or expected_sender_fingerprint.strip()
        != expected_sender_fingerprint
    ):
        raise TransferError(
            "an independently supplied expected sender fingerprint is required"
        )

    transfer_path = Path(transfer_dir).expanduser()
    try:
        transfer_fd = os.open(transfer_path, _directory_flags())
    except OSError as exc:
        raise TransferError(
            f"transfer bundle cannot be opened safely: {exc}"
        ) from exc

    try:
        transfer_report = verify_transfer_bundle_fd(
            transfer_fd,
            expected_sender_fingerprint=expected_sender_fingerprint,
        )
        if not transfer_report.integrity_verified:
            raise TransferError(
                "transfer bundle failed verification: "
                + "; ".join(transfer_report.errors)
            )
        if transfer_report.sender_identity_binding != "VERIFIED":
            raise TransferError(
                "transfer sender identity was not bound to the expected fingerprint"
            )
        if transfer_report.destination_system != receiver_system:
            raise TransferError(
                "transfer is addressed to a different destination system"
            )
        assert transfer_report.transfer_bundle_identity is not None
        assert transfer_report.offer_identity is not None
        assert transfer_report.package_identity is not None
        assert transfer_report.source_system is not None

        package_dest = Path(package_destination).expanduser()
        receipt_dest = Path(receipt_destination).expanduser()
        custody_dest = Path(receiver_custody_root).expanduser()
        transfer_resolved = transfer_path.resolve(strict=True)

        package_parent = package_dest.parent.resolve(strict=True)
        receipt_parent = receipt_dest.parent.resolve(strict=True)
        custody_parent = custody_dest.parent.resolve(strict=True)
        package_candidate = package_parent / package_dest.name
        receipt_candidate = receipt_parent / receipt_dest.name
        custody_candidate = custody_parent / custody_dest.name

        for label, candidate in (
            ("received package", package_candidate),
            ("receipt", receipt_candidate),
            ("receiver custody", custody_candidate),
        ):
            if _paths_overlap(candidate, transfer_resolved):
                raise TransferError(
                    f"{label} destination must be outside the transfer bundle"
                )

        if _paths_overlap(package_candidate, receipt_candidate):
            raise TransferError(
                "received package and receipt destinations must be disjoint"
            )
        if _paths_overlap(package_candidate, custody_candidate):
            raise TransferError(
                "received package and receiver custody destinations must be disjoint"
            )
        if _paths_overlap(receipt_candidate, custody_candidate):
            raise TransferError(
                "receipt and receiver custody destinations must be disjoint"
            )

        def _verified_duplicate_receipt() -> TransferReceipt:
            existing = verify_transfer_receipt(
                receipt_dest,
                transfer_bundle=transfer_path,
                received_package=package_dest,
                expected_sender_fingerprint=expected_sender_fingerprint,
                _transfer_fd=transfer_fd,
            )
            if not existing.integrity_verified:
                raise TransferError(
                    "existing receipt destination is not a valid duplicate receipt: "
                    + "; ".join(existing.errors)
                )
            if existing.destination_system != receiver_system:
                raise TransferError(
                    "existing receipt belongs to a different receiver"
                )
            custody_root_path = Path(receiver_custody_root).expanduser()
            if (
                not custody_root_path.is_dir()
                or custody_root_path.is_symlink()
            ):
                raise TransferError(
                    "live receiver custody ledger is unavailable for duplicate delivery"
                )
            receipt_value = _canonical_file(receipt_dest / "receipt.json")
            receipt_core_value = receipt_value.get("core")
            if not isinstance(receipt_core_value, dict):
                raise TransferError("existing receipt core is malformed")
            declared_ids = set(
                receipt_core_value.get("receiver_custody_identities", [])
            )
            live_ledger = LocalCustodyLedger(custody_root_path)
            live_records = live_ledger.record_bytes_for_subject(
                transfer_report.package_identity
            )
            live_ids = {
                str(parse_canonical_json_bytes(raw)["custody_identity"])
                for raw in live_records
            }
            if not declared_ids.issubset(live_ids):
                raise TransferError(
                    "live receiver custody ledger no longer contains the "
                    "acknowledgements bound by the existing receipt"
                )
            assert existing.receipt_identity is not None
            return TransferReceipt(
                path=receipt_dest,
                receipt_identity=existing.receipt_identity,
                transfer_bundle_identity=(
                    transfer_report.transfer_bundle_identity
                ),
                offer_identity=transfer_report.offer_identity,
                package_identity=transfer_report.package_identity,
                duplicate_delivery=True,
            )

        if receipt_dest.exists() or receipt_dest.is_symlink():
            return _verified_duplicate_receipt()

        embedded_package = transfer_path / "package"
        if package_dest.exists() or package_dest.is_symlink():
            existing_package = verify_forensic_package(package_dest)
            if (
                not existing_package.integrity_verified
                or existing_package.package_identity
                != transfer_report.package_identity
            ):
                raise TransferError(
                    "existing received package destination conflicts with transfer"
                )
        else:
            try:
                embedded_package_fd = os.open(
                    "package",
                    _directory_flags(),
                    dir_fd=transfer_fd,
                )
            except OSError as exc:
                raise TransferError(
                    f"embedded transfer package cannot be opened safely: {exc}"
                ) from exc
            try:
                copied, _identity = _copy_package_directory(
                    embedded_package,
                    package_dest,
                    source_package_fd=embedded_package_fd,
                )
            finally:
                os.close(embedded_package_fd)
            copied_report = verify_forensic_package(copied)
            if (
                not copied_report.integrity_verified
                or copied_report.package_identity
                != transfer_report.package_identity
            ):
                raise TransferError(
                    "received package copy does not match transfer subject"
                )

        ledger = LocalCustodyLedger(receiver_custody_root)
        requested_clock = accepted_at or observe_clock()
        expected_actions = (
            CustodyAction.CAPTURED,
            CustodyAction.STORED,
            CustodyAction.VERIFIED,
        )
        receiver_records = ledger.ensure_action_sequence(
            transfer_report.package_identity,
            expected_actions,
            actor=receiver_system,
            source=transfer_report.source_system,
            related_identity=transfer_report.offer_identity,
            clock=requested_clock,
        )
        clock = _existing_acceptance_clock(
            receiver_records,
            offer_identity_value=transfer_report.offer_identity,
            receiver_system=receiver_system,
            source_system=transfer_report.source_system,
        )
        if clock is None:
            raise TransferError(
                "receiver acknowledgement custody clock is unavailable"
            )

        custody_ids: list[str] = []
        for raw in receiver_records:
            value = parse_canonical_json_bytes(raw)
            custody_ids.append(str(value["custody_identity"]))

        receipt_core_value = receipt_core(
            transfer_bundle_identity_value=(
                transfer_report.transfer_bundle_identity
            ),
            offer_identity_value=transfer_report.offer_identity,
            package_identity=transfer_report.package_identity,
            source_system=transfer_report.source_system,
            destination_system=receiver_system,
            accepted_at=clock,
            receiver_custody_identities=custody_ids,
        )
        receipt_identity_value = receipt_identity(receipt_core_value)
        receipt = {
            "core": receipt_core_value,
            "receipt_identity": receipt_identity_value,
            "self_hash_exclusion": "receipt_identity",
        }
        signature = sign_transfer_envelope(
            receipt,
            role="receiver",
            subject_kind="transfer_receipt",
            subject_identity=receipt_identity_value,
            key_file=receiver_key,
        )

        if receipt_dest.name in {"", ".", ".."}:
            raise TransferError("receipt destination name is invalid")
        if receipt_dest.exists() or receipt_dest.is_symlink():
            return _verified_duplicate_receipt()
        parent = receipt_dest.parent.resolve(strict=True)
        parent_fd = os.open(parent, _directory_flags())
        staging_name = f".{receipt_dest.name}.{uuid.uuid4().hex}.tmp"
        created = False
        try:
            os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
            created = True
            staging_fd = os.open(
                staging_name,
                _directory_flags(),
                dir_fd=parent_fd,
            )
            staging_identity = _directory_identity(staging_fd)
            try:
                os.mkdir(
                    "receiver_custody",
                    mode=0o700,
                    dir_fd=staging_fd,
                )
                custody_parent_fd = os.open(
                    "receiver_custody",
                    _directory_flags(),
                    dir_fd=staging_fd,
                )
                try:
                    os.mkdir("sha256", mode=0o700, dir_fd=custody_parent_fd)
                    custody_fd = os.open(
                        "sha256",
                        _directory_flags(),
                        dir_fd=custody_parent_fd,
                    )
                    try:
                        for raw in receiver_records:
                            value = parse_canonical_json_bytes(raw)
                            identity = str(value["custody_identity"])
                            name = identity.split(":", 1)[1] + ".json"
                            fd = os.open(
                                name,
                                os.O_WRONLY
                                | os.O_CREAT
                                | os.O_EXCL
                                | os.O_NOFOLLOW
                                | os.O_CLOEXEC,
                                0o600,
                                dir_fd=custody_fd,
                            )
                            try:
                                _write_all(fd, raw)
                                os.fsync(fd)
                            finally:
                                os.close(fd)
                        os.fsync(custody_fd)
                    finally:
                        os.close(custody_fd)
                finally:
                    os.close(custody_parent_fd)

                for name, data in (
                    ("receipt.json", canonical_json_bytes(receipt)),
                    (
                        "receipt.signature.json",
                        canonical_json_bytes(signature),
                    ),
                ):
                    fd = os.open(
                        name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | os.O_CLOEXEC,
                        0o600,
                        dir_fd=staging_fd,
                    )
                    try:
                        _write_all(fd, data)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.fsync(staging_fd)
            finally:
                os.close(staging_fd)

            staged_path = parent / staging_name
            staged_report = verify_transfer_receipt(
                staged_path,
                transfer_bundle=transfer_path,
                received_package=package_dest,
                expected_sender_fingerprint=expected_sender_fingerprint,
                _transfer_fd=transfer_fd,
            )
            if (
                not staged_report.integrity_verified
                or staged_report.receipt_identity
                != receipt_identity_value
            ):
                raise TransferError(
                    "staged transfer receipt failed verification: "
                    + "; ".join(staged_report.errors)
                )

            try:
                final = _publish_directory(
                    parent=parent,
                    parent_fd=parent_fd,
                    staging_name=staging_name,
                    destination_name=receipt_dest.name,
                    staging_identity=staging_identity,
                    label="transfer receipt",
                )
            except TransferError as exc:
                if (
                    str(exc) == "package destination must not already exist"
                    and (receipt_dest.exists() or receipt_dest.is_symlink())
                ):
                    duplicate = _verified_duplicate_receipt()
                    _remove_tree_at(parent_fd, staging_name)
                    os.fsync(parent_fd)
                    created = False
                    return duplicate
                raise
            created = False
            final_report = verify_transfer_receipt(
                final,
                transfer_bundle=transfer_path,
                received_package=package_dest,
                expected_sender_fingerprint=expected_sender_fingerprint,
                _transfer_fd=transfer_fd,
            )
            if (
                not final_report.integrity_verified
                or final_report.receipt_identity
                != receipt_identity_value
            ):
                raise TransferError(
                    "published transfer receipt failed verification: "
                    + "; ".join(final_report.errors)
                )
            return TransferReceipt(
                path=final,
                receipt_identity=receipt_identity_value,
                transfer_bundle_identity=(
                    transfer_report.transfer_bundle_identity
                ),
                offer_identity=transfer_report.offer_identity,
                package_identity=transfer_report.package_identity,
                duplicate_delivery=False,
            )
        except Exception:
            if created:
                try:
                    _remove_tree_at(parent_fd, staging_name)
                    os.fsync(parent_fd)
                except OSError:
                    pass
            raise
        finally:
            os.close(parent_fd)
    finally:
        os.close(transfer_fd)
