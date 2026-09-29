"""Phase 15 distributed-custody transfer records and identities."""
from __future__ import annotations

import hashlib
from typing import Any

from provenance_core import (
    CANONICALIZATION_ID,
    ClockAssurance,
    canonical_json_bytes,
    require_sha256_identity,
)
from provenance_trust.model import (
    ed25519_key_fingerprint,
    normalize_ed25519_public_key,
    sha256_content_identity,
)


TRANSFER_PROTOCOL = "provenance.transfer.v1"
TRANSFER_OFFER_SCHEMA = "provenance.transfer-offer.v1"
TRANSFER_RECEIPT_SCHEMA = "provenance.transfer-receipt.v1"
TRANSFER_BUNDLE_SCHEMA = "provenance.transfer-bundle.v1"
TRANSFER_SIGNATURE_SCHEMA = "provenance.transfer-signature.v1"

OFFER_DOMAIN = b"PROVENANCE/TRANSFER-OFFER/v1\0"
RECEIPT_DOMAIN = b"PROVENANCE/TRANSFER-RECEIPT/v1\0"
BUNDLE_DOMAIN = b"PROVENANCE/TRANSFER-BUNDLE/v1\0"
SIGNATURE_DOMAIN = b"PROVENANCE/TRANSFER-SIGNATURE/v1\0"
SIGNATURE_NAMESPACE = "provenance-transfer"


def _identity(domain: bytes, core: object) -> str:
    digest = hashlib.sha256(domain + canonical_json_bytes(core)).hexdigest()
    return f"sha256:{digest}"


def offer_identity(core: object) -> str:
    return _identity(OFFER_DOMAIN, core)


def receipt_identity(core: object) -> str:
    return _identity(RECEIPT_DOMAIN, core)


def transfer_bundle_identity(core: object) -> str:
    return _identity(BUNDLE_DOMAIN, core)


def transfer_signature_identity(core: object) -> str:
    return _identity(SIGNATURE_DOMAIN, core)


def clock_dict(clock: object) -> dict[str, str]:
    try:
        recorded_at = clock.recorded_at
        clock_source = clock.clock_source
        assurance = clock.clock_assurance
    except AttributeError as exc:
        raise TypeError(
            "clock must expose recorded_at, clock_source, and clock_assurance"
        ) from exc
    if not isinstance(recorded_at, str) or not recorded_at:
        raise ValueError("clock recorded_at must be non-empty text")
    if not isinstance(clock_source, str) or not clock_source:
        raise ValueError("clock source must be non-empty text")
    if not isinstance(assurance, ClockAssurance):
        raise TypeError("clock assurance must be a ClockAssurance")
    return {
        "recorded_at": recorded_at,
        "clock_source": clock_source,
        "clock_assurance": assurance.value,
    }


def _system(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be non-empty canonical text")
    if any(ch in value for ch in "\r\n\x00"):
        raise ValueError(f"{label} contains forbidden control characters")
    return value


def offer_core(
    *,
    package_identity: str,
    evidence_manifest_identity: str,
    source_system: str,
    destination_system: str,
    offered_at: object,
) -> dict[str, Any]:
    require_sha256_identity(package_identity, label="transfer package identity")
    require_sha256_identity(
        evidence_manifest_identity,
        label="transfer evidence manifest identity",
    )
    source = _system(source_system, label="source_system")
    destination = _system(destination_system, label="destination_system")
    if source == destination:
        raise ValueError("source_system and destination_system must differ")
    return {
        "schema": TRANSFER_OFFER_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "protocol": TRANSFER_PROTOCOL,
        "subject_kind": "forensic_package",
        "subject_identity": package_identity,
        "evidence_manifest_identity": evidence_manifest_identity,
        "source_system": source,
        "destination_system": destination,
        "offered_at": clock_dict(offered_at),
    }


def receipt_core(
    *,
    transfer_bundle_identity_value: str,
    offer_identity_value: str,
    package_identity: str,
    source_system: str,
    destination_system: str,
    accepted_at: object,
    receiver_custody_identities: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    require_sha256_identity(
        transfer_bundle_identity_value,
        label="transfer bundle identity",
    )
    require_sha256_identity(offer_identity_value, label="offer identity")
    require_sha256_identity(package_identity, label="package identity")
    source = _system(source_system, label="source_system")
    destination = _system(destination_system, label="destination_system")
    if source == destination:
        raise ValueError("source_system and destination_system must differ")
    identities = tuple(receiver_custody_identities)
    if not identities:
        raise ValueError("receipt requires receiver custody acknowledgements")
    for index, value in enumerate(identities):
        require_sha256_identity(
            value,
            label=f"receiver custody identity[{index}]",
        )
    if len(set(identities)) != len(identities):
        raise ValueError("receiver custody identities must be unique")
    return {
        "schema": TRANSFER_RECEIPT_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "protocol": TRANSFER_PROTOCOL,
        "transfer_bundle_identity": transfer_bundle_identity_value,
        "offer_identity": offer_identity_value,
        "subject_kind": "forensic_package",
        "subject_identity": package_identity,
        "source_system": source,
        "destination_system": destination,
        "receipt_status": "ACCEPTED",
        "accepted_at": clock_dict(accepted_at),
        "receiver_custody_identities": list(identities),
        "ordering": "PARTIAL",
    }


def transfer_signature_core(
    *,
    role: str,
    subject_kind: str,
    subject_identity: str,
    signed_bytes: bytes,
    public_key: str,
    signature: str,
) -> dict[str, Any]:
    if role not in {"sender", "receiver"}:
        raise ValueError("transfer signature role must be sender or receiver")
    if subject_kind not in {"transfer_offer", "transfer_receipt"}:
        raise ValueError("unsupported transfer signature subject kind")
    require_sha256_identity(
        subject_identity,
        label="transfer signature subject identity",
    )
    normalized = normalize_ed25519_public_key(public_key)
    if not isinstance(signature, str) or not signature:
        raise ValueError("transfer signature must be non-empty text")
    return {
        "schema": TRANSFER_SIGNATURE_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "role": role,
        "subject_kind": subject_kind,
        "subject_identity": subject_identity,
        "signed_content_identity": sha256_content_identity(signed_bytes),
        "algorithm": "ssh-ed25519",
        "namespace": SIGNATURE_NAMESPACE,
        "public_key": normalized,
        "key_fingerprint": ed25519_key_fingerprint(normalized),
        "signature": signature,
    }


def transfer_bundle_core(
    *,
    package_identity: str,
    evidence_manifest_identity: str,
    offer_identity_value: str,
    offer_signature_identity: str,
    source_system: str,
    destination_system: str,
    members: list[dict[str, object]],
) -> dict[str, Any]:
    for label, value in (
        ("package identity", package_identity),
        ("evidence manifest identity", evidence_manifest_identity),
        ("offer identity", offer_identity_value),
        ("offer signature identity", offer_signature_identity),
    ):
        require_sha256_identity(value, label=label)
    source = _system(source_system, label="source_system")
    destination = _system(destination_system, label="destination_system")
    if not isinstance(members, list):
        raise TypeError("transfer bundle members must be a list")
    return {
        "schema": TRANSFER_BUNDLE_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "protocol": TRANSFER_PROTOCOL,
        "transfer_state": "FINALIZED",
        "subject_kind": "forensic_package",
        "subject_identity": package_identity,
        "evidence_manifest_identity": evidence_manifest_identity,
        "offer_identity": offer_identity_value,
        "offer_signature_identity": offer_signature_identity,
        "source_system": source,
        "destination_system": destination,
        "members": members,
        "ordering": "PARTIAL",
    }
