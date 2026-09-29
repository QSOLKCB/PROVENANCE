"""Phase 12 trust-record schemas and deterministic identities."""
from __future__ import annotations

import base64
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any

from provenance_core import (
    CANONICALIZATION_ID,
    canonical_json_bytes,
    require_sha256_identity,
)


SIGNATURE_SCHEMA = "provenance.signature.v1"
EXTERNAL_ANCHOR_SCHEMA = "provenance.external-anchor.v1"
GIT_ANCHOR_PAYLOAD_SCHEMA = "provenance.git-anchor-payload.v1"
SIGNATURE_DOMAIN = b"PROVENANCE/SIGNATURE-RECORD/v1\0"
EXTERNAL_ANCHOR_DOMAIN = b"PROVENANCE/EXTERNAL-ANCHOR/v1\0"
SIGNATURE_NAMESPACE = "provenance"
SUBJECT_KIND_FORENSIC_PACKAGE = "forensic_package"
_SIGNATURE_ALGORITHM = "ssh-ed25519"
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


def signature_record_identity(core: object) -> str:
    digest = hashlib.sha256(
        SIGNATURE_DOMAIN + canonical_json_bytes(core)
    ).hexdigest()
    return f"sha256:{digest}"


def external_anchor_identity(core: object) -> str:
    digest = hashlib.sha256(
        EXTERNAL_ANCHOR_DOMAIN + canonical_json_bytes(core)
    ).hexdigest()
    return f"sha256:{digest}"


def sha256_content_identity(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("content identity input must be bytes")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def normalize_ed25519_public_key(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("public key must be text")
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] != _SIGNATURE_ALGORITHM:
        raise ValueError("public key must be ssh-ed25519")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise ValueError("public key base64 is invalid") from exc
    if not blob:
        raise ValueError("public key blob must not be empty")
    return f"{_SIGNATURE_ALGORITHM} {parts[1]}"


def ed25519_key_fingerprint(public_key: str) -> str:
    normalized = normalize_ed25519_public_key(public_key)
    encoded = normalized.split(" ", 1)[1]
    blob = base64.b64decode(encoded, validate=True)
    digest = hashlib.sha256(blob).digest()
    value = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{value}"


def git_anchor_payload(
    subject_identity: str,
    *,
    subject_kind: str = SUBJECT_KIND_FORENSIC_PACKAGE,
) -> bytes:
    require_sha256_identity(
        subject_identity,
        label="anchor subject identity",
    )
    if subject_kind != SUBJECT_KIND_FORENSIC_PACKAGE:
        raise ValueError("unsupported anchor subject kind")
    return canonical_json_bytes(
        {
            "schema": GIT_ANCHOR_PAYLOAD_SCHEMA,
            "canonicalization": CANONICALIZATION_ID,
            "subject_kind": subject_kind,
            "subject_identity": subject_identity,
        }
    )


def validate_git_anchor_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Git anchor path must be a non-empty string")
    if "\x00" in value or "\\" in value:
        raise ValueError("Git anchor path must be portable")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ValueError("Git anchor path must be relative")
    parts = path.parts
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(_SAFE_SEGMENT.fullmatch(part) is None for part in parts)
    ):
        raise ValueError("Git anchor path is unsafe")
    normalized = PurePosixPath(*parts).as_posix()
    if normalized != value:
        raise ValueError("Git anchor path must be canonical")
    return normalized


def signature_core(
    *,
    subject_identity: str,
    signed_content_identity: str,
    public_key: str,
    signature: str,
) -> dict[str, Any]:
    require_sha256_identity(
        subject_identity,
        label="signature subject identity",
    )
    require_sha256_identity(
        signed_content_identity,
        label="signed content identity",
    )
    normalized_key = normalize_ed25519_public_key(public_key)
    if not isinstance(signature, str) or not signature:
        raise ValueError("signature must be non-empty text")
    return {
        "schema": SIGNATURE_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "subject_kind": SUBJECT_KIND_FORENSIC_PACKAGE,
        "subject_identity": subject_identity,
        "signed_path": "package.json",
        "signed_content_identity": signed_content_identity,
        "algorithm": _SIGNATURE_ALGORITHM,
        "namespace": SIGNATURE_NAMESPACE,
        "public_key": normalized_key,
        "key_fingerprint": ed25519_key_fingerprint(normalized_key),
        "signature": signature,
    }


def external_anchor_core(
    *,
    subject_identity: str,
    commit_oid: str,
    git_object_format: str,
    path: str,
    payload_content_identity: str,
    repository_hint: str | None,
) -> dict[str, Any]:
    require_sha256_identity(
        subject_identity,
        label="anchor subject identity",
    )
    require_sha256_identity(
        payload_content_identity,
        label="anchor payload content identity",
    )
    if git_object_format not in {"sha1", "sha256"}:
        raise ValueError("Git object format must be sha1 or sha256")
    expected_length = 40 if git_object_format == "sha1" else 64
    if (
        not isinstance(commit_oid, str)
        or len(commit_oid) != expected_length
        or any(char not in "0123456789abcdef" for char in commit_oid)
    ):
        raise ValueError("Git commit OID does not match object format")
    anchor_path = validate_git_anchor_path(path)
    if repository_hint is not None and (
        not isinstance(repository_hint, str) or not repository_hint
    ):
        raise ValueError("repository_hint must be null or non-empty text")
    return {
        "schema": EXTERNAL_ANCHOR_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "subject_kind": SUBJECT_KIND_FORENSIC_PACKAGE,
        "subject_identity": subject_identity,
        "mechanism": "git-commit",
        "git_object_format": git_object_format,
        "commit_oid": commit_oid,
        "path": anchor_path,
        "payload_content_identity": payload_content_identity,
        "repository_hint": repository_hint,
    }
