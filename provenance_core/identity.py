"""Cryptographic identity helpers for PROVENANCE."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .canonical import canonical_json_bytes

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

EVENT_DOMAIN = b"PROVENANCE/EVENT/v1\0"
MANIFEST_DOMAIN = b"PROVENANCE/MANIFEST/v1\0"


class IdentityError(ValueError):
    """Raised when an identity is malformed."""


def sha256_identity(data: bytes) -> str:
    """Return the ordinary content identity for exact artifact bytes."""

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def domain_identity(domain: bytes, value: Any) -> str:
    """Hash canonical structured evidence under an explicit semantic domain."""

    if not domain or not domain.endswith(b"\0"):
        raise IdentityError("identity domain must be non-empty and NUL-terminated")
    digest = hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()
    return f"sha256:{digest}"


def event_identity(core: Any) -> str:
    return domain_identity(EVENT_DOMAIN, core)


def manifest_identity(core: Any) -> str:
    return domain_identity(MANIFEST_DOMAIN, core)


def require_sha256_identity(value: str, *, label: str = "identity") -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise IdentityError(f"{label} must be sha256:<64 lowercase hex characters>")
    return value
