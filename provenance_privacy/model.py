"""Phase 14 selective-disclosure schemas and deterministic redaction."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable

from provenance_core import (
    CANONICALIZATION_ID,
    MAX_SAFE_INTEGER,
    canonical_json_bytes,
    require_sha256_identity,
)


REDACTION_SPEC_SCHEMA = "provenance.redaction-spec.v1"
DISCLOSURE_SCHEMA = "provenance.selective-disclosure.v1"
REDACTION_SPEC_DOMAIN = b"PROVENANCE/REDACTION-SPEC/v1\0"
DISCLOSURE_DOMAIN = b"PROVENANCE/SELECTIVE-DISCLOSURE/v1\0"
REDACTION_ACTOR = "provenance-privacy:redaction/v1"
REDACTION_OPERATION = "privacy.redact.byte_ranges"


@dataclass(frozen=True, slots=True, order=True)
class RedactionRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if (
            type(self.start) is not int
            or type(self.end) is not int
            or self.start < 0
            or self.end <= self.start
            or self.end > MAX_SAFE_INTEGER
        ):
            raise ValueError(
                "redaction range must satisfy 0 <= start < end <= MAX_SAFE_INTEGER"
            )

    def to_dict(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}


def normalize_ranges(
    ranges: Iterable[RedactionRange | tuple[int, int]],
    *,
    byte_count: int,
) -> tuple[RedactionRange, ...]:
    if type(byte_count) is not int or byte_count < 0:
        raise ValueError("byte_count must be a non-negative integer")
    normalized: list[RedactionRange] = []
    for item in ranges:
        value = (
            item
            if isinstance(item, RedactionRange)
            else RedactionRange(*item)
        )
        if value.end > byte_count:
            raise ValueError("redaction range exceeds source byte count")
        normalized.append(value)
    normalized.sort()
    if not normalized:
        raise ValueError("at least one redaction range is required")
    for prior, current in zip(normalized, normalized[1:]):
        if current.start < prior.end:
            raise ValueError("redaction ranges must not overlap")
    return tuple(normalized)


def redaction_spec_identity(core: object) -> str:
    digest = hashlib.sha256(
        REDACTION_SPEC_DOMAIN + canonical_json_bytes(core)
    ).hexdigest()
    return f"sha256:{digest}"


def disclosure_identity(core: object) -> str:
    digest = hashlib.sha256(
        DISCLOSURE_DOMAIN + canonical_json_bytes(core)
    ).hexdigest()
    return f"sha256:{digest}"


def build_redaction_spec_core(
    *,
    source_content_identity: str,
    source_record_identity: str,
    source_byte_count: int,
    source_media_type: str,
    ranges: Iterable[RedactionRange | tuple[int, int]],
    mask_byte: int,
) -> dict[str, object]:
    require_sha256_identity(
        source_content_identity,
        label="redaction source content identity",
    )
    require_sha256_identity(
        source_record_identity,
        label="redaction source record identity",
    )
    if (
        type(source_byte_count) is not int
        or source_byte_count < 0
        or source_byte_count > MAX_SAFE_INTEGER
    ):
        raise ValueError("source_byte_count must be a canonical safe integer")
    if not isinstance(source_media_type, str) or not source_media_type:
        raise ValueError("source_media_type must be non-empty text")
    if type(mask_byte) is not int or not 0 <= mask_byte <= 255:
        raise ValueError("mask_byte must be an integer from 0 through 255")
    normalized = normalize_ranges(ranges, byte_count=source_byte_count)
    return {
        "schema": REDACTION_SPEC_SCHEMA,
        "canonicalization": CANONICALIZATION_ID,
        "method": "byte-range-mask",
        "source_content_identity": source_content_identity,
        "source_record_identity": source_record_identity,
        "source_byte_count": source_byte_count,
        "source_media_type": source_media_type,
        "ranges": [item.to_dict() for item in normalized],
        "mask_byte": mask_byte,
    }


def apply_redaction(
    source: bytes,
    *,
    ranges: Iterable[RedactionRange | tuple[int, int]],
    mask_byte: int = 42,
) -> bytes:
    if not isinstance(source, bytes):
        raise TypeError("source must be bytes")
    if type(mask_byte) is not int or not 0 <= mask_byte <= 255:
        raise ValueError("mask_byte must be an integer from 0 through 255")
    normalized = normalize_ranges(ranges, byte_count=len(source))
    output = bytearray(source)
    for item in normalized:
        output[item.start:item.end] = bytes([mask_byte]) * (
            item.end - item.start
        )
    return bytes(output)
