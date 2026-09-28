"""Canonical JSON for PROVENANCE structured records.

Version 1 deliberately accepts only the portable JSON value subset needed by
the bootstrap evidence core. In particular, floating-point numbers are rejected
until their cross-language canonical representation is specified.
"""
from __future__ import annotations

import json
import math
from typing import Any

CANONICALIZATION_ID = "provenance.canonical-json.v1"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by canonical JSON v1."""


def _validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"{path}: integer is outside the portable JSON safe-integer range"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"{path}: non-finite numbers are forbidden")
        raise CanonicalizationError(
            f"{path}: floating-point numbers are not supported by canonical JSON v1"
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _validate_value(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"{path}: unsupported canonical JSON type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes terminated by exactly one LF."""

    _validate_value(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return (encoded + "\n").encode("utf-8")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise CanonicalizationError(f"non-finite JSON constant is forbidden: {token}")


def parse_canonical_json_bytes(data: bytes) -> Any:
    """Parse bytes only if they are strict canonical JSON v1."""

    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalizationError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalizationError("input is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"input is not strict JSON: {exc}") from exc

    _validate_value(value)
    if canonical_json_bytes(value) != data:
        raise CanonicalizationError("input is valid JSON but not canonical JSON v1")
    return value
