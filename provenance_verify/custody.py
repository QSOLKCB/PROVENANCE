"""Independent verification for PROVENANCE custody records."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable

from provenance_core import (
    CANONICALIZATION_ID,
    CUSTODY_SCHEMA,
    CanonicalizationError,
    ClockAssurance,
    CustodyAction,
    custody_identity,
    parse_canonical_json_bytes,
    require_sha256_identity,
)

CUSTODY_VERIFICATION_REPORT_SCHEMA = "provenance.custody-verification-report.v1"
_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


@dataclass(frozen=True, slots=True)
class CustodyVerificationReport:
    integrity_verified: bool
    record_count: int
    subject_count: int
    tips: tuple[tuple[str, str], ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": CUSTODY_VERIFICATION_REPORT_SCHEMA,
            "integrity_verified": self.integrity_verified,
            "record_count": self.record_count,
            "subject_count": self.subject_count,
            "tips": [
                {"subject_identity": subject, "custody_identity": tip}
                for subject, tip in self.tips
            ],
            "errors": list(self.errors),
        }


def _validate_time(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ValueError(
            f"{label} must be canonical UTC RFC3339 "
            "YYYY-MM-DDTHH:MM:SS[.ffffff]Z"
        )
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid UTC timestamp") from exc
    return value


def _parse_record(data: bytes, index: int) -> tuple[str, dict[str, object]]:
    label = f"custody record[{index}]"
    try:
        value = parse_canonical_json_bytes(data)
    except (CanonicalizationError, RecursionError) as exc:
        raise ValueError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    if set(value) != {
        "core",
        "custody_identity",
        "self_hash_exclusion",
    }:
        raise ValueError(f"{label} envelope keys changed")

    claimed = value.get("custody_identity")
    try:
        require_sha256_identity(claimed, label=f"{label} identity")
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if value.get("self_hash_exclusion") != "custody_identity":
        raise ValueError(f"{label} self_hash_exclusion changed")

    core = value.get("core")
    if not isinstance(core, dict):
        raise ValueError(f"{label} core must be an object")
    if set(core) != {
        "schema",
        "canonicalization",
        "subject_identity",
        "action",
        "recorded_at",
        "clock_source",
        "clock_assurance",
        "actor",
        "source",
        "previous_custody",
    }:
        raise ValueError(f"{label} core keys changed")
    if core.get("schema") != CUSTODY_SCHEMA:
        raise ValueError(f"{label} schema changed")
    if core.get("canonicalization") != CANONICALIZATION_ID:
        raise ValueError(f"{label} canonicalization changed")

    subject = core.get("subject_identity")
    try:
        require_sha256_identity(subject, label=f"{label} subject identity")
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc

    action = core.get("action")
    if not isinstance(action, str) or action not in {
        item.value for item in CustodyAction
    }:
        raise ValueError(f"{label} action is invalid")

    _validate_time(core.get("recorded_at"), label=f"{label} recorded_at")

    clock_source = core.get("clock_source")
    if not isinstance(clock_source, str) or not clock_source:
        raise ValueError(f"{label} clock_source must be a non-empty string")

    assurance = core.get("clock_assurance")
    if not isinstance(assurance, str) or assurance not in {
        item.value for item in ClockAssurance
    }:
        raise ValueError(f"{label} clock_assurance is invalid")

    for field in ("actor", "source"):
        item = core.get(field)
        if item is not None and (not isinstance(item, str) or not item):
            raise ValueError(
                f"{label} {field} must be null or a non-empty string"
            )

    previous = core.get("previous_custody")
    if previous is not None:
        try:
            require_sha256_identity(
                previous,
                label=f"{label} previous custody identity",
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc

    expected = custody_identity(core)
    if claimed != expected:
        raise ValueError(f"{label} identity does not match canonical core")

    return str(claimed), core


def verify_custody_records(
    records: Iterable[bytes],
) -> CustodyVerificationReport:
    errors: list[str] = []
    parsed: dict[str, dict[str, object]] = {}

    for index, data in enumerate(records):
        if not isinstance(data, bytes):
            errors.append(f"custody record[{index}] must be bytes")
            continue
        try:
            identity, core = _parse_record(data, index)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if identity in parsed:
            errors.append(f"duplicate custody identity: {identity}")
            continue
        parsed[identity] = core

    by_subject: dict[str, set[str]] = {}
    for identity, core in parsed.items():
        subject = str(core["subject_identity"])
        by_subject.setdefault(subject, set()).add(identity)

    tips: list[tuple[str, str]] = []

    for subject, identities in sorted(by_subject.items()):
        roots: list[str] = []
        child_of: dict[str, str] = {}
        referenced: set[str] = set()

        for identity in sorted(identities):
            core = parsed[identity]
            previous = core["previous_custody"]
            if previous is None:
                roots.append(identity)
                continue
            previous = str(previous)
            if previous not in parsed:
                errors.append(
                    f"custody {identity} has dangling predecessor {previous}"
                )
                continue
            if str(parsed[previous]["subject_identity"]) != subject:
                errors.append(
                    f"custody {identity} links across subjects to {previous}"
                )
                continue
            if previous in child_of:
                errors.append(
                    f"custody predecessor {previous} has multiple children: "
                    f"{child_of[previous]}, {identity}"
                )
            else:
                child_of[previous] = identity
            referenced.add(previous)

        if len(roots) != 1:
            errors.append(
                f"subject {subject} must have exactly one custody root; "
                f"found {len(roots)}"
            )
            continue

        root = roots[0]
        visited: set[str] = set()
        current = root
        while True:
            if current in visited:
                errors.append(
                    f"subject {subject} custody chain contains a cycle at {current}"
                )
                break
            visited.add(current)
            child = child_of.get(current)
            if child is None:
                tips.append((subject, current))
                break
            current = child

        if visited != identities:
            missing = ", ".join(sorted(identities - visited))
            errors.append(
                f"subject {subject} custody chain is disconnected: {missing}"
            )

    return CustodyVerificationReport(
        integrity_verified=not errors,
        record_count=len(parsed),
        subject_count=len(by_subject),
        tips=tuple(sorted(tips)),
        errors=tuple(errors),
    )
