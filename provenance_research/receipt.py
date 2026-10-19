"""Source-bound research check declarations and retained-byte comparisons.

This separate contract does not execute builds or establish causal provenance.
All bindings are DECLARED; only integrity and exact byte equality are derived.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from provenance_core import (
    CANONICALIZATION_ID, MAX_SAFE_INTEGER, canonical_json_bytes,
    domain_identity, parse_canonical_json_bytes, require_sha256_identity,
    sha256_identity,
)
from .manifest import ResearchError

SCHEMA = "provenance.research-check-receipt.v1"
DOMAIN = b"PROVENANCE/RESEARCH-CHECK-RECEIPT/v1\0"


def _object(value: object, keys: str, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise ResearchError(f"{label}: object keys changed")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResearchError(f"{label}: non-empty string required")
    return value


def _list(value: object, label: str) -> list:
    if not isinstance(value, list) or not value:
        raise ResearchError(f"{label}: non-empty list required")
    return value


def _validate(core: object) -> dict:
    core = _object(core, "schema canonicalization evidence_class source artifacts build checks", "core")
    if core["schema"] != SCHEMA or core["canonicalization"] != CANONICALIZATION_ID:
        raise ResearchError("unsupported research check schema or canonicalization")
    if core["evidence_class"] != "DECLARED":
        raise ResearchError("research check metadata must remain DECLARED")
    source = _object(core["source"], "repository commit_algorithm commit", "source")
    _text(source["repository"], "source.repository")
    algorithm = _text(source["commit_algorithm"], "source.commit_algorithm")
    if algorithm not in ("sha1", "sha256"):
        raise ResearchError("source.commit_algorithm must be sha1 or sha256")
    width = 40 if algorithm == "sha1" else 64
    if not isinstance(source["commit"], str) or re.fullmatch(r"[0-9a-f]{%d}" % width, source["commit"]) is None:
        raise ResearchError("source.commit must match its declared Git hash algorithm")

    artifacts = {}
    for artifact in _list(core["artifacts"], "artifacts"):
        artifact = _object(artifact, "key role content_identity byte_count", "artifact")
        key = _text(artifact["key"], "artifact key")
        role = _text(artifact["role"], "artifact role")
        if role not in ("source", "build", "output", "expectation", "expectation_basis"):
            raise ResearchError("invalid artifact role")
        if key in artifacts:
            raise ResearchError("duplicate artifact key")
        require_sha256_identity(artifact["content_identity"])
        count = artifact["byte_count"]
        if type(count) is not int or not 0 <= count <= MAX_SAFE_INTEGER:
            raise ResearchError("artifact byte_count must be a non-negative safe integer")
        artifacts[key] = artifact

    def ref(key: object, role: str) -> str:
        key = _text(key, "artifact reference")
        if key not in artifacts or artifacts[key]["role"] != role:
            raise ResearchError(f"unknown or wrong-role artifact reference: {key}")
        return key

    def refs(value: object, role: str) -> list:
        values = _list(value, f"build {role} references")
        keys = [ref(key, role) for key in values]
        if len(set(keys)) != len(keys):
            raise ResearchError("duplicate build artifact reference")
        return keys

    build = _object(core["build"], "sources recipe outputs", "build")
    refs(build["sources"], "source")
    ref(build["recipe"], "build")
    outputs = refs(build["outputs"], "output")
    checks = set()
    bindings = set()
    for check in _list(core["checks"], "checks"):
        check = _object(check, "key output expectation expectation_basis expectation_method comparison", "check")
        key = _text(check["key"], "check key")
        if key in checks:
            raise ResearchError("duplicate check key")
        checks.add(key)
        output = ref(check["output"], "output")
        expectation = ref(check["expectation"], "expectation")
        basis = ref(check["expectation_basis"], "expectation_basis")
        if output not in outputs:
            raise ResearchError("check output must be bound to build outputs")
        if check["expectation_method"] not in ("analytic", "external_oracle"):
            raise ResearchError("unsupported expectation method")
        if check["comparison"] != "exact_bytes":
            raise ResearchError("unsupported comparison")
        binding = (output, expectation, basis)
        if binding in bindings:
            raise ResearchError("duplicate check binding")
        bindings.add(binding)
    return core


def research_check_receipt_identity(core: dict) -> str:
    """Return the domain identity of a validated declaration, not proof of it."""
    return domain_identity(DOMAIN, _validate(core))


def seal_research_check_receipt(core: dict) -> bytes:
    """Snapshot declarations; sealing neither executes nor verifies artifacts."""
    core = parse_canonical_json_bytes(canonical_json_bytes(core))
    return canonical_json_bytes({
        "core": core,
        "receipt_identity": research_check_receipt_identity(core),
        "self_hash_exclusion": "receipt_identity",
    })


def verify_research_check_receipt(data: bytes, contents: Mapping[str, bytes]) -> dict:
    """Verify supplied retained bytes, then compare exact output/expectation bytes.

    No URL or path is opened and no recipe is executed. Every artifact must pass
    integrity before any comparison is evaluated. Verified bytes are retained in
    memory for comparison, never re-read from a potentially changing backend.
    Equality does not establish expectation independence or semantic correctness.
    """
    report = {
        "schema": "provenance.research-check-verification-report.v1",
        "receipt_identity": None,
        "canonical": False,
        "schema_valid": False,
        "identity_valid": False,
        "metadata_class": None,
        "byte_integrity_verified": False,
        "comparisons_verified": False,
        "checked_artifacts": [],
        "missing_artifacts": [],
        "checks": [],
        "errors": [],
        "build_execution": "not_checked",
        "source_membership": "not_checked",
        "expectation_independence": "not_checked",
        "semantic_correctness": "not_checked",
    }
    try:
        if type(data) is not bytes:
            raise ResearchError("receipt must be bytes")
        envelope = parse_canonical_json_bytes(data)
        report["canonical"] = True
        envelope = _object(envelope, "core receipt_identity self_hash_exclusion", "envelope")
        core = _validate(envelope["core"])
        report["schema_valid"] = True
        report["metadata_class"] = "DECLARED"
        report["checks"] = [{"key": check["key"], "status": "not_checked"} for check in core["checks"]]
        identity = domain_identity(DOMAIN, core)
        report["receipt_identity"] = identity
        if envelope["self_hash_exclusion"] != "receipt_identity" or envelope["receipt_identity"] != identity:
            raise ResearchError("receipt identity or self-hash exclusion mismatch")
        report["identity_valid"] = True
        verified = {}
        for artifact in core["artifacts"]:
            key, digest = artifact["key"], artifact["content_identity"]
            try:
                raw = contents[digest]
            except KeyError:
                report["missing_artifacts"].append(key)
                continue
            except Exception as exc:
                report["missing_artifacts"].append(key)
                report["errors"].append(f"artifact lookup failed: {key} ({type(exc).__name__}): {exc}")
                continue
            if type(raw) is not bytes or len(raw) != artifact["byte_count"] or sha256_identity(raw) != digest:
                report["errors"].append(f"artifact bytes mismatch: {key}")
            else:
                verified[key] = raw
                report["checked_artifacts"].append(key)
        report["byte_integrity_verified"] = not report["errors"] and not report["missing_artifacts"]
        if report["byte_integrity_verified"]:
            for check, result in zip(core["checks"], report["checks"]):
                result["status"] = "matched" if verified[check["output"]] == verified[check["expectation"]] else "mismatched"
            report["comparisons_verified"] = all(item["status"] == "matched" for item in report["checks"])
    except (TypeError, ValueError, RecursionError) as exc:
        report["errors"].append(str(exc))
    return report
