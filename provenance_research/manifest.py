"""Version 1 research manifest contract. No network or proof execution."""
from __future__ import annotations

import re
from collections.abc import Mapping

from provenance_core import (
    CANONICALIZATION_ID, MAX_SAFE_INTEGER, canonical_json_bytes,
    domain_identity, parse_canonical_json_bytes, require_sha256_identity,
    sha256_identity,
)

SCHEMA = "provenance.research-manifest.v1"
DOMAIN = b"PROVENANCE/RESEARCH-MANIFEST/v1\0"


class ResearchError(ValueError):
    """The research evidence contract was violated."""


def _object(value: object, keys: str, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise ResearchError(f"{label}: object keys changed")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResearchError(f"{label}: non-empty string required")
    return value


def _list(value: object, label: str, *, nonempty: bool = False) -> list:
    if not isinstance(value, list) or (nonempty and not value):
        raise ResearchError(f"{label}: {'non-empty ' if nonempty else ''}list required")
    return value


def _path(value: object) -> str:
    path = _text(value, "artifact path")
    if path.startswith("/") or "\\" in path or ":" in path or any(
        part in {"", ".", ".."} for part in path.split("/")
    ) or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in path):
        raise ResearchError("artifact path must be a portable relative path")
    return path


def _validate(core: object) -> dict:
    core = _object(core, "schema canonicalization evidence_class source artifacts uses claims attribution", "core")
    if core["schema"] != SCHEMA or core["canonicalization"] != CANONICALIZATION_ID:
        raise ResearchError("unsupported research schema or canonicalization")
    if core["evidence_class"] != "DECLARED":
        raise ResearchError("research metadata must remain DECLARED")
    source = _object(core["source"], "project repository commit commit_algorithm license", "source")
    for key in ("project", "repository", "license"):
        _text(source[key], f"source.{key}")
    algorithm = _text(source["commit_algorithm"], "source.commit_algorithm")
    if algorithm not in ("sha1", "sha256"):
        raise ResearchError("source.commit_algorithm must be sha1 or sha256")
    width = 40 if algorithm == "sha1" else 64
    if not isinstance(source["commit"], str) or re.fullmatch(r"[0-9a-f]{%d}" % width, source["commit"]) is None:
        raise ResearchError("source.commit must match its declared Git hash algorithm")

    artifacts = {}
    paths = set()
    roles = {"source", "local", "license", "notice", "citation", "scope", "comparator", "receipt"}
    for artifact in _list(core["artifacts"], "artifacts", nonempty=True):
        artifact = _object(artifact, "key path origin role content_identity byte_count", "artifact")
        key = _text(artifact["key"], "artifact key")
        path = _path(artifact["path"])
        origin = _text(artifact["origin"], "artifact origin")
        role = _text(artifact["role"], "artifact role")
        if origin not in ("upstream", "local") or role not in roles:
            raise ResearchError("invalid artifact origin or role")
        locator = (artifact["origin"], path)
        if key in artifacts or locator in paths:
            raise ResearchError("duplicate artifact key or origin/path")
        require_sha256_identity(artifact["content_identity"])
        count = artifact["byte_count"]
        if type(count) is not int or not 0 <= count <= MAX_SAFE_INTEGER:
            raise ResearchError("artifact byte_count must be a non-negative safe integer")
        artifacts[key] = artifact
        paths.add(locator)

    def ref(key: object, *, role: str | None = None, origin: str | None = None) -> dict:
        key = _text(key, "artifact reference")
        if key not in artifacts:
            raise ResearchError(f"unknown artifact reference: {key}")
        artifact = artifacts[key]
        if (role is not None and artifact["role"] != role) or (origin is not None and artifact["origin"] != origin):
            raise ResearchError(f"artifact reference has wrong role/origin: {key}")
        return artifact

    pairs = set()
    for use in _list(core["uses"], "uses", nonempty=True):
        use = _object(use, "upstream local mode modification_notice", "use")
        upstream = ref(use["upstream"], origin="upstream")
        mode = use["mode"]
        if mode not in ("reference", "adaptation", "derived", "copied"):
            raise ResearchError("invalid usage mode")
        if use["local"] is not None:
            _text(use["local"], "use local reference")
        pair = (use["upstream"], use["local"])
        if pair in pairs:
            raise ResearchError("duplicate use binding")
        pairs.add(pair)
        if mode == "reference":
            if use["local"] is not None or use["modification_notice"] is not None:
                raise ResearchError("reference must not claim a local derivative")
        else:
            local = ref(use["local"], role="local", origin="local")
            if mode == "copied":
                if (local["content_identity"], local["byte_count"]) != (upstream["content_identity"], upstream["byte_count"]):
                    raise ResearchError("copied use must bind identical bytes")
                if use["modification_notice"] is not None:
                    raise ResearchError("copied use must not claim modifications")
            else:
                _text(use["modification_notice"], "modification notice")

    for claim in _list(core["claims"], "claims", nonempty=True):
        claim = _object(claim, "family manuscript manuscript_scope formalized_scope local_scope scope_artifact declarations comparator verification_receipts", "claim")
        for key in ("family", "manuscript", "manuscript_scope", "formalized_scope", "local_scope"):
            _text(claim[key], f"claim.{key}")
        if claim["scope_artifact"] is not None:
            ref(claim["scope_artifact"], role="scope", origin="upstream")
        declarations = _list(claim["declarations"], "declarations")
        for declaration in declarations:
            _text(declaration, "declaration")
        if len(set(declarations)) != len(declarations):
            raise ResearchError("duplicate declaration")
        if claim["comparator"] is not None:
            ref(claim["comparator"], role="comparator", origin="upstream")
            if not declarations or claim["scope_artifact"] is None:
                raise ResearchError("comparator requires declarations and a scope artifact")
        for receipt in _list(claim["verification_receipts"], "verification_receipts"):
            ref(receipt, role="receipt")

    attribution = _object(core["attribution"], "credit license_artifact notice_status notice_artifact citations", "attribution")
    _text(attribution["credit"], "attribution credit")
    ref(attribution["license_artifact"], role="license", origin="upstream")
    if attribution["notice_status"] == "present":
        ref(attribution["notice_artifact"], role="notice", origin="upstream")
    elif attribution["notice_status"] in ("not_observed", "absent_in_inspected_tree"):
        if attribution["notice_artifact"] is not None:
            raise ResearchError("notice artifact contradicts notice status")
    else:
        raise ResearchError("invalid notice status")
    for citation in _list(attribution["citations"], "citations", nonempty=True):
        ref(citation, role="citation", origin="upstream")
    return core


def seal_research_manifest(core: dict) -> bytes:
    """Snapshot validated declarations as canonical, identity-bound bytes.

    Sealing does not check artifact possession, repository membership, legal
    compliance, or mathematical validity. Use the independent verifier for bytes.
    """
    core = parse_canonical_json_bytes(canonical_json_bytes(core))
    _validate(core)
    return canonical_json_bytes({
        "core": core,
        "research_identity": domain_identity(DOMAIN, core),
        "self_hash_exclusion": "research_identity",
    })


def verify_research_manifest(data: bytes, contents: Mapping[str, bytes]) -> dict:
    """Recompute identity and all artifact bindings from caller-supplied bytes.

    contents maps sha256:<digest> to exact retained bytes. No artifact paths are
    opened, no URLs fetched, and no supplied mathematical receipt is executed.
    Missing evidence fails the byte-integrity result and remains visible.
    """
    identity = None
    metadata_class = None
    missing = []
    checked = []
    errors = []
    try:
        envelope = _object(parse_canonical_json_bytes(data), "core research_identity self_hash_exclusion", "envelope")
        core = _validate(envelope["core"])
        metadata_class = core["evidence_class"]
        identity = domain_identity(DOMAIN, core)
        if envelope["self_hash_exclusion"] != "research_identity" or envelope["research_identity"] != identity:
            raise ResearchError("research identity or self-hash exclusion mismatch")
        for artifact in core["artifacts"]:
            digest = artifact["content_identity"]
            try:
                raw = contents[digest]
            except KeyError:
                missing.append(artifact["key"])
                continue
            if not isinstance(raw, bytes) or len(raw) != artifact["byte_count"] or sha256_identity(raw) != digest:
                errors.append(f"artifact bytes mismatch: {artifact['key']}")
            else:
                checked.append(artifact["key"])
    except (TypeError, ValueError, RecursionError) as exc:
        errors.append(str(exc))
    return {
        "schema": "provenance.research-verification-report.v1",
        "research_identity": identity,
        "byte_integrity_verified": not errors and not missing,
        "checked_artifacts": checked,
        "missing_artifacts": missing,
        "errors": errors,
        "metadata_class": metadata_class,
        "upstream_membership": "not_checked",
        "mathematical_validity": "not_checked",
        "license_compliance": "not_checked",
    }
