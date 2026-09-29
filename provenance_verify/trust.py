"""Independent Phase 12 signature and external-anchor verification."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from provenance_core import (
    CANONICALIZATION_ID,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    require_sha256_identity,
)
from provenance_trust.model import (
    EXTERNAL_ANCHOR_SCHEMA,
    SIGNATURE_NAMESPACE,
    SIGNATURE_SCHEMA,
    SUBJECT_KIND_FORENSIC_PACKAGE,
    ed25519_key_fingerprint,
    external_anchor_identity,
    git_anchor_payload,
    normalize_ed25519_public_key,
    sha256_content_identity,
    signature_record_identity,
    validate_git_anchor_path,
)
from .package import (
    FORENSIC_PACKAGE_SCHEMA,
    forensic_package_identity,
    verify_forensic_package,
)


SIGNATURE_VERIFICATION_REPORT_SCHEMA = (
    "provenance.signature-verification-report.v1"
)
ANCHOR_VERIFICATION_REPORT_SCHEMA = (
    "provenance.external-anchor-verification-report.v1"
)
ASSURANCE_VERIFICATION_REPORT_SCHEMA = (
    "provenance.assurance-verification-report.v1"
)
_STRUCTURED_LIMIT = 16 * 1024 * 1024
_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SignatureVerificationReport:
    status: str
    subject_identity: str | None
    signature_identity: str | None
    key_fingerprint: str | None
    algorithm: str | None
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": SIGNATURE_VERIFICATION_REPORT_SCHEMA,
            "status": self.status,
            "subject_identity": self.subject_identity,
            "signature_identity": self.signature_identity,
            "key_fingerprint": self.key_fingerprint,
            "algorithm": self.algorithm,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class AnchorVerificationReport:
    status: str
    subject_identity: str | None
    anchor_identity: str | None
    mechanism: str | None
    commit_oid: str | None
    path: str | None
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": ANCHOR_VERIFICATION_REPORT_SCHEMA,
            "status": self.status,
            "subject_identity": self.subject_identity,
            "anchor_identity": self.anchor_identity,
            "mechanism": self.mechanism,
            "commit_oid": self.commit_oid,
            "path": self.path,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class AssuranceVerificationReport:
    integrity: str
    signature: str
    external_anchor: str
    package: dict[str, object]
    signature_report: dict[str, object] | None
    anchor_report: dict[str, object] | None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": ASSURANCE_VERIFICATION_REPORT_SCHEMA,
            "integrity": self.integrity,
            "signature": self.signature,
            "external_anchor": self.external_anchor,
            "package": self.package,
            "signature_report": self.signature_report,
            "anchor_report": self.anchor_report,
        }


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required if not hasattr(os, name)]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if missing:
        raise ValueError(
            "trust verification requires descriptor-relative filesystem support: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0)
    )


def _read_all(fd: int, *, limit: int = _STRUCTURED_LIMIT) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise ValueError("structured trust input exceeds size limit")
        chunks.append(chunk)


def _read_regular_path(path: Path | str, *, label: str) -> bytes:
    supplied = Path(path).expanduser()
    if supplied.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    try:
        fd = os.open(supplied, _file_flags())
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{label} must be a regular file")
        return _read_all(fd)
    finally:
        os.close(fd)


def _read_package_subject(
    package_dir: Path | str,
) -> tuple[bytes, str]:
    root = Path(package_dir).expanduser()
    if root.is_symlink():
        raise ValueError("package root must not be a symbolic link")
    try:
        root_fd = os.open(root, _directory_flags())
    except OSError as exc:
        raise ValueError(
            f"package root cannot be opened safely: {exc}"
        ) from exc
    try:
        try:
            fd = os.open("package.json", _file_flags(), dir_fd=root_fd)
        except OSError as exc:
            raise ValueError(
                f"package.json cannot be opened safely: {exc}"
            ) from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("package.json must be a regular file")
            raw = _read_all(fd)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)

    value = parse_canonical_json_bytes(raw)
    if not isinstance(value, dict) or set(value) != {
        "core",
        "package_identity",
        "self_hash_exclusion",
    }:
        raise ValueError("package.json envelope keys changed")
    core = value.get("core")
    if not isinstance(core, dict):
        raise ValueError("package.json core must be an object")
    if core.get("schema") != FORENSIC_PACKAGE_SCHEMA:
        raise ValueError("package.json schema changed")
    claimed = value.get("package_identity")
    require_sha256_identity(claimed, label="package identity")
    if value.get("self_hash_exclusion") != "package_identity":
        raise ValueError("package.json self_hash_exclusion changed")
    if forensic_package_identity(core) != claimed:
        raise ValueError(
            "package.json identity does not match canonical package core"
        )
    return raw, str(claimed)


def _canonical_record(path: Path | str, *, label: str) -> dict[str, Any]:
    raw = _read_regular_path(path, label=label)
    try:
        value = parse_canonical_json_bytes(raw)
    except Exception as exc:
        raise ValueError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain an object")
    return value


def _tool(name: str) -> str | None:
    return shutil.which(name)


def verify_signature_record(
    package_dir: Path | str,
    signature_record: Path | str,
) -> SignatureVerificationReport:
    subject_identity: str | None = None
    signature_identity_value: str | None = None
    fingerprint: str | None = None
    algorithm: str | None = None
    errors: list[str] = []

    try:
        package_bytes, subject_identity = _read_package_subject(package_dir)
        record = _canonical_record(
            signature_record,
            label="signature record",
        )
        if set(record) != {
            "core",
            "signature_identity",
            "self_hash_exclusion",
        }:
            raise ValueError("signature record envelope keys changed")
        core = record.get("core")
        if not isinstance(core, dict) or set(core) != {
            "schema",
            "canonicalization",
            "subject_kind",
            "subject_identity",
            "signed_path",
            "signed_content_identity",
            "algorithm",
            "namespace",
            "public_key",
            "key_fingerprint",
            "signature",
        }:
            raise ValueError("signature record core keys changed")
        if core.get("schema") != SIGNATURE_SCHEMA:
            raise ValueError("signature record schema changed")
        if core.get("canonicalization") != CANONICALIZATION_ID:
            raise ValueError("signature canonicalization changed")
        if core.get("subject_kind") != SUBJECT_KIND_FORENSIC_PACKAGE:
            raise ValueError("signature subject kind changed")
        if core.get("subject_identity") != subject_identity:
            raise ValueError("signature subject identity does not match package")
        if core.get("signed_path") != "package.json":
            raise ValueError("signature signed_path changed")
        signed_identity = core.get("signed_content_identity")
        require_sha256_identity(
            signed_identity,
            label="signature signed content identity",
        )
        if signed_identity != sha256_content_identity(package_bytes):
            raise ValueError(
                "signature record does not bind the current package.json bytes"
            )
        if core.get("algorithm") != "ssh-ed25519":
            raise ValueError("signature algorithm is unsupported")
        algorithm = "ssh-ed25519"
        if core.get("namespace") != SIGNATURE_NAMESPACE:
            raise ValueError("signature namespace changed")
        public_key = normalize_ed25519_public_key(
            str(core.get("public_key"))
        )
        fingerprint = ed25519_key_fingerprint(public_key)
        if core.get("key_fingerprint") != fingerprint:
            raise ValueError("signature key fingerprint mismatch")
        signature = core.get("signature")
        if (
            not isinstance(signature, str)
            or not signature.startswith("-----BEGIN SSH SIGNATURE-----")
            or not signature.rstrip().endswith("-----END SSH SIGNATURE-----")
        ):
            raise ValueError("signature armor is invalid")
        claimed = record.get("signature_identity")
        require_sha256_identity(claimed, label="signature identity")
        if record.get("self_hash_exclusion") != "signature_identity":
            raise ValueError("signature self_hash_exclusion changed")
        if signature_record_identity(core) != claimed:
            raise ValueError(
                "signature identity does not match canonical signature core"
            )
        signature_identity_value = str(claimed)
    except Exception as exc:
        errors.append(str(exc))
        return SignatureVerificationReport(
            "FAILED",
            subject_identity,
            signature_identity_value,
            fingerprint,
            algorithm,
            tuple(errors),
        )

    ssh_keygen = _tool("ssh-keygen")
    if ssh_keygen is None:
        return SignatureVerificationReport(
            "UNAVAILABLE",
            subject_identity,
            signature_identity_value,
            fingerprint,
            algorithm,
            ("ssh-keygen is unavailable",),
        )

    with tempfile.TemporaryDirectory(prefix="provenance-verify-sign-") as tmp:
        root = Path(tmp)
        allowed = root / "allowed_signers"
        sig = root / "signature"
        allowed.write_text(
            f"provenance {public_key}\n",
            encoding="ascii",
        )
        sig.write_text(signature, encoding="ascii")
        try:
            completed = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed),
                    "-I",
                    "provenance",
                    "-n",
                    SIGNATURE_NAMESPACE,
                    "-s",
                    str(sig),
                ],
                input=package_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return SignatureVerificationReport(
                "UNAVAILABLE",
                subject_identity,
                signature_identity_value,
                fingerprint,
                algorithm,
                (f"ssh-keygen verification could not execute: {exc}",),
            )
    if completed.returncode != 0:
        detail = completed.stderr.decode(
            "utf-8", errors="replace"
        ).strip()
        return SignatureVerificationReport(
            "FAILED",
            subject_identity,
            signature_identity_value,
            fingerprint,
            algorithm,
            (detail or "SSH signature verification failed",),
        )
    return SignatureVerificationReport(
        "VERIFIED",
        subject_identity,
        signature_identity_value,
        fingerprint,
        algorithm,
        (),
    )


def _safe_git_repo(path: Path | str) -> Path:
    supplied = Path(path).expanduser()
    if supplied.is_symlink():
        raise ValueError("Git anchor repository root must not be a symlink")
    resolved = supplied.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("Git anchor repository must be a directory")
    return resolved


def _git(
    git: str,
    repo: Path,
    args: list[str],
    *,
    text: bool = True,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        [git, "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
        text=text,
        encoding="utf-8" if text else None,
        errors="replace" if text else None,
        env=env,
    )


def verify_git_anchor_record(
    package_dir: Path | str,
    anchor_record: Path | str,
    *,
    git_repo: Path | str | None,
) -> AnchorVerificationReport:
    subject_identity: str | None = None
    anchor_identity_value: str | None = None
    mechanism: str | None = None
    commit_oid: str | None = None
    anchor_path: str | None = None

    try:
        _package_bytes, subject_identity = _read_package_subject(package_dir)
        record = _canonical_record(anchor_record, label="anchor record")
        if set(record) != {
            "core",
            "anchor_identity",
            "self_hash_exclusion",
        }:
            raise ValueError("anchor record envelope keys changed")
        core = record.get("core")
        if not isinstance(core, dict) or set(core) != {
            "schema",
            "canonicalization",
            "subject_kind",
            "subject_identity",
            "mechanism",
            "git_object_format",
            "commit_oid",
            "path",
            "payload_content_identity",
            "repository_hint",
        }:
            raise ValueError("anchor record core keys changed")
        if core.get("schema") != EXTERNAL_ANCHOR_SCHEMA:
            raise ValueError("anchor record schema changed")
        if core.get("canonicalization") != CANONICALIZATION_ID:
            raise ValueError("anchor canonicalization changed")
        if core.get("subject_kind") != SUBJECT_KIND_FORENSIC_PACKAGE:
            raise ValueError("anchor subject kind changed")
        if core.get("subject_identity") != subject_identity:
            raise ValueError("anchor subject identity does not match package")
        if core.get("mechanism") != "git-commit":
            raise ValueError("anchor mechanism is unsupported")
        mechanism = "git-commit"
        object_format = core.get("git_object_format")
        if object_format not in {"sha1", "sha256"}:
            raise ValueError("anchor Git object format is invalid")
        expected_oid_len = 40 if object_format == "sha1" else 64
        commit_value = core.get("commit_oid")
        if (
            not isinstance(commit_value, str)
            or len(commit_value) != expected_oid_len
            or any(c not in "0123456789abcdef" for c in commit_value)
        ):
            raise ValueError("anchor commit OID is invalid")
        commit_oid = commit_value
        anchor_path = validate_git_anchor_path(str(core.get("path")))
        payload = git_anchor_payload(subject_identity)
        payload_identity = core.get("payload_content_identity")
        require_sha256_identity(
            payload_identity,
            label="anchor payload content identity",
        )
        if payload_identity != sha256_content_identity(payload):
            raise ValueError("anchor payload content identity mismatch")
        hint = core.get("repository_hint")
        if hint is not None and (
            not isinstance(hint, str) or not hint
        ):
            raise ValueError("anchor repository_hint is invalid")
        claimed = record.get("anchor_identity")
        require_sha256_identity(claimed, label="anchor identity")
        if record.get("self_hash_exclusion") != "anchor_identity":
            raise ValueError("anchor self_hash_exclusion changed")
        if external_anchor_identity(core) != claimed:
            raise ValueError(
                "anchor identity does not match canonical anchor core"
            )
        anchor_identity_value = str(claimed)
    except Exception as exc:
        return AnchorVerificationReport(
            "FAILED",
            subject_identity,
            anchor_identity_value,
            mechanism,
            commit_oid,
            anchor_path,
            (str(exc),),
        )

    if git_repo is None:
        return AnchorVerificationReport(
            "NOT_ATTEMPTED",
            subject_identity,
            anchor_identity_value,
            mechanism,
            commit_oid,
            anchor_path,
            ("Git object database was not supplied",),
        )
    git = _tool("git")
    if git is None:
        return AnchorVerificationReport(
            "UNAVAILABLE",
            subject_identity,
            anchor_identity_value,
            mechanism,
            commit_oid,
            anchor_path,
            ("git is unavailable",),
        )
    try:
        repo = _safe_git_repo(git_repo)
        fmt = _git(git, repo, ["rev-parse", "--show-object-format"])
        if fmt.returncode != 0:
            raise ValueError(
                fmt.stderr.strip()
                or "cannot determine Git object format"
            )
        if fmt.stdout.strip() != object_format:
            raise ValueError("Git object format does not match anchor record")
        exists = _git(
            git,
            repo,
            ["cat-file", "-e", f"{commit_oid}^{{commit}}"],
        )
        if exists.returncode != 0:
            raise ValueError(
                exists.stderr.strip()
                or "anchored Git commit is unavailable"
            )
        show = _git(
            git,
            repo,
            ["show", f"{commit_oid}:{anchor_path}"],
            text=False,
        )
        if show.returncode != 0:
            detail = bytes(show.stderr).decode(
                "utf-8", errors="replace"
            ).strip()
            raise ValueError(
                detail or "anchored path is absent from Git commit"
            )
        if bytes(show.stdout) != payload:
            raise ValueError(
                "Git commit path does not contain the exact anchor payload"
            )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return AnchorVerificationReport(
            "FAILED",
            subject_identity,
            anchor_identity_value,
            mechanism,
            commit_oid,
            anchor_path,
            (str(exc),),
        )
    return AnchorVerificationReport(
        "VERIFIED",
        subject_identity,
        anchor_identity_value,
        mechanism,
        commit_oid,
        anchor_path,
        (),
    )


def verify_assurance(
    package_dir: Path | str,
    *,
    signature_record: Path | str | None = None,
    anchor_record: Path | str | None = None,
    git_repo: Path | str | None = None,
) -> AssuranceVerificationReport:
    package = verify_forensic_package(package_dir)
    integrity = "VERIFIED" if package.integrity_verified else "FAILED"

    signature_report = (
        None
        if signature_record is None
        else verify_signature_record(package_dir, signature_record)
    )
    signature = (
        "NOT_PRESENT"
        if signature_report is None
        else signature_report.status
    )

    anchor_report = (
        None
        if anchor_record is None
        else verify_git_anchor_record(
            package_dir,
            anchor_record,
            git_repo=git_repo,
        )
    )
    external_anchor = (
        "NOT_PRESENT" if anchor_report is None else anchor_report.status
    )

    return AssuranceVerificationReport(
        integrity=integrity,
        signature=signature,
        external_anchor=external_anchor,
        package=package.to_dict(),
        signature_report=(
            None
            if signature_report is None
            else signature_report.to_dict()
        ),
        anchor_report=(
            None if anchor_report is None else anchor_report.to_dict()
        ),
    )
