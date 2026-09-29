"""Phase 12 detached signature and Git-anchor record producers."""
from __future__ import annotations

import os
from pathlib import Path
import re
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
from provenance_verify.package import (
    FORENSIC_PACKAGE_SCHEMA,
    forensic_package_identity,
    verify_forensic_package,
)
from .model import (
    SIGNATURE_NAMESPACE,
    ed25519_key_fingerprint,
    external_anchor_core,
    external_anchor_identity,
    git_anchor_payload,
    normalize_ed25519_public_key,
    sha256_content_identity,
    signature_core,
    signature_record_identity,
    validate_git_anchor_path,
)


_CHUNK_SIZE = 1024 * 1024
_STRUCTURED_LIMIT = 16 * 1024 * 1024
_SAFE_GIT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


class TrustRecordError(RuntimeError):
    """Raised when an optional Phase 12 trust record cannot be produced safely."""


def _directory_flags() -> int:
    missing = [
        name
        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
        if not hasattr(os, name)
    ]
    if os.open not in os.supports_dir_fd:
        missing.append("dir_fd support for os.open")
    if os.unlink not in os.supports_dir_fd:
        missing.append("dir_fd support for os.unlink")
    if missing:
        raise TrustRecordError(
            "trust records require descriptor-relative filesystem support: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_read_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0)
    )


def _read_all(fd: int, *, max_bytes: int | None = None) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise TrustRecordError("structured trust input exceeds size limit")
        chunks.append(chunk)


def _directory_identity(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise TrustRecordError("expected directory descriptor")
    return info.st_dev, info.st_ino


def _path_still_matches(
    path: Path,
    expected_identity: tuple[int, int],
) -> bool:
    try:
        fd = os.open(path, _directory_flags())
    except OSError:
        return False
    try:
        return _directory_identity(fd) == expected_identity
    finally:
        os.close(fd)


def _read_package_json(package_dir: Path | str) -> tuple[bytes, str]:
    supplied = Path(package_dir).expanduser()
    if supplied.is_symlink():
        raise TrustRecordError("package root must not be a symbolic link")
    try:
        root_fd = os.open(supplied, _directory_flags())
    except OSError as exc:
        raise TrustRecordError(
            f"package root cannot be opened safely: {exc}"
        ) from exc
    try:
        try:
            fd = os.open("package.json", _file_read_flags(), dir_fd=root_fd)
        except OSError as exc:
            raise TrustRecordError(
                f"package.json cannot be opened safely: {exc}"
            ) from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise TrustRecordError("package.json must be a regular file")
            raw = _read_all(fd, max_bytes=_STRUCTURED_LIMIT)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)

    try:
        envelope = parse_canonical_json_bytes(raw)
    except Exception as exc:
        raise TrustRecordError(
            f"package.json is not canonical PROVENANCE JSON: {exc}"
        ) from exc
    if not isinstance(envelope, dict) or set(envelope) != {
        "core",
        "package_identity",
        "self_hash_exclusion",
    }:
        raise TrustRecordError("package.json envelope keys changed")
    core = envelope.get("core")
    if not isinstance(core, dict):
        raise TrustRecordError("package.json core must be an object")
    if core.get("schema") != FORENSIC_PACKAGE_SCHEMA:
        raise TrustRecordError("package.json schema changed")
    claimed = envelope.get("package_identity")
    try:
        require_sha256_identity(claimed, label="package identity")
    except (TypeError, ValueError) as exc:
        raise TrustRecordError(str(exc)) from exc
    if envelope.get("self_hash_exclusion") != "package_identity":
        raise TrustRecordError("package.json self_hash_exclusion changed")
    expected = forensic_package_identity(core)
    if claimed != expected:
        raise TrustRecordError(
            "package.json identity does not match canonical package core"
        )
    return raw, str(claimed)


def _verified_package_subject(
    package_dir: Path | str,
) -> tuple[bytes, str]:
    report = verify_forensic_package(package_dir)
    if not report.integrity_verified or report.package_identity is None:
        raise TrustRecordError(
            "forensic package failed integrity verification before trust record creation: "
            + "; ".join(report.errors)
        )
    raw, identity = _read_package_json(package_dir)
    if identity != report.package_identity:
        raise TrustRecordError(
            "package identity changed between verification and trust capture"
        )
    second = verify_forensic_package(package_dir)
    if (
        not second.integrity_verified
        or second.package_identity != identity
    ):
        raise TrustRecordError(
            "forensic package changed during trust record creation"
        )
    return raw, identity


def _require_tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise TrustRecordError(f"required optional tool is unavailable: {name}")
    return value


def _safe_key_path(key_file: Path | str) -> Path:
    path = Path(key_file).expanduser()
    if path.is_symlink():
        raise TrustRecordError("SSH signing key path must not be a symlink")
    try:
        info = path.stat()
    except OSError as exc:
        raise TrustRecordError(
            f"SSH signing key cannot be inspected: {exc}"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise TrustRecordError("SSH signing key must be a regular file")
    return path.resolve(strict=True)


def _public_key_from_signing_key(
    ssh_keygen: str,
    key_file: Path,
) -> str:
    try:
        first = key_file.read_text(
            encoding="utf-8",
            errors="strict",
        ).splitlines()[0].strip()
    except (UnicodeDecodeError, IndexError, OSError):
        first = ""
    if first.startswith("ssh-ed25519 "):
        return normalize_ed25519_public_key(first)

    try:
        completed = subprocess.run(
            [ssh_keygen, "-y", "-f", str(key_file)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TrustRecordError(
            f"ssh-keygen could not derive the public key: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "ssh-keygen -y failed"
        raise TrustRecordError(detail)
    try:
        return normalize_ed25519_public_key(completed.stdout)
    except ValueError as exc:
        raise TrustRecordError(str(exc)) from exc


def create_signature_record(
    package_dir: Path | str,
    key_file: Path | str,
) -> dict[str, Any]:
    """Sign exact package.json bytes with an OpenSSH Ed25519 SSHSIG."""

    package_bytes, package_identity = _verified_package_subject(package_dir)
    ssh_keygen = _require_tool("ssh-keygen")
    key_path = _safe_key_path(key_file)
    public_key = _public_key_from_signing_key(ssh_keygen, key_path)

    with tempfile.TemporaryDirectory(prefix="provenance-sign-") as tmp:
        root = Path(tmp)
        target = root / "package.json"
        target.write_bytes(package_bytes)
        try:
            completed = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "sign",
                    "-f",
                    str(key_path),
                    "-n",
                    SIGNATURE_NAMESPACE,
                    target.name,
                ],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TrustRecordError(
                f"ssh-keygen signing failed to execute: {exc}"
            ) from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "ssh-keygen signing failed"
            raise TrustRecordError(detail)
        signature_path = root / "package.json.sig"
        try:
            signature = signature_path.read_text(encoding="ascii")
        except OSError as exc:
            raise TrustRecordError(
                f"ssh-keygen did not produce a signature: {exc}"
            ) from exc

    core = signature_core(
        subject_identity=package_identity,
        signed_content_identity=sha256_content_identity(package_bytes),
        public_key=public_key,
        signature=signature,
    )
    return {
        "core": core,
        "signature_identity": signature_record_identity(core),
        "self_hash_exclusion": "signature_identity",
    }


def _safe_git_ref(value: str) -> str:
    if (
        not isinstance(value, str)
        or _SAFE_GIT_REF.fullmatch(value) is None
        or ".." in value
        or "//" in value
        or "@{" in value
    ):
        raise TrustRecordError(
            "Git anchor commit/ref contains unsupported revision syntax"
        )
    return value


def _git(
    git: str,
    repo: Path,
    args: list[str],
    *,
    text: bool = True,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TrustRecordError(f"Git anchor command failed: {exc}") from exc


def _safe_git_repo(repo_dir: Path | str) -> Path:
    path = Path(repo_dir).expanduser()
    if path.is_symlink():
        raise TrustRecordError("Git anchor repository root must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise TrustRecordError(
            f"Git anchor repository cannot be resolved: {exc}"
        ) from exc
    if not resolved.is_dir():
        raise TrustRecordError("Git anchor repository must be a directory")
    return resolved


def create_git_anchor_record(
    package_dir: Path | str,
    git_repo: Path | str,
    commit_ref: str,
    path: str,
    *,
    repository_hint: str | None = None,
) -> dict[str, Any]:
    """Bind a package identity to exact bytes already present in a Git commit."""

    _package_bytes, package_identity = _verified_package_subject(package_dir)
    anchor_path = validate_git_anchor_path(path)
    ref = _safe_git_ref(commit_ref)
    repo = _safe_git_repo(git_repo)
    git = _require_tool("git")

    object_format_result = _git(
        git,
        repo,
        ["rev-parse", "--show-object-format"],
    )
    if object_format_result.returncode != 0:
        raise TrustRecordError(
            object_format_result.stderr.strip()
            or "cannot determine Git object format"
        )
    object_format = object_format_result.stdout.strip()
    if object_format not in {"sha1", "sha256"}:
        raise TrustRecordError(
            f"unsupported Git object format: {object_format!r}"
        )

    commit_result = _git(
        git,
        repo,
        ["rev-parse", "--verify", f"{ref}^{{commit}}"],
    )
    if commit_result.returncode != 0:
        raise TrustRecordError(
            commit_result.stderr.strip()
            or "Git commit/ref cannot be resolved"
        )
    commit_oid = commit_result.stdout.strip().lower()

    tree_entry = _git(
        git,
        repo,
        ["ls-tree", commit_oid, "--", anchor_path],
    )
    if tree_entry.returncode != 0:
        raise TrustRecordError(
            tree_entry.stderr.strip()
            or "cannot inspect Git anchor tree entry"
        )
    entry = tree_entry.stdout.rstrip("\n")
    if "\n" in entry or "\t" not in entry:
        raise TrustRecordError(
            "Git anchor path does not resolve to exactly one tree entry"
        )
    metadata, observed_path = entry.split("\t", 1)
    fields = metadata.split()
    if (
        observed_path != anchor_path
        or len(fields) != 3
        or fields[0] not in {"100644", "100755"}
        or fields[1] != "blob"
    ):
        raise TrustRecordError(
            "Git anchor path must be a regular committed blob"
        )

    payload = git_anchor_payload(package_identity)
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
        raise TrustRecordError(
            detail or "Git anchor path is absent from the commit"
        )
    observed = bytes(show.stdout)
    if observed != payload:
        raise TrustRecordError(
            "Git commit path does not contain the exact PROVENANCE anchor payload"
        )

    core = external_anchor_core(
        subject_identity=package_identity,
        commit_oid=commit_oid,
        git_object_format=object_format,
        path=anchor_path,
        payload_content_identity=sha256_content_identity(payload),
        repository_hint=repository_hint,
    )
    return {
        "core": core,
        "anchor_identity": external_anchor_identity(core),
        "self_hash_exclusion": "anchor_identity",
    }


def write_git_anchor_payload(
    package_dir: Path | str,
    destination: Path | str,
) -> Path:
    """Publish the exact canonical payload that a Git commit must contain."""

    _package_bytes, package_identity = _verified_package_subject(package_dir)
    data = git_anchor_payload(package_identity)
    return _write_new_file(destination, data, label="Git anchor payload")


def _write_new_file(
    destination: Path | str,
    data: bytes,
    *,
    label: str,
) -> Path:
    supplied = Path(destination).expanduser()
    if supplied.name in {"", ".", ".."}:
        raise TrustRecordError(f"{label} destination name is invalid")
    if supplied.exists() or supplied.is_symlink():
        raise TrustRecordError(f"{label} destination must not already exist")
    if supplied.parent.is_symlink():
        raise TrustRecordError(
            f"{label} destination parent must not be a symlink"
        )
    try:
        parent = supplied.parent.resolve(strict=True)
    except OSError as exc:
        raise TrustRecordError(
            f"{label} destination parent cannot be resolved: {exc}"
        ) from exc

    parent_fd = os.open(parent, _directory_flags())
    parent_identity = _directory_identity(parent_fd)
    created = False
    try:
        try:
            fd = os.open(
                supplied.name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
        except OSError as exc:
            raise TrustRecordError(
                f"{label} cannot be created safely: {exc}"
            ) from exc
        try:
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:
                    raise TrustRecordError(f"short {label} write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        if not _path_still_matches(parent, parent_identity):
            raise TrustRecordError(
                f"{label} destination parent changed during publication"
            )
        return parent / supplied.name
    except Exception:
        if created:
            try:
                os.unlink(supplied.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_fd)


def write_trust_record(
    destination: Path | str,
    record: dict[str, Any],
) -> Path:
    """Publish one canonical detached trust record without overwrite."""

    data = canonical_json_bytes(record)
    return _write_new_file(
        destination,
        data,
        label="trust record",
    )
