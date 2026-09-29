"""OpenSSH signing helpers for Phase 15 transfer records."""
from __future__ import annotations

import os
from pathlib import Path
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
    ed25519_key_fingerprint,
    normalize_ed25519_public_key,
    sha256_content_identity,
)
from provenance_trust.records import (
    _public_key_from_signing_key,
    _require_tool,
    _safe_key_path,
)

from .model import (
    SIGNATURE_NAMESPACE,
    TRANSFER_SIGNATURE_SCHEMA,
    transfer_signature_core,
    transfer_signature_identity,
)


class TransferSignatureError(RuntimeError):
    """Raised when a transfer signature cannot be created or verified."""


def sign_transfer_envelope(
    envelope: dict[str, Any],
    *,
    role: str,
    subject_kind: str,
    subject_identity: str,
    key_file: Path | str,
) -> dict[str, Any]:
    data = canonical_json_bytes(envelope)
    ssh_keygen = _require_tool("ssh-keygen")
    key_path = _safe_key_path(key_file)
    public_key = _public_key_from_signing_key(ssh_keygen, key_path)

    with tempfile.TemporaryDirectory(prefix="provenance-transfer-sign-") as tmp:
        root = Path(tmp)
        target = root / "record.json"
        target.write_bytes(data)
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
        if completed.returncode != 0:
            raise TransferSignatureError(
                completed.stderr.strip() or "transfer signing failed"
            )
        signature_path = root / "record.json.sig"
        signature = signature_path.read_text(encoding="ascii")

        allowed = root / "allowed_signers"
        allowed.write_text(
            f"provenance-transfer {public_key}\n",
            encoding="ascii",
        )
        verified = subprocess.run(
            [
                ssh_keygen,
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                "provenance-transfer",
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
        if verified.returncode != 0:
            detail = verified.stderr.decode(
                "utf-8", errors="replace"
            ).strip()
            raise TransferSignatureError(
                detail or "new transfer signature failed self-verification"
            )

    core = transfer_signature_core(
        role=role,
        subject_kind=subject_kind,
        subject_identity=subject_identity,
        signed_bytes=data,
        public_key=public_key,
        signature=signature,
    )
    return {
        "core": core,
        "signature_identity": transfer_signature_identity(core),
        "self_hash_exclusion": "signature_identity",
    }


def verify_transfer_signature(
    envelope: dict[str, Any],
    signature_record: dict[str, Any],
    *,
    expected_role: str,
    expected_subject_kind: str,
    expected_subject_identity: str,
) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    try:
        if set(signature_record) != {
            "core",
            "signature_identity",
            "self_hash_exclusion",
        }:
            raise ValueError("transfer signature envelope keys changed")
        core = signature_record.get("core")
        if not isinstance(core, dict) or set(core) != {
            "schema",
            "canonicalization",
            "role",
            "subject_kind",
            "subject_identity",
            "signed_content_identity",
            "algorithm",
            "namespace",
            "public_key",
            "key_fingerprint",
            "signature",
        }:
            raise ValueError("transfer signature core keys changed")
        if core.get("schema") != TRANSFER_SIGNATURE_SCHEMA:
            raise ValueError("transfer signature schema changed")
        if core.get("canonicalization") != CANONICALIZATION_ID:
            raise ValueError("transfer signature canonicalization changed")
        if core.get("role") != expected_role:
            raise ValueError("transfer signature role mismatch")
        if core.get("subject_kind") != expected_subject_kind:
            raise ValueError("transfer signature subject kind mismatch")
        if core.get("subject_identity") != expected_subject_identity:
            raise ValueError("transfer signature subject identity mismatch")
        if core.get("algorithm") != "ssh-ed25519":
            raise ValueError("transfer signature algorithm is unsupported")
        if core.get("namespace") != SIGNATURE_NAMESPACE:
            raise ValueError("transfer signature namespace changed")

        data = canonical_json_bytes(envelope)
        expected_content = sha256_content_identity(data)
        if core.get("signed_content_identity") != expected_content:
            raise ValueError("transfer signature signed-content identity mismatch")

        public_value = core.get("public_key")
        normalized = normalize_ed25519_public_key(str(public_value))
        if public_value != normalized:
            raise ValueError("transfer signature public key is not normalized")
        fingerprint = ed25519_key_fingerprint(normalized)
        if core.get("key_fingerprint") != fingerprint:
            raise ValueError("transfer signature key fingerprint mismatch")

        signature = core.get("signature")
        if (
            not isinstance(signature, str)
            or not signature.startswith("-----BEGIN SSH SIGNATURE-----")
            or not signature.rstrip().endswith("-----END SSH SIGNATURE-----")
        ):
            raise ValueError("transfer signature armor is invalid")
        signature.encode("ascii")

        claimed = signature_record.get("signature_identity")
        require_sha256_identity(claimed, label="transfer signature identity")
        if signature_record.get("self_hash_exclusion") != "signature_identity":
            raise ValueError("transfer signature self-hash exclusion changed")
        if transfer_signature_identity(core) != claimed:
            raise ValueError("transfer signature identity mismatch")
    except Exception as exc:
        return False, (str(exc),)

    ssh_keygen = _require_tool("ssh-keygen")
    with tempfile.TemporaryDirectory(prefix="provenance-transfer-verify-") as tmp:
        root = Path(tmp)
        allowed = root / "allowed_signers"
        sig = root / "signature"
        allowed.write_text(
            f"provenance-transfer {normalized}\n",
            encoding="ascii",
        )
        sig.write_text(signature, encoding="ascii")
        completed = subprocess.run(
            [
                ssh_keygen,
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                "provenance-transfer",
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(sig),
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
    if completed.returncode != 0:
        detail = completed.stderr.decode(
            "utf-8", errors="replace"
        ).strip()
        return False, (detail or "transfer signature verification failed",)
    return True, ()
