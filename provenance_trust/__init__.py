"""Optional Phase 12 authenticity mechanisms for PROVENANCE."""

from .model import (
    EXTERNAL_ANCHOR_SCHEMA,
    GIT_ANCHOR_PAYLOAD_SCHEMA,
    SIGNATURE_NAMESPACE,
    SIGNATURE_SCHEMA,
    SUBJECT_KIND_FORENSIC_PACKAGE,
    ed25519_key_fingerprint,
    external_anchor_identity,
    git_anchor_payload,
    signature_record_identity,
)
from .records import (
    TrustRecordError,
    create_git_anchor_record,
    create_signature_record,
    write_trust_record,
)

__all__ = [
    "EXTERNAL_ANCHOR_SCHEMA",
    "GIT_ANCHOR_PAYLOAD_SCHEMA",
    "SIGNATURE_NAMESPACE",
    "SIGNATURE_SCHEMA",
    "SUBJECT_KIND_FORENSIC_PACKAGE",
    "TrustRecordError",
    "create_git_anchor_record",
    "create_signature_record",
    "ed25519_key_fingerprint",
    "external_anchor_identity",
    "git_anchor_payload",
    "signature_record_identity",
    "write_trust_record",
]
