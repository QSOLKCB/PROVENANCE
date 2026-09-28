from __future__ import annotations

import unittest

from provenance_core import (
    ArtifactRecord,
    CanonicalizationError,
    CollectionStatus,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    IdentityError,
    ManifestCore,
    ManifestEnvelope,
    Relationship,
    canonical_json_bytes,
    domain_identity,
    parse_canonical_json_bytes,
    sha256_identity,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_is_canonical(self) -> None:
        left = {"b": 2, "a": [3, {"z": None, "x": True}]}
        right = {"a": [3, {"x": True, "z": None}], "b": 2}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))
        self.assertEqual(
            canonical_json_bytes(left),
            b'{"a":[3,{"x":true,"z":null}],"b":2}\n',
        )

    def test_noncanonical_input_is_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json_bytes(b'{"b":2, "a":1}\n')

    def test_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "duplicate"):
            parse_canonical_json_bytes(b'{"a":1,"a":2}\n')

    def test_out_of_range_integer_is_rejected(self) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "safe-integer"):
            canonical_json_bytes({"n": 9_007_199_254_740_992})

    def test_bom_and_float_are_rejected(self) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "BOM"):
            parse_canonical_json_bytes(b"\xef\xbb\xbf{}\n")
        with self.assertRaisesRegex(CanonicalizationError, "floating-point"):
            canonical_json_bytes({"temperature": 0.7})


class IdentityTests(unittest.TestCase):
    def test_artifact_identity_is_exact_sha256(self) -> None:
        self.assertEqual(
            sha256_identity(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_domain_identity_requires_explicit_nul_terminated_domain(self) -> None:
        with self.assertRaises(IdentityError):
            domain_identity(b"PROVENANCE/TEST/v1", {"x": 1})


class RecordTests(unittest.TestCase):
    def test_artifact_record_binds_exact_bytes(self) -> None:
        record = ArtifactRecord.from_bytes(b"prompt", media_type="text/plain")
        self.assertEqual(record.byte_count, 6)
        self.assertEqual(record.content_identity, sha256_identity(b"prompt"))
        self.assertEqual(record.to_dict()["retention"], "CONTENT_RETAINED")

    def test_event_identity_changes_when_core_changes(self) -> None:
        artifact = ArtifactRecord.from_bytes(b"response")
        first = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="response",
                outputs=(artifact.content_identity,),
            )
        )
        second = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.DECLARED,
                actor="adapter:test",
                operation="response",
                outputs=(artifact.content_identity,),
            )
        )
        self.assertNotEqual(first.event_identity, second.event_identity)

    def test_event_envelope_rejects_identity_substitution(self) -> None:
        artifact = ArtifactRecord.from_bytes(b"x")
        core = EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="adapter:test",
            operation="capture",
            outputs=(artifact.content_identity,),
            collection_status=CollectionStatus.RECORDED,
        )
        valid = EventEnvelope.seal(core)
        different = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="different",
                outputs=(artifact.content_identity,),
            )
        )
        self.assertNotEqual(valid.event_identity, different.event_identity)
        with self.assertRaisesRegex(ValueError, "does not match"):
            EventEnvelope(core=core, event_identity=different.event_identity)

    def test_relationship_target_must_be_a_sha256_identity(self) -> None:
        with self.assertRaises(IdentityError):
            Relationship(kind="derived_from", target="not-an-identity")

    def test_manifest_membership_is_order_independent_but_exact(self) -> None:
        a = ArtifactRecord.from_bytes(b"a").content_identity
        b = ArtifactRecord.from_bytes(b"b").content_identity
        event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="capture",
                inputs=(a,),
                outputs=(b,),
            )
        )
        left = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[b, a], events=[event.event_identity])
        )
        right = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[a, b, a], events=[event.event_identity])
        )
        self.assertEqual(left.manifest_identity, right.manifest_identity)

        changed = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[a], events=[event.event_identity])
        )
        self.assertNotEqual(left.manifest_identity, changed.manifest_identity)

    def test_self_hash_fields_are_outside_hashed_core(self) -> None:
        artifact = ArtifactRecord.from_bytes(b"evidence")
        event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="capture",
                outputs=(artifact.content_identity,),
            )
        )
        payload = event.to_dict()
        self.assertEqual(payload["self_hash_exclusion"], "event_identity")
        self.assertNotIn("event_identity", payload["core"])


if __name__ == "__main__":
    unittest.main()
