from __future__ import annotations

import unittest

from provenance_core import (
    MAX_SAFE_INTEGER,
    ArtifactRecord,
    CanonicalizationError,
    CollectionStatus,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    IdentityError,
    ManifestArtifact,
    ManifestCore,
    ManifestEnvelope,
    Relationship,
    RetentionState,
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
            canonical_json_bytes({"n": MAX_SAFE_INTEGER + 1})

    def test_lone_surrogate_is_rejected_as_canonicalization_error(self) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "invalid Unicode"):
            canonical_json_bytes({"text": "\ud800"})
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json_bytes(b'"\\ud800"\n')

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

    def test_fixed_v1_identity_fixtures(self) -> None:
        artifact = ArtifactRecord.from_bytes(b"fixture", media_type="text/plain")
        self.assertEqual(
            artifact.content_identity,
            "sha256:f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
        )
        self.assertEqual(
            artifact.record_identity,
            "sha256:c5329634201793d2ecf76f3667da28164fe3449db7c2afd2979e5daf9273ada6",
        )

        event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="capture",
                outputs=(artifact.content_identity,),
            )
        )
        self.assertEqual(
            event.event_identity,
            "sha256:409e540e19f7952d90d6d866a7da623808d5c4acbba18f1b839f530d4cff6401",
        )

        manifest = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[artifact], events=[event.event_identity])
        )
        self.assertEqual(
            manifest.manifest_identity,
            "sha256:8f61ba370addc2f1a1004598d07aac41c819193586c949e9ebb3b3e6cbbc67d1",
        )


class RecordTests(unittest.TestCase):
    def test_from_bytes_defaults_to_digest_only(self) -> None:
        record = ArtifactRecord.from_bytes(b"prompt", media_type="text/plain")
        self.assertEqual(record.byte_count, 6)
        self.assertEqual(record.content_identity, sha256_identity(b"prompt"))
        self.assertEqual(record.retention, RetentionState.DIGEST_ONLY)

        retained = ArtifactRecord.from_bytes(
            b"prompt",
            media_type="text/plain",
            retention=RetentionState.CONTENT_RETAINED,
        )
        self.assertEqual(retained.retention, RetentionState.CONTENT_RETAINED)

    def test_artifact_record_rejects_noncanonical_byte_count(self) -> None:
        digest = sha256_identity(b"x")
        with self.assertRaisesRegex(ValueError, "canonical safe integer"):
            ArtifactRecord(
                content_identity=digest,
                byte_count=MAX_SAFE_INTEGER + 1,
                media_type="application/octet-stream",
            )

    def test_artifact_record_identity_binds_metadata(self) -> None:
        content_identity = sha256_identity(b"same bytes")
        plain = ArtifactRecord(
            content_identity=content_identity,
            byte_count=10,
            media_type="text/plain",
            retention=RetentionState.DIGEST_ONLY,
        )
        binary = ArtifactRecord(
            content_identity=content_identity,
            byte_count=10,
            media_type="application/octet-stream",
            retention=RetentionState.DIGEST_ONLY,
        )
        retained = ArtifactRecord(
            content_identity=content_identity,
            byte_count=10,
            media_type="text/plain",
            retention=RetentionState.CONTENT_RETAINED,
        )
        self.assertEqual(plain.content_identity, binary.content_identity)
        self.assertNotEqual(plain.record_identity, binary.record_identity)
        self.assertNotEqual(plain.record_identity, retained.record_identity)

        first_manifest = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[plain])
        )
        second_manifest = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[binary])
        )
        self.assertNotEqual(
            first_manifest.manifest_identity, second_manifest.manifest_identity
        )

    def test_event_core_rejects_mutable_collections_and_untyped_enums(self) -> None:
        artifact = ArtifactRecord.from_bytes(b"x")
        with self.assertRaisesRegex(TypeError, "tuples"):
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="capture",
                inputs=[artifact.content_identity],  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(TypeError, "EvidenceClass"):
            EventCore(
                evidence_class="OBSERVED",  # type: ignore[arg-type]
                actor="adapter:test",
                operation="capture",
            )

    def test_derived_event_requires_source(self) -> None:
        with self.assertRaisesRegex(ValueError, "DERIVED event"):
            EventCore(
                evidence_class=EvidenceClass.DERIVED,
                actor="analysis:test",
                operation="calculation",
            )

        source = ArtifactRecord.from_bytes(b"source").content_identity
        by_input = EventCore(
            evidence_class=EvidenceClass.DERIVED,
            actor="analysis:test",
            operation="calculation",
            inputs=(source,),
        )
        self.assertEqual(by_input.inputs, (source,))

        by_relationship = EventCore(
            evidence_class=EvidenceClass.DERIVED,
            actor="analysis:test",
            operation="calculation",
            relationships=(Relationship("derived_from", source),),
        )
        self.assertEqual(by_relationship.relationships[0].target, source)

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
        a = ArtifactRecord.from_bytes(b"a")
        b = ArtifactRecord.from_bytes(b"b")
        event = EventEnvelope.seal(
            EventCore(
                evidence_class=EvidenceClass.OBSERVED,
                actor="adapter:test",
                operation="capture",
                inputs=(a.content_identity,),
                outputs=(b.content_identity,),
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

    def test_manifest_encodes_missing_artifact_explicitly(self) -> None:
        missing_id = sha256_identity(b"lost bytes")
        missing = ManifestArtifact.missing(missing_id)
        opened = ManifestEnvelope.seal(
            ManifestCore.build(artifacts=[missing], scope="open")
        )
        self.assertEqual(
            opened.core.to_dict()["artifacts"],
            [
                {
                    "content_identity": missing_id,
                    "record_identity": None,
                    "retention": "MISSING",
                }
            ],
        )
        with self.assertRaisesRegex(ValueError, "closed manifest"):
            ManifestCore.build(artifacts=[missing], scope="closed")

    def test_manifest_rejects_conflicting_metadata_for_same_content(self) -> None:
        content_identity = sha256_identity(b"same")
        first = ArtifactRecord(
            content_identity=content_identity,
            byte_count=4,
            media_type="text/plain",
        )
        second = ArtifactRecord(
            content_identity=content_identity,
            byte_count=4,
            media_type="application/octet-stream",
        )
        with self.assertRaisesRegex(ValueError, "conflicting metadata"):
            ManifestCore.build(artifacts=[first, second])

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
