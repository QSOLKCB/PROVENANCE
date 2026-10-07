from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from provenance_core import (
    EvidenceClass, EventCore, EventEnvelope, canonical_json_bytes,
    parse_canonical_json_bytes, sha256_identity,
)
from provenance_research import seal_research_manifest, verify_research_manifest
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "openai_math"
PINNED_IDENTITY = "sha256:8daa4ec906c5c6175c7c9d92c7f04887a2940466ca44ee40c89bdb4518ffadaa"


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.raw = (FIXTURE / "research-manifest.json").read_bytes()
        self.envelope = parse_canonical_json_bytes(self.raw)
        self.core = self.envelope["core"]
        self.contents = {}
        for name in ("LICENSE", "scope.md", "Heisenberg.lean", "Heisenberg.json", "citation.md"):
            data = (FIXTURE / "upstream" / name).read_bytes()
            self.contents[sha256_identity(data)] = data

    def test_pinned_fixture_and_independent_domain_digest(self):
        calculated = "sha256:" + hashlib.sha256(
            b"PROVENANCE/RESEARCH-MANIFEST/v1\0" + canonical_json_bytes(self.core)
        ).hexdigest()
        self.assertEqual(calculated, PINNED_IDENTITY)
        self.assertEqual(self.envelope["research_identity"], PINNED_IDENTITY)
        self.assertEqual(seal_research_manifest(self.core), self.raw)
        report = verify_research_manifest(self.raw, self.contents)
        self.assertTrue(report["byte_integrity_verified"], report)
        self.assertEqual(len(report["checked_artifacts"]), 5)
        for key in ("upstream_membership", "mathematical_validity", "license_compliance"):
            self.assertEqual(report[key], "not_checked")
        self.assertEqual(self.core["claims"][0]["verification_receipts"], [])

    def test_metadata_and_self_hash_tampering(self):
        for mutate in (
            lambda e: e["core"]["source"].update(commit="f" * 40),
            lambda e: e.update(research_identity="sha256:" + "0" * 64),
            lambda e: e.update(self_hash_exclusion="core"),
        ):
            with self.subTest(mutate=mutate):
                envelope = copy.deepcopy(self.envelope)
                mutate(envelope)
                report = verify_research_manifest(canonical_json_bytes(envelope), self.contents)
                self.assertFalse(report["byte_integrity_verified"], report)

    def test_missing_and_wrong_bytes_never_verify(self):
        digest = self.core["artifacts"][1]["content_identity"]
        contents = self.contents.copy()
        del contents[digest]
        report = verify_research_manifest(self.raw, contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertEqual(report["missing_artifacts"], ["scope"])
        contents[digest] = b"changed"
        report = verify_research_manifest(self.raw, contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertIn("artifact bytes mismatch: scope", report["errors"])

    def test_strict_schema_and_reference_contract(self):
        mutations = [
            lambda c: c.update(schema="provenance.research-manifest.v2"),
            lambda c: c.update(evidence_class="OBSERVED"),
            lambda c: c.update(unknown=True),
            lambda c: c["source"].update(commit="main"),
            lambda c: c["artifacts"][0].update(byte_count=True),
            lambda c: c["artifacts"][0].update(path="../LICENSE"),
            lambda c: c["artifacts"].append(c["artifacts"][0].copy()),
            lambda c: c["uses"][0].update(upstream="missing"),
            lambda c: c["uses"][0].update(local="scope"),
            lambda c: c["claims"][0].update(scope_artifact="citation"),
            lambda c: c["claims"][0].update(declarations=[]),
            lambda c: c["claims"][0].update(verification_receipts=["scope"]),
            lambda c: c["attribution"].update(license_artifact="scope"),
            lambda c: c["attribution"].update(notice_status="present"),
            lambda c: c["attribution"].update(citations=[]),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                core = copy.deepcopy(self.core)
                mutate(core)
                with self.assertRaises(ValueError):
                    seal_research_manifest(core)

    def test_duplicate_keys_and_noncanonical_json_fail_closed(self):
        for data in (
            self.raw.replace(b'"evidence_class":"DECLARED"', b'"evidence_class":"DECLARED","evidence_class":"OBSERVED"'),
            b" " + self.raw,
            b"\xef\xbb\xbf" + self.raw,
            b"[]\n",
        ):
            with self.subTest(data=data[:20]):
                self.assertFalse(verify_research_manifest(data, self.contents)["byte_integrity_verified"])

    def test_reuse_modes_and_modification_notices(self):
        local = self.core["artifacts"][1].copy()
        local.update(key="local", path="docs/scope.md", origin="local", role="local")
        self.core["artifacts"].append(local)
        use = self.core["uses"][0]
        use.update(local="local", mode="copied")
        self.assertTrue(verify_research_manifest(seal_research_manifest(self.core), self.contents)["byte_integrity_verified"])
        local["content_identity"] = sha256_identity(b"modified scope")
        local["byte_count"] = len(b"modified scope")
        with self.assertRaises(ValueError):
            seal_research_manifest(self.core)
        for mode in ("adaptation", "derived"):
            use["mode"] = mode
            with self.assertRaises(ValueError):
                seal_research_manifest(self.core)
            use["modification_notice"] = "QSOL-IMC changed the scope text for a local example."
            contents = dict(self.contents, **{local["content_identity"]: b"modified scope"})
            self.assertTrue(verify_research_manifest(seal_research_manifest(self.core), contents)["byte_integrity_verified"])
            use["modification_notice"] = None

    def test_sealing_snapshots_input_without_mutation(self):
        original = copy.deepcopy(self.core)
        sealed = seal_research_manifest(self.core)
        self.assertEqual(original, self.core)
        self.core["claims"][0]["local_scope"] = "later declaration"
        self.assertEqual(sealed, self.raw)
        self.assertNotEqual(sealed, seal_research_manifest(self.core))

    def test_manifest_integrates_with_existing_store_and_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalEvidenceStore(Path(tmp) / "store")
            for raw in self.contents.values():
                store.put_artifact(raw)
            record = store.put_artifact(self.raw, media_type="application/json")
            event = EventEnvelope.seal(EventCore(
                evidence_class=EvidenceClass.DECLARED,
                actor="operator:research-test", operation="research.register",
                inputs=tuple(self.contents), outputs=(record.content_identity,),
            ))
            store.put_event(event)
            snapshot = store.finalize(scope="closed")
            report = verify_bundle(snapshot.path)
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertTrue(verify_research_manifest(self.raw, self.contents)["byte_integrity_verified"])


if __name__ == "__main__":
    unittest.main()
