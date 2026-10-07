from __future__ import annotations

import copy
from collections.abc import Mapping
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from provenance_core import (
    EvidenceClass, EventCore, EventEnvelope, canonical_json_bytes,
    parse_canonical_json_bytes, sha256_identity,
)
from provenance_research import ResearchError, seal_research_manifest, verify_research_manifest
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "openai_math"
PINNED_IDENTITY = "sha256:a551b261cf1b8fb7db203c3cebf203b02b92fa8edebb9b27ccd6f2d88dd113ba"


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
        self.assertEqual(report["metadata_class"], "DECLARED")
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
        self.assertEqual(report["metadata_class"], "DECLARED")
        contents[digest] = b"changed"
        report = verify_research_manifest(self.raw, contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertIn("artifact bytes mismatch: scope", report["errors"])

    def test_deep_input_returns_failed_report(self):
        depth = sys.getrecursionlimit() + 100
        raw = b"[" * depth + b"0" + b"]" * depth + b"\n"
        report = verify_research_manifest(raw, self.contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertTrue(report["errors"])
        self.assertIsNone(report["research_identity"])
        self.assertIsNone(report["metadata_class"])

    def test_recursion_failure_during_canonical_validation_is_reported(self):
        with mock.patch(
            "provenance_core.canonical._validate_value",
            side_effect=RecursionError("canonical value nesting exhausted"),
        ):
            report = verify_research_manifest(self.raw, self.contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertEqual(report["errors"], ["canonical value nesting exhausted"])
        self.assertIsNone(report["metadata_class"])

    def test_unhashable_roles_and_local_references_raise_research_error(self):
        for value in ([], {}, ["local"], {"name": "local"}):
            for field in ("role", "origin", "local"):
                with self.subTest(value=value, field=field):
                    core = copy.deepcopy(self.core)
                    if field == "local":
                        core["uses"][0][field] = value
                    else:
                        core["artifacts"][0][field] = value
                    with self.assertRaises(ResearchError):
                        seal_research_manifest(core)
                    envelope = dict(self.envelope, core=core)
                    report = verify_research_manifest(canonical_json_bytes(envelope), self.contents)
                    self.assertFalse(report["byte_integrity_verified"])
                    self.assertIsNone(report["metadata_class"])

    def test_portable_paths_reject_c0_del_and_c1_controls(self):
        for codepoint in (*range(32), *range(127, 160)):
            with self.subTest(codepoint=codepoint):
                core = copy.deepcopy(self.core)
                core["artifacts"][0]["path"] = "bad" + chr(codepoint) + "name"
                with self.assertRaises(ResearchError):
                    seal_research_manifest(core)
                envelope = dict(self.envelope, core=core)
                self.assertFalse(verify_research_manifest(canonical_json_bytes(envelope), self.contents)["byte_integrity_verified"])

    def test_disappearing_digest_is_missing_and_other_checks_continue(self):
        digest = self.core["artifacts"][1]["content_identity"]

        class DisappearingContents(dict):
            def __getitem__(self, key):
                if key == digest:
                    self.pop(key, None)
                return super().__getitem__(key)

        contents = DisappearingContents(self.contents)
        self.assertIn(digest, contents)
        report = verify_research_manifest(self.raw, contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertEqual(report["missing_artifacts"], ["scope"])
        self.assertEqual(report["checked_artifacts"], ["license", "statement", "comparator", "citation"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["metadata_class"], "DECLARED")

    def test_invalid_metadata_never_acquires_a_classification(self):
        invalid_core = copy.deepcopy(self.core)
        invalid_core["evidence_class"] = "OBSERVED"
        malformed_core = copy.deepcopy(self.core)
        del malformed_core["source"]["license"]
        for raw in (
            b"[]\n", b"{\n", b" " + self.raw,
            canonical_json_bytes(dict(self.envelope, core=invalid_core)),
            canonical_json_bytes(dict(self.envelope, core=malformed_core)),
        ):
            with self.subTest(raw=raw[:30]):
                report = verify_research_manifest(raw, self.contents)
                self.assertFalse(report["byte_integrity_verified"])
                self.assertIsNone(report["metadata_class"])
                self.assertIsNone(report["research_identity"])
        tampered = dict(self.envelope, research_identity="sha256:" + "0" * 64)
        report = verify_research_manifest(canonical_json_bytes(tampered), self.contents)
        self.assertFalse(report["byte_integrity_verified"])
        self.assertEqual(report["metadata_class"], "DECLARED")

    def test_backend_lookup_errors_are_gaps_and_remaining_checks_continue(self):
        digest = self.core["artifacts"][1]["content_identity"]
        retained = self.contents

        class FailingBackend(Mapping):
            def __init__(self, failure):
                self.failure = failure

            def __getitem__(self, key):
                if key == digest:
                    raise self.failure
                return retained[key]

            def __iter__(self):
                return iter(retained)

            def __len__(self):
                return len(retained)

        for failure in (
            OSError("artifact store unavailable"), RuntimeError("backend disconnected"),
            ValueError("backend payload unreadable"), TypeError("backend decoding failed"),
        ):
            with self.subTest(failure=type(failure).__name__):
                report = verify_research_manifest(self.raw, FailingBackend(failure))
                self.assertFalse(report["byte_integrity_verified"])
                self.assertEqual(report["missing_artifacts"], ["scope"])
                self.assertEqual(report["checked_artifacts"], ["license", "statement", "comparator", "citation"])
                self.assertEqual(report["errors"], [f"artifact lookup failed: scope ({type(failure).__name__}): {failure}"])
                self.assertEqual(report["metadata_class"], "DECLARED")
        for cancellation in (KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(cancellation=type(cancellation).__name__):
                with self.assertRaises(type(cancellation)):
                    verify_research_manifest(self.raw, FailingBackend(cancellation))

    def test_source_algorithm_is_explicit_and_matches_commit_width(self):
        for algorithm, commit in (("sha1", "a" * 40), ("sha256", "b" * 64)):
            with self.subTest(algorithm=algorithm):
                core = copy.deepcopy(self.core)
                core["source"].update(commit_algorithm=algorithm, commit=commit)
                report = verify_research_manifest(seal_research_manifest(core), self.contents)
                self.assertTrue(report["byte_integrity_verified"], report)
                self.assertEqual(report["upstream_membership"], "not_checked")
        for algorithm, commit in (
            ("sha1", "a" * 64), ("sha256", "b" * 40),
            ("future-hash", "a" * 40), ([], "a" * 40),
            ("sha1", "A" * 40), ("sha1", "main"),
        ):
            with self.subTest(algorithm=algorithm, commit=commit):
                core = copy.deepcopy(self.core)
                core["source"].update(commit_algorithm=algorithm, commit=commit)
                with self.assertRaises(ResearchError):
                    seal_research_manifest(core)
                report = verify_research_manifest(canonical_json_bytes(dict(self.envelope, core=core)), self.contents)
                self.assertFalse(report["byte_integrity_verified"])
        core = copy.deepcopy(self.core)
        del core["source"]["commit_algorithm"]
        with self.assertRaises(ResearchError):
            seal_research_manifest(core)

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
