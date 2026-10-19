from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from provenance_core import canonical_json_bytes, parse_canonical_json_bytes, sha256_identity
from provenance_research import (
    research_check_receipt_identity,
    seal_research_check_receipt, verify_research_check_receipt,
)


def fixture(output=b"2\n"):
    values = [("source", b"add(1, 1)\n"), ("build", b"run retained source\n"),
              ("output", output), ("expectation", b"2\n"),
              ("expectation_basis", b"One plus one equals two; serialize as 2 and LF.\n")]
    artifacts = [{"key": role, "role": role, "content_identity": sha256_identity(raw),
                  "byte_count": len(raw)} for role, raw in values]
    return {
        "schema": "provenance.research-check-receipt.v1",
        "canonicalization": "provenance.canonical-json.v1",
        "evidence_class": "DECLARED",
        "source": {"repository": "https://example.invalid/research", "commit_algorithm": "sha1", "commit": "a" * 40},
        "artifacts": artifacts,
        "build": {"sources": ["source"], "recipe": "build", "outputs": ["output"]},
        "checks": [{"key": "sum", "output": "output", "expectation": "expectation",
                    "expectation_basis": "expectation_basis", "expectation_method": "analytic", "comparison": "exact_bytes"}],
    }, {sha256_identity(raw): raw for _, raw in values}


class ResearchReceiptTests(unittest.TestCase):
    def setUp(self):
        self.core, self.contents = fixture()
        self.raw = seal_research_check_receipt(self.core)

    def verify(self, core=None, contents=None):
        return verify_research_check_receipt(
            self.raw if core is None else seal_research_check_receipt(core),
            self.contents if contents is None else contents,
        )

    def test_identity_uses_independent_encoding_and_domain(self):
        encoded = (json.dumps(self.core, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        expected = "sha256:" + hashlib.sha256(b"PROVENANCE/RESEARCH-CHECK-RECEIPT/v1\0" + encoded).hexdigest()
        self.assertEqual(research_check_receipt_identity(self.core), expected)
        self.assertEqual(parse_canonical_json_bytes(self.raw)["receipt_identity"], expected)
        report = self.verify()
        for key in ("canonical", "schema_valid", "identity_valid", "byte_integrity_verified", "comparisons_verified"):
            self.assertTrue(report[key], report)
        self.assertEqual(report["checks"], [{"key": "sum", "status": "matched"}])
        for key in ("build_execution", "source_membership", "expectation_independence", "semantic_correctness"):
            self.assertEqual(report[key], "not_checked")

    def test_snapshot_and_order_preservation(self):
        raw = self.raw
        self.core["source"]["commit"] = "b" * 40
        self.assertEqual(parse_canonical_json_bytes(raw)["core"]["source"]["commit"], "a" * 40)
        original = research_check_receipt_identity(self.core)
        self.core["artifacts"].reverse()
        self.assertNotEqual(research_check_receipt_identity(self.core), original)

    def test_exact_mismatch_is_not_an_integrity_failure(self):
        for output in (b"3\n", b"2\r\n", b"2", b"2.0\n"):
            core, contents = fixture(output)
            report = self.verify(core, contents)
            self.assertTrue(report["byte_integrity_verified"])
            self.assertFalse(report["comparisons_verified"])
            self.assertEqual(report["checks"][0]["status"], "mismatched")

    def test_every_missing_artifact_blocks_all_comparisons(self):
        for artifact in self.core["artifacts"]:
            contents = self.contents.copy()
            del contents[artifact["content_identity"]]
            report = self.verify(contents=contents)
            self.assertFalse(report["byte_integrity_verified"])
            self.assertFalse(report["comparisons_verified"])
            self.assertIn(artifact["key"], report["missing_artifacts"])
            self.assertEqual(report["checks"][0]["status"], "not_checked")

    def test_wrong_bytes_and_wrong_type_fail_closed(self):
        for raw in (b"wrong", b"3\n", bytearray(b"2\n"), "2\n", None):
            contents = dict(self.contents)
            contents[self.core["artifacts"][2]["content_identity"]] = raw
            report = self.verify(contents=contents)
            self.assertFalse(report["comparisons_verified"])
            self.assertFalse(report["byte_integrity_verified"])
            self.assertTrue(report["errors"])

    def test_backend_failures_are_reported_without_hiding_other_artifacts(self):
        target = self.core["artifacts"][0]["content_identity"]
        class Backend(dict):
            def __getitem__(self, key):
                if key == target:
                    raise OSError("offline")
                return super().__getitem__(key)
        report = self.verify(contents=Backend(self.contents))
        self.assertEqual(report["missing_artifacts"], ["source"])
        self.assertEqual(len(report["checked_artifacts"]), 4)
        self.assertIn("OSError", report["errors"][0])
        self.assertFalse(report["comparisons_verified"])

    def test_process_cancellation_propagates(self):
        class Backend(dict):
            def __getitem__(self, key):
                raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.verify(contents=Backend())

    def test_compares_retained_bytes_without_second_lookup(self):
        calls = {}
        class Backend(dict):
            def __getitem__(self, key):
                calls[key] = calls.get(key, 0) + 1
                limit = 2 if key == sha256_identity(b"2\n") else 1
                if calls[key] > limit:
                    raise OSError("artifact re-read after verification")
                return super().__getitem__(key)
        self.assertTrue(self.verify(contents=Backend(self.contents))["comparisons_verified"])
        self.assertEqual(sum(calls.values()), 5)

    def test_tampering_and_self_hash_exclusion_fail(self):
        for mutate in (
            lambda e: e["core"]["source"].update(commit="b" * 40),
            lambda e: e.update(receipt_identity="sha256:" + "0" * 64),
            lambda e: e.update(self_hash_exclusion="core"),
        ):
            envelope = parse_canonical_json_bytes(self.raw)
            mutate(envelope)
            report = verify_research_check_receipt(canonical_json_bytes(envelope), self.contents)
            self.assertFalse(report["identity_valid"])
            self.assertFalse(report["comparisons_verified"])
            self.assertEqual(report["checked_artifacts"], [])

    def test_schema_rejections(self):
        mutations = [
            lambda c: c.update(extra=1),
            lambda c: c.update(evidence_class="DERIVED"),
            lambda c: c.update(schema="provenance.research-check-receipt.v2"),
            lambda c: c["source"].update(commit_algorithm="sha512"),
            lambda c: c["source"].update(extra="not allowed"),
            lambda c: c["source"].update(commit="a" * 64),
            lambda c: c["artifacts"][0].update(byte_count=True),
            lambda c: c["artifacts"][0].update(byte_count=2 ** 53),
            lambda c: c["artifacts"][0].update(content_identity="sha256:bad"),
            lambda c: c["artifacts"][0].update(role=[]),
            lambda c: c["artifacts"].append(copy.deepcopy(c["artifacts"][0])),
            lambda c: c["build"].update(sources=[]),
            lambda c: c["build"].update(outputs=[]),
            lambda c: c["build"].update(outputs=["output", "output"]),
            lambda c: c["build"].update(sources=[{}]),
            lambda c: c["build"].update(sources=["source", "source"]),
            lambda c: c["build"].update(recipe="source"),
            lambda c: c.update(checks=[]),
            lambda c: c["checks"][0].update(output="unknown"),
            lambda c: c["checks"][0].update(expectation_basis=[]),
            lambda c: c["checks"][0].update(extra="not allowed"),
            lambda c: c["checks"][0].update(expectation="output"),
            lambda c: c["checks"][0].update(expectation_basis="expectation"),
            lambda c: c["checks"][0].update(expectation_method="inferred"),
            lambda c: c["checks"][0].update(comparison="numeric_tolerance"),
            lambda c: c["checks"].append(copy.deepcopy(c["checks"][0])),
            lambda c: c["checks"].append(dict(c["checks"][0], key="duplicate-binding")),
        ]
        for mutate in mutations:
            core = copy.deepcopy(self.core)
            mutate(core)
            with self.subTest(core=core):
                with self.assertRaises(ValueError):
                    seal_research_check_receipt(core)
                envelope = parse_canonical_json_bytes(self.raw)
                envelope["core"] = core
                encoded = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()
                report = verify_research_check_receipt(encoded, self.contents)
                self.assertFalse(report["schema_valid"])
                self.assertIsNone(report["metadata_class"])
                self.assertFalse(report["comparisons_verified"])

    def test_check_output_must_belong_to_declared_build(self):
        core = copy.deepcopy(self.core)
        core["artifacts"].append(dict(core["artifacts"][2], key="unbound-output"))
        core["checks"][0]["output"] = "unbound-output"
        with self.assertRaisesRegex(ValueError, "build outputs"):
            seal_research_check_receipt(core)

    def test_strict_json_and_bad_input_fail_closed(self):
        inputs = [self.raw[:-1], b" " + self.raw, b'{"x":1,"x":2}\n', b'{"x":NaN}\n',
                  b"\xff\n", b"[]\n", b"[" * (sys.getrecursionlimit() + 10) + b"0", None, "{}"]
        for raw in inputs:
            report = verify_research_check_receipt(raw, self.contents)
            self.assertFalse(report["comparisons_verified"])
            self.assertFalse(report["byte_integrity_verified"])
            self.assertTrue(report["errors"])

    def test_sha256_commit_and_external_oracle_are_declarations(self):
        self.core["source"].update(commit_algorithm="sha256", commit="f" * 64)
        self.core["checks"][0]["expectation_method"] = "external_oracle"
        self.assertTrue(self.verify(self.core)["comparisons_verified"])

    def test_retained_example_and_literal_expectation(self):
        from examples.research_check.verify import HERE, verify
        expected = b'{"a":"caf\xc3\xa9\\n","z":[null,true,false,42]}\n'
        self.assertEqual((HERE / "expected.json").read_bytes(), expected)
        self.assertEqual((HERE / "output.json").read_bytes(), expected)
        report = verify()
        self.assertTrue(report["comparisons_verified"], report)
        self.assertEqual(report["receipt_identity"],
                         "sha256:837daa2be2eac1cb133353f53bcf1f78c3020bc04bd79f3c0ae28290e6fa10bf")

    def test_receipt_integrates_as_ordinary_store_artifact(self):
        from provenance_core import EvidenceClass, EventCore, EventEnvelope
        from provenance_store import LocalEvidenceStore
        from provenance_verify import verify_bundle
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalEvidenceStore(Path(tmp) / "store")
            for raw in self.contents.values():
                store.put_artifact(raw)
            record = store.put_artifact(self.raw, media_type="application/json")
            store.put_event(EventEnvelope.seal(EventCore(
                evidence_class=EvidenceClass.DECLARED,
                actor="operator:check-test", operation="research.check.register",
                inputs=tuple(self.contents), outputs=(record.content_identity,),
            )))
            snapshot = store.finalize(scope="closed")
            report = verify_bundle(snapshot.path)
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertTrue(self.verify()["comparisons_verified"])

    def test_example_does_not_substitute_equal_bytes_for_missing_or_wrong_file(self):
        from examples.research_check.verify import HERE, verify
        read_bytes = Path.read_bytes
        for name in ("output.json", "expected.json"):
            for missing in (True, False):
                def changed_read(path):
                    if path == HERE / name:
                        if missing:
                            raise FileNotFoundError(name)
                        return b"WRONG OUTPUT\n"
                    return read_bytes(path)
                with self.subTest(name=name, missing=missing):
                    with mock.patch.object(Path, "read_bytes", changed_read):
                        with self.assertRaises((FileNotFoundError, ValueError)):
                            verify()


if __name__ == "__main__":
    unittest.main()
