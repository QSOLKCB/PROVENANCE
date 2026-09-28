from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import provenance_verify.verifier as verifier_module

from provenance_core import (
    ArtifactRecord,
    EvidenceClass,
    EventCore,
    EventEnvelope,
    ManifestArtifact,
    ManifestCore,
    ManifestEnvelope,
    Relationship,
    RetentionState,
    canonical_json_bytes,
    manifest_identity,
    sha256_identity,
)
from provenance_verify import verify_bundle


def _digest(identity: str) -> str:
    return identity.split(":", 1)[1]


def _event_path(bundle: Path, identity: str) -> Path:
    return bundle / "events" / "sha256" / f"{_digest(identity)}.json"


def _record_path(bundle: Path, identity: str) -> Path:
    return bundle / "artifact_records" / "sha256" / f"{_digest(identity)}.json"


def _content_path(bundle: Path, identity: str) -> Path:
    return bundle / "artifacts" / "sha256" / _digest(identity)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_bundle(
    bundle: Path,
    *,
    retention: RetentionState = RetentionState.CONTENT_RETAINED,
) -> dict[str, object]:
    payload = b"phase-2 retained evidence\n"
    artifact = ArtifactRecord.from_bytes(
        payload,
        media_type="text/plain",
        retention=retention,
    )
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="adapter:test",
            operation="capture",
            outputs=(artifact.content_identity,),
        )
    )
    manifest = ManifestEnvelope.seal(
        ManifestCore.build(
            artifacts=[artifact],
            events=[event.event_identity],
            scope="closed",
        )
    )

    _write_json(bundle / "manifest.json", manifest.to_dict())
    _write_json(_record_path(bundle, artifact.record_identity), artifact.to_dict())
    _write_json(_event_path(bundle, event.event_identity), event.to_dict())
    if retention is RetentionState.CONTENT_RETAINED:
        path = _content_path(bundle, artifact.content_identity)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    return {
        "artifact": artifact,
        "event": event,
        "manifest": manifest,
        "payload": payload,
    }


class VerifyBundleTests(unittest.TestCase):
    def test_valid_retained_bundle_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)

            report = verify_bundle(bundle)

            self.assertTrue(report.integrity_verified)
            self.assertEqual(report.manifest_scope, "closed")
            self.assertEqual(report.known_missing_artifacts, 0)
            self.assertEqual(
                report.manifest_identity,
                fixture["manifest"].manifest_identity,
            )
            self.assertEqual(report.errors, ())

    def test_valid_digest_only_bundle_verifies_without_content_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle, retention=RetentionState.DIGEST_ONLY)
            artifact = fixture["artifact"]
            self.assertFalse(_content_path(bundle, artifact.content_identity).exists())

            report = verify_bundle(bundle)

            self.assertTrue(report.integrity_verified)
            self.assertEqual(report.errors, ())

    def test_open_manifest_can_encode_known_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()

            missing_id = sha256_identity(b"known but unavailable")
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="adapter:test",
                    operation="capture",
                    outputs=(missing_id,),
                )
            )
            manifest = ManifestEnvelope.seal(
                ManifestCore.build(
                    artifacts=[ManifestArtifact.missing(missing_id)],
                    events=[event.event_identity],
                    scope="open",
                )
            )
            _write_json(bundle / "manifest.json", manifest.to_dict())
            _write_json(_event_path(bundle, event.event_identity), event.to_dict())

            report = verify_bundle(bundle)

            self.assertTrue(report.integrity_verified)
            self.assertEqual(report.manifest_scope, "open")
            self.assertEqual(report.known_missing_artifacts, 1)

    def test_changed_artifact_byte_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            path = _content_path(bundle, artifact.content_identity)
            path.write_bytes(path.read_bytes() + b"x")

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("byte-count mismatch" in item for item in report.errors),
                report.errors,
            )

    def test_changed_event_field_fails_identity_recomputation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            event = fixture["event"]
            path = _event_path(bundle, event.event_identity)
            envelope = _read_json(path)
            core = envelope["core"]
            assert isinstance(core, dict)
            core["operation"] = "tampered"
            _write_json(path, envelope)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("event identity does not match" in item for item in report.errors),
                report.errors,
            )

    def test_wrong_artifact_byte_count_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            path = _record_path(bundle, artifact.record_identity)
            record = _read_json(path)
            record["byte_count"] = artifact.byte_count + 1
            _write_json(path, record)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("byte-count mismatch" in item for item in report.errors),
                report.errors,
            )

    def test_missing_retained_artifact_file_fails_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            _content_path(bundle, artifact.content_identity).unlink()

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("missing declared files" in item for item in report.errors),
                report.errors,
            )

    def test_extra_undeclared_file_fails_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)
            extra = bundle / "artifacts" / "sha256" / ("0" * 64)
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_bytes(b"undeclared")

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("undeclared files" in item for item in report.errors),
                report.errors,
            )

    def test_duplicate_manifest_artifact_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)
            path = bundle / "manifest.json"
            envelope = _read_json(path)
            core = envelope["core"]
            assert isinstance(core, dict)
            artifacts = core["artifacts"]
            assert isinstance(artifacts, list)
            artifacts.append(dict(artifacts[0]))
            envelope["manifest_identity"] = manifest_identity(core)
            _write_json(path, envelope)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("sorted and unique" in item for item in report.errors),
                report.errors,
            )

    def test_malformed_digest_fails_before_bundle_walk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)
            path = bundle / "manifest.json"
            envelope = _read_json(path)
            core = envelope["core"]
            assert isinstance(core, dict)
            artifacts = core["artifacts"]
            assert isinstance(artifacts, list)
            entry = artifacts[0]
            assert isinstance(entry, dict)
            entry["content_identity"] = "sha256:bad"
            envelope["manifest_identity"] = manifest_identity(core)
            _write_json(path, envelope)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("64 lowercase hex" in item for item in report.errors),
                report.errors,
            )

    def test_duplicate_json_key_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            manifest = bundle / "manifest.json"
            manifest.write_bytes(
                b'{"core":{},"core":{},"manifest_identity":"sha256:'
                + b"0" * 64
                + b'","self_hash_exclusion":"manifest_identity"}\n'
            )

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("duplicate JSON object key" in item for item in report.errors),
                report.errors,
            )

    def test_noncanonical_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)
            path = bundle / "manifest.json"
            envelope = _read_json(path)
            path.write_text(
                json.dumps(envelope, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("not canonical JSON" in item for item in report.errors),
                report.errors,
            )

    def test_symbolic_link_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            content = _content_path(bundle, artifact.content_identity)
            content.unlink()
            outside = root / "outside.bin"
            outside.write_bytes(fixture["payload"])
            content.symlink_to(outside)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "non-regular filesystem entries are forbidden" in item
                    for item in report.errors
                ),
                report.errors,
            )

    def test_manifest_symlink_is_rejected_before_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_bundle = root / "source"
            source_bundle.mkdir()
            _write_bundle(source_bundle)

            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "manifest.json").symlink_to(source_bundle / "manifest.json")

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "manifest.json" in item and "unsafe" in item
                    for item in report.errors
                ),
                report.errors,
            )

    def test_missing_artifact_record_does_not_claim_artifact_phase_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            _record_path(bundle, artifact.record_identity).unlink()

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertNotIn(
                "artifact metadata and available content verified",
                report.checks,
            )

    def test_missing_event_record_does_not_claim_event_phase_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            event = fixture["event"]
            _event_path(bundle, event.event_identity).unlink()

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertNotIn(
                "event identities and references verified",
                report.checks,
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX mkfifo")
    def test_undeclared_fifo_is_rejected_as_special_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)
            fifo = bundle / "undeclared.fifo"
            os.mkfifo(fifo)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "non-regular filesystem entries are forbidden" in item
                    and "undeclared.fifo" in item
                    for item in report.errors
                ),
                report.errors,
            )
            self.assertNotIn(
                "physical bundle membership exactly matches the manifest",
                report.checks,
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX mkfifo")
    def test_fifo_manifest_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            os.mkfifo(bundle / "manifest.json")

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertIn(
                "manifest.json must be a regular non-symlink file",
                report.errors,
            )

    def test_deeply_nested_manifest_returns_failed_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            depth = 2000
            (bundle / "manifest.json").write_bytes(
                (b"[" * depth) + b"{}" + (b"]" * depth) + b"\n"
            )

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("nesting depth" in item for item in report.errors),
                report.errors,
            )

    def test_oversized_integer_returns_failed_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            huge = b"9" * 5000
            (bundle / "manifest.json").write_bytes(b'{"n":' + huge + b"}\n")

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("cannot be parsed" in item for item in report.errors),
                report.errors,
            )

    def test_container_valued_enum_fields_return_failed_reports(self) -> None:
        invalid_values = ([], {}, None, True, 1)

        for invalid in invalid_values:
            with self.subTest(field="manifest scope", invalid=invalid):
                with tempfile.TemporaryDirectory() as tmp:
                    bundle = Path(tmp) / "bundle"
                    bundle.mkdir()
                    _write_bundle(bundle)
                    path = bundle / "manifest.json"
                    envelope = _read_json(path)
                    core = envelope["core"]
                    assert isinstance(core, dict)
                    core["scope"] = invalid
                    envelope["manifest_identity"] = manifest_identity(core)
                    _write_json(path, envelope)

                    report = verify_bundle(bundle)

                    self.assertFalse(report.integrity_verified)
                    self.assertTrue(
                        any("manifest scope is invalid" in item for item in report.errors),
                        report.errors,
                    )

            with self.subTest(field="manifest retention", invalid=invalid):
                with tempfile.TemporaryDirectory() as tmp:
                    bundle = Path(tmp) / "bundle"
                    bundle.mkdir()
                    _write_bundle(bundle)
                    path = bundle / "manifest.json"
                    envelope = _read_json(path)
                    core = envelope["core"]
                    assert isinstance(core, dict)
                    artifacts = core["artifacts"]
                    assert isinstance(artifacts, list)
                    entry = artifacts[0]
                    assert isinstance(entry, dict)
                    entry["retention"] = invalid
                    envelope["manifest_identity"] = manifest_identity(core)
                    _write_json(path, envelope)

                    report = verify_bundle(bundle)

                    self.assertFalse(report.integrity_verified)
                    self.assertTrue(
                        any(
                            "manifest artifact[0] retention is invalid" in item
                            for item in report.errors
                        ),
                        report.errors,
                    )

            with self.subTest(field="artifact retention", invalid=invalid):
                with tempfile.TemporaryDirectory() as tmp:
                    bundle = Path(tmp) / "bundle"
                    bundle.mkdir()
                    fixture = _write_bundle(bundle)
                    artifact = fixture["artifact"]
                    path = _record_path(bundle, artifact.record_identity)
                    record = _read_json(path)
                    record["retention"] = invalid
                    _write_json(path, record)

                    report = verify_bundle(bundle)

                    self.assertFalse(report.integrity_verified)
                    self.assertTrue(
                        any(
                            "artifact record retention is invalid" in item
                            for item in report.errors
                        ),
                        report.errors,
                    )

            for field in ("evidence_class", "collection_status"):
                with self.subTest(field=field, invalid=invalid):
                    with tempfile.TemporaryDirectory() as tmp:
                        bundle = Path(tmp) / "bundle"
                        bundle.mkdir()
                        fixture = _write_bundle(bundle)
                        event = fixture["event"]
                        path = _event_path(bundle, event.event_identity)
                        envelope = _read_json(path)
                        core = envelope["core"]
                        assert isinstance(core, dict)
                        core[field] = invalid
                        _write_json(path, envelope)

                        report = verify_bundle(bundle)

                        self.assertFalse(report.integrity_verified)
                        self.assertTrue(
                            any(
                                f"event {field} is invalid" in item
                                for item in report.errors
                            ),
                            report.errors,
                        )

    def test_symlinked_event_parent_is_never_treated_as_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)

            events = bundle / "events"
            outside_events = root / "outside-events"
            events.rename(outside_events)
            events.symlink_to(outside_events, target_is_directory=True)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "non-regular filesystem entries are forbidden" in item
                    and "events" in item
                    for item in report.errors
                ),
                report.errors,
            )
            self.assertNotIn(
                "event identities and references verified",
                report.checks,
            )

    def test_symlinked_artifact_record_parent_is_never_treated_as_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)

            records = bundle / "artifact_records"
            outside_records = root / "outside-records"
            records.rename(outside_records)
            records.symlink_to(outside_records, target_is_directory=True)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "non-regular filesystem entries are forbidden" in item
                    and "artifact_records" in item
                    for item in report.errors
                ),
                report.errors,
            )
            self.assertNotIn(
                "artifact metadata and available content verified",
                report.checks,
            )

    def test_retained_artifact_is_hashed_in_bounded_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()

            payload = b"x" * (verifier_module.READ_CHUNK_SIZE * 3 + 123)
            artifact = ArtifactRecord.from_bytes(
                payload,
                media_type="application/octet-stream",
                retention=RetentionState.CONTENT_RETAINED,
            )
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="adapter:test",
                    operation="capture",
                    outputs=(artifact.content_identity,),
                )
            )
            manifest = ManifestEnvelope.seal(
                ManifestCore.build(
                    artifacts=[artifact],
                    events=[event.event_identity],
                )
            )
            _write_json(bundle / "manifest.json", manifest.to_dict())
            _write_json(
                _record_path(bundle, artifact.record_identity),
                artifact.to_dict(),
            )
            _write_json(_event_path(bundle, event.event_identity), event.to_dict())
            content_path = _content_path(bundle, artifact.content_identity)
            content_path.parent.mkdir(parents=True, exist_ok=True)
            content_path.write_bytes(payload)

            real_read = os.read
            requested_sizes: list[int] = []

            def bounded_read(fd: int, size: int) -> bytes:
                requested_sizes.append(size)
                return real_read(fd, size)

            with mock.patch.object(verifier_module.os, "read", side_effect=bounded_read):
                report = verify_bundle(bundle)

            self.assertTrue(report.integrity_verified, report.errors)
            self.assertTrue(requested_sizes)
            self.assertLessEqual(
                max(requested_sizes),
                verifier_module.READ_CHUNK_SIZE,
            )
            self.assertGreaterEqual(len(requested_sizes), 4)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0,
        "requires unprivileged POSIX permissions",
    )
    def test_unreadable_subtree_fails_exact_membership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)

            blocked = bundle / "blocked"
            blocked.mkdir()
            (blocked / "hidden.bin").write_bytes(b"hidden")
            blocked.chmod(0)
            try:
                report = verify_bundle(bundle)
            finally:
                blocked.chmod(0o700)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "cannot traverse bundle directory blocked" in item
                    or "cannot enumerate bundle directory blocked" in item
                    for item in report.errors
                ),
                report.errors,
            )
            self.assertNotIn(
                "physical bundle membership exactly matches the manifest",
                report.checks,
            )

    def test_enumeration_failure_returns_failed_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)

            with mock.patch.object(
                verifier_module,
                "_physical_files",
                side_effect=verifier_module.VerificationError(
                    "cannot enumerate bundle directory blocked: permission denied"
                ),
            ):
                report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("cannot enumerate bundle" in item for item in report.errors),
                report.errors,
            )
            self.assertNotIn(
                "physical bundle membership exactly matches the manifest",
                report.checks,
            )

    def test_record_removed_after_enumeration_fails_overall_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            event = fixture["event"]
            event_path = _event_path(bundle, event.event_identity)
            original_physical_files = verifier_module._physical_files

            def enumerate_then_remove(root_fd: int) -> tuple[set[str], list[str]]:
                result = original_physical_files(root_fd)
                event_path.unlink()
                return result

            with mock.patch.object(
                verifier_module,
                "_physical_files",
                side_effect=enumerate_then_remove,
            ):
                report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "events/sha256/" in item and "missing or unsafe" in item
                    for item in report.errors
                ),
                report.errors,
            )
            self.assertNotIn(
                "event identities and references verified",
                report.checks,
            )

    def test_manifest_self_hash_exclusion_defect_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            _write_bundle(bundle)
            path = bundle / "manifest.json"
            envelope = _read_json(path)
            envelope["self_hash_exclusion"] = "wrong"
            _write_json(path, envelope)

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("self_hash_exclusion" in item for item in report.errors),
                report.errors,
            )

    def test_unresolved_event_input_fails_reference_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            old_event = fixture["event"]
            old_path = _event_path(bundle, old_event.event_identity)
            old_path.unlink()

            ghost = sha256_identity(b"not in manifest")
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="adapter:test",
                    operation="capture",
                    inputs=(ghost,),
                    outputs=(artifact.content_identity,),
                )
            )
            _write_json(_event_path(bundle, event.event_identity), event.to_dict())
            manifest = ManifestEnvelope.seal(
                ManifestCore.build(
                    artifacts=[artifact],
                    events=[event.event_identity],
                )
            )
            _write_json(bundle / "manifest.json", manifest.to_dict())

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any("input does not resolve" in item for item in report.errors),
                report.errors,
            )

    def test_unresolved_relationship_target_fails_reference_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()
            fixture = _write_bundle(bundle)
            artifact = fixture["artifact"]
            old_event = fixture["event"]
            _event_path(bundle, old_event.event_identity).unlink()

            ghost = sha256_identity(b"unresolved relationship")
            event = EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="adapter:test",
                    operation="capture",
                    outputs=(artifact.content_identity,),
                    relationships=(Relationship("parent", ghost),),
                )
            )
            _write_json(_event_path(bundle, event.event_identity), event.to_dict())
            manifest = ManifestEnvelope.seal(
                ManifestCore.build(
                    artifacts=[artifact],
                    events=[event.event_identity],
                )
            )
            _write_json(bundle / "manifest.json", manifest.to_dict())

            report = verify_bundle(bundle)

            self.assertFalse(report.integrity_verified)
            self.assertTrue(
                any(
                    "relationship target does not resolve" in item
                    for item in report.errors
                ),
                report.errors,
            )


if __name__ == "__main__":
    unittest.main()
