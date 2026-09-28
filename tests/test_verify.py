from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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
                any("symbolic links are forbidden" in item for item in report.errors),
                report.errors,
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
