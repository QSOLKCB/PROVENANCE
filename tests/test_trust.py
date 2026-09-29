from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from provenance_core import (
    ClockAssurance,
    CustodyAction,
    EvidenceClass,
    EventCore,
    EventEnvelope,
)
from provenance_custody import ClockObservation, LocalCustodyLedger
from provenance_export import create_forensic_package
from provenance_store import LocalEvidenceStore
from provenance_trust import git_anchor_payload
from provenance_trust.records import (
    create_git_anchor_record,
    create_signature_record,
    write_trust_record,
)
from provenance_verify import (
    verify_assurance,
    verify_git_anchor_record,
    verify_signature_record,
)


def _clock() -> ClockObservation:
    return ClockObservation(
        recorded_at="2026-09-29T14:00:00.000000Z",
        clock_source="phase12-test",
        clock_assurance=ClockAssurance.LOCAL,
    )


def _package_fixture(root: Path) -> Path:
    store_root = root / "store"
    custody_root = root / "custody"
    store = LocalEvidenceStore(store_root)
    custody = LocalCustodyLedger(custody_root)

    artifact = store.put_artifact(
        b"phase-12 signed evidence\n",
        media_type="text/plain",
        retain_content=True,
    )
    event = EventEnvelope.seal(
        EventCore(
            evidence_class=EvidenceClass.OBSERVED,
            actor="phase12:test",
            operation="trust.capture",
            outputs=(artifact.content_identity,),
        )
    )
    store.put_event(event)
    snapshot = store.finalize(scope="closed")

    for subject in (
        artifact.content_identity,
        event.event_identity,
        snapshot.manifest_identity,
    ):
        custody.append(
            subject,
            CustodyAction.VERIFIED,
            actor="provenance-verify:v1",
            source="phase12-fixture",
            related_identity=(
                None
                if subject == snapshot.manifest_identity
                else snapshot.manifest_identity
            ),
            clock=_clock(),
        )

    package = create_forensic_package(
        store_root,
        custody_root,
        root / "package",
    )
    return package.path


def _fingerprint(root: Path) -> tuple[tuple[str, int, int, str], ...]:
    rows: list[tuple[str, int, int, str]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        info = path.stat()
        rows.append(
            (
                path.relative_to(root).as_posix(),
                info.st_size,
                info.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )
    return tuple(rows)


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        check=False,
    )


class TrustVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [
            name for name in ("ssh-keygen", "git")
            if shutil.which(name) is None
        ]
        if missing:
            raise RuntimeError(
                "Phase 12 trust tests require: " + ", ".join(missing)
            )

    def test_ed25519_signature_is_detached_and_reproducibly_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = _package_fixture(root)
            before = _fingerprint(package)

            key = root / "signing-key"
            generated = subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)

            record = create_signature_record(package, key)
            record_path = write_trust_record(
                root / "package.signature.json",
                record,
            )
            self.assertEqual(before, _fingerprint(package))

            report = verify_signature_record(package, record_path)
            self.assertEqual(report.status, "VERIFIED", report.errors)
            self.assertEqual(report.algorithm, "ssh-ed25519")
            self.assertTrue(report.key_fingerprint.startswith("SHA256:"))

            assurance = verify_assurance(
                package,
                signature_record=record_path,
            )
            self.assertEqual(assurance.integrity, "VERIFIED")
            self.assertEqual(assurance.signature, "VERIFIED")
            self.assertEqual(assurance.external_anchor, "NOT_PRESENT")

    def test_signature_and_integrity_are_independent_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = _package_fixture(root)
            key = root / "key"
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            signature_path = write_trust_record(
                root / "signature.json",
                create_signature_record(package, key),
            )

            artifact = next(
                path
                for path in (package / "evidence" / "artifacts" / "sha256").iterdir()
                if path.is_file()
            )
            artifact.write_bytes(artifact.read_bytes() + b"tamper")

            assurance = verify_assurance(
                package,
                signature_record=signature_path,
            )
            self.assertEqual(assurance.integrity, "FAILED")
            self.assertEqual(assurance.signature, "VERIFIED")
            self.assertEqual(assurance.external_anchor, "NOT_PRESENT")

    def test_signature_record_tamper_fails_without_changing_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = _package_fixture(root)
            key = root / "key"
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            record_path = write_trust_record(
                root / "signature.json",
                create_signature_record(package, key),
            )
            raw = record_path.read_bytes()
            record_path.write_bytes(raw[:-1] + b" ")

            report = verify_signature_record(package, record_path)
            self.assertEqual(report.status, "FAILED")

    def test_git_commit_anchor_verifies_exact_committed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = _package_fixture(root)

            repo = root / "anchor-repo"
            repo.mkdir()
            self.assertEqual(_run_git(repo, "init").returncode, 0)
            self.assertEqual(
                _run_git(repo, "config", "user.name", "Phase 12 Test").returncode,
                0,
            )
            self.assertEqual(
                _run_git(
                    repo,
                    "config",
                    "user.email",
                    "phase12@example.invalid",
                ).returncode,
                0,
            )

            package_identity = (
                __import__("json").loads(
                    (package / "package.json").read_text(encoding="utf-8")
                )["package_identity"]
            )
            anchor_file = repo / "anchors" / "package.provenance"
            anchor_file.parent.mkdir()
            anchor_file.write_bytes(git_anchor_payload(package_identity))
            self.assertEqual(_run_git(repo, "add", "anchors/package.provenance").returncode, 0)
            committed = _run_git(repo, "commit", "-m", "Anchor package")
            self.assertEqual(committed.returncode, 0, committed.stderr)

            record = create_git_anchor_record(
                package,
                repo,
                "HEAD",
                "anchors/package.provenance",
                repository_hint="local-test-repository",
            )
            record_path = write_trust_record(
                root / "git-anchor.json",
                record,
            )

            report = verify_git_anchor_record(
                package,
                record_path,
                git_repo=repo,
            )
            self.assertEqual(report.status, "VERIFIED", report.errors)

            # Working-tree changes do not rewrite the historical commit anchor.
            anchor_file.write_bytes(b"different working tree bytes")
            report = verify_git_anchor_record(
                package,
                record_path,
                git_repo=repo,
            )
            self.assertEqual(report.status, "VERIFIED", report.errors)

            no_repo = verify_git_anchor_record(
                package,
                record_path,
                git_repo=None,
            )
            self.assertEqual(no_repo.status, "NOT_ATTEMPTED")

    def test_anchor_and_integrity_are_independent_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = _package_fixture(root)
            repo = root / "repo"
            repo.mkdir()
            _run_git(repo, "init")
            _run_git(repo, "config", "user.name", "Phase 12 Test")
            _run_git(repo, "config", "user.email", "phase12@example.invalid")

            import json
            identity = json.loads(
                (package / "package.json").read_text(encoding="utf-8")
            )["package_identity"]
            target = repo / "anchor.json"
            target.write_bytes(git_anchor_payload(identity))
            _run_git(repo, "add", "anchor.json")
            commit = _run_git(repo, "commit", "-m", "Anchor")
            self.assertEqual(commit.returncode, 0, commit.stderr)

            anchor_path = write_trust_record(
                root / "anchor-record.json",
                create_git_anchor_record(
                    package,
                    repo,
                    "HEAD",
                    "anchor.json",
                ),
            )

            artifact = next(
                path
                for path in (package / "evidence" / "artifacts" / "sha256").iterdir()
                if path.is_file()
            )
            artifact.write_bytes(artifact.read_bytes() + b"tamper")

            assurance = verify_assurance(
                package,
                anchor_record=anchor_path,
                git_repo=repo,
            )
            self.assertEqual(assurance.integrity, "FAILED")
            self.assertEqual(assurance.signature, "NOT_PRESENT")
            self.assertEqual(assurance.external_anchor, "VERIFIED")

    def test_no_optional_trust_records_remains_valid_integrity_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package = _package_fixture(Path(tmp))
            report = verify_assurance(package)
            self.assertEqual(report.integrity, "VERIFIED")
            self.assertEqual(report.signature, "NOT_PRESENT")
            self.assertEqual(report.external_anchor, "NOT_PRESENT")


if __name__ == "__main__":
    unittest.main()
