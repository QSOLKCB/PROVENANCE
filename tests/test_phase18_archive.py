"""Exercise actual Git archive routing without claiming a Lean proof run."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import phase18_manifest

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_CITATION_SHA256 = "50633f2f0cf4fb2bb3518874cfe58e0827a12eb95fea3f76f2b24ccc75e16dcc"


class Phase18ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.run_git("init", "--quiet")
        sources = set(subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "formal"], text=True
        ).splitlines())
        sources.add("formal/CITATION.cff")
        sources.update(phase18_manifest.ARCHIVE_EXTRA_FILES)
        sources.add("CITATION.cff")
        for relative in sources:
            dest = self.repo / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, dest)
        self.run_git("add", "--all")
        self.tree = self.run_git("write-tree").decode().strip()
        self.root_patch = mock.patch.object(phase18_manifest, "ROOT", self.repo)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def run_git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.PIPE)

    def test_workflow_archive_and_manifest_share_historical_citation(self):
        # Execute the real formal-source git archive invocation from the workflow.
        workflow = (ROOT / ".github/workflows/formal.yml").read_text()
        commands = [line.strip() for line in workflow.splitlines()
                    if line.strip().startswith("git archive") and "HEAD --" in line]
        self.assertEqual(len(commands), 1)
        out = Path(self.tmp.name) / "archives"
        out.mkdir()
        args = shlex.split(commands[0])
        args = [self.tree if arg == "HEAD" else arg.replace("$out", str(out)) for arg in args]
        subprocess.run(args, cwd=self.repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        archive = out / "PROVENANCE-phase18-formal-sources.tar.gz"
        prefix = "PROVENANCE-phase18-formal/"
        with tarfile.open(archive, "r:gz") as handle:
            members = {m.name.removeprefix(prefix): handle.extractfile(m).read()
                       for m in handle.getmembers() if m.isfile()}
        files = phase18_manifest._archive_source_files(self.tree)
        self.assertEqual(set(members), set(files))
        self.assertNotIn("CITATION.cff", members)
        citation = members["formal/CITATION.cff"]
        self.assertEqual(hashlib.sha256(citation).hexdigest(), HISTORICAL_CITATION_SHA256)
        self.assertIn(b'version: "1.1.1"', citation)
        self.assertIn(b'doi: "10.5281/zenodo.23043860"', citation)
        self.assertNotIn(b"10.5281/zenodo.23207011", citation)
        for relative in files:
            raw = phase18_manifest._blob_bytes(self.tree, relative)
            self.assertEqual(raw, members[relative], relative)
        phase18_manifest._validate_historical_citation(self.tree)

    def test_moving_root_citation_cannot_change_phase18_metadata(self):
        historical = (self.repo / "formal/CITATION.cff").read_bytes()
        future = historical.replace(b'"1.1.1"', b'"9.9.9"').replace(
            b"10.5281/zenodo.23043860", b"10.5281/zenodo.99999999"
        )
        (self.repo / "CITATION.cff").write_bytes(future)
        self.run_git("add", "--all")
        tree = self.run_git("write-tree").decode().strip()
        phase18_manifest._validate_historical_citation(tree)
        self.assertNotIn("CITATION.cff", phase18_manifest._archive_source_files(tree))
        self.assertEqual(phase18_manifest._blob_bytes(tree, "formal/CITATION.cff"), historical)

    def test_changed_historical_citation_fails_closed(self):
        for raw in ((ROOT / "CITATION.cff").read_bytes(), b"altered archival citation\n"):
            with self.subTest(raw=raw[:30]):
                (self.repo / "formal/CITATION.cff").write_bytes(raw)
                self.run_git("add", "--all")
                tree = self.run_git("write-tree").decode().strip()
                with self.assertRaisesRegex(SystemExit, "published v1.1.1 citation bytes"):
                    phase18_manifest._validate_historical_citation(tree)


if __name__ == "__main__":
    unittest.main()
