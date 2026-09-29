from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from provenance_mcp import ProvenanceMCPServer
from provenance_verify import verify_bundle, verify_forensic_package


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_BIN = REPO_ROOT / "provenance-cli" / "target" / "debug" / "provenance"


def _run(
    *args: str,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    if env is not None:
        run_env.update(env)
    return subprocess.run(
        [str(CLI_BIN), *args],
        cwd=REPO_ROOT if cwd is None else cwd,
        env=run_env,
        input=input_text,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _json_result(completed: subprocess.CompletedProcess[str]) -> dict:
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed: returncode={completed.returncode}\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    payload = json.loads(completed.stdout)
    if payload.get("ok") is not True:
        raise AssertionError(payload)
    result = payload.get("result")
    if not isinstance(result, dict):
        raise AssertionError(payload)
    return result


class ProvenanceCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not CLI_BIN.is_file():
            raise RuntimeError(
                "Phase 8 Rust CLI binary is missing; run "
                "'cargo build --manifest-path provenance-cli/Cargo.toml --locked'"
            )

    def test_terminal_lifecycle_creates_and_verifies_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "store"
            custody = root / "custody"
            export = root / "exported"
            package_root = root / "forensic-package"
            source = root / "evidence.txt"
            source_bytes = b"Phase 8 terminal evidence\n"
            source.write_bytes(source_bytes)

            recorded = _json_result(
                _run(
                    "record",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                    "--file",
                    str(source),
                    "--actor",
                    "operator:test",
                    "--operation",
                    "terminal.capture",
                    "--media-type",
                    "text/plain",
                )
            )
            self.assertEqual(recorded["classification"], "DECLARED")
            self.assertEqual(
                recorded["occurrence_classification"],
                "OBSERVED",
            )
            self.assertEqual(recorded["byte_count"], len(source_bytes))
            self.assertEqual(recorded["retention"], "CONTENT_RETAINED")

            inspected = _json_result(
                _run(
                    "inspect",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            self.assertIsNone(inspected["current_manifest_identity"])
            self.assertEqual(inspected["artifact_count"], 2)
            self.assertEqual(inspected["event_count"], 2)
            self.assertEqual(inspected["pending_artifact_count"], 2)
            self.assertEqual(inspected["pending_event_count"], 2)

            artifact_inspect = _json_result(
                _run(
                    "inspect",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                    "--identity",
                    recorded["artifact_identity"],
                )
            )
            self.assertEqual(artifact_inspect["kind"], "artifact")
            self.assertEqual(
                artifact_inspect["retention"],
                "CONTENT_RETAINED",
            )

            finalized = _json_result(
                _run(
                    "finalize",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                    "--scope",
                    "closed",
                )
            )
            self.assertTrue(finalized["integrity_verified"])
            self.assertTrue(finalized["custody_verified"])

            verified = _json_result(
                _run(
                    "verify",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            self.assertTrue(verified["bundle"]["integrity_verified"])
            self.assertTrue(verified["custody"]["integrity_verified"])
            self.assertEqual(
                verified["bundle"]["manifest_identity"],
                finalized["manifest_identity"],
            )

            exported = _json_result(
                _run(
                    "export",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                    "--destination",
                    str(export),
                )
            )
            self.assertEqual(
                exported["manifest_identity"],
                finalized["manifest_identity"],
            )
            self.assertTrue(exported["integrity_verified"])
            self.assertTrue(exported["custody_verified"])

            exported_report = verify_bundle(export)
            self.assertTrue(
                exported_report.integrity_verified,
                exported_report.errors,
            )
            self.assertEqual(
                exported_report.manifest_identity,
                finalized["manifest_identity"],
            )

            package = _json_result(
                _run(
                    "package",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                    "--destination",
                    str(package_root),
                )
            )
            self.assertEqual(
                package["manifest_identity"],
                finalized["manifest_identity"],
            )
            self.assertTrue(package["integrity_verified"])
            self.assertTrue(package["custody_verified"])
            package_report = verify_forensic_package(package_root)
            self.assertTrue(
                package_report.integrity_verified,
                package_report.errors,
            )
            self.assertEqual(
                package_report.package_identity,
                package["package_identity"],
            )
            self.assertEqual(
                package_report.evidence_manifest_identity,
                finalized["manifest_identity"],
            )

    def test_relative_paths_resolve_from_caller_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            caller = Path(tmp)
            suffix = caller.name
            store_name = f"{suffix}-store"
            custody_name = f"{suffix}-custody"
            source_name = f"{suffix}-evidence.bin"
            export_name = f"{suffix}-export"

            caller_source = caller / source_name
            caller_source.write_bytes(b"caller-relative-evidence\n")

            repo_store = REPO_ROOT / store_name
            repo_custody = REPO_ROOT / custody_name
            repo_source = REPO_ROOT / source_name
            repo_export = REPO_ROOT / export_name

            self.assertFalse(repo_store.exists())
            self.assertFalse(repo_custody.exists())
            self.assertFalse(repo_source.exists())
            self.assertFalse(repo_export.exists())

            external_env = {"PROVENANCE_ROOT": str(REPO_ROOT)}

            recorded = _json_result(
                _run(
                    "record",
                    "--store",
                    f"./{store_name}",
                    "--custody",
                    f"./{custody_name}",
                    "--file",
                    f"./{source_name}",
                    "--actor",
                    "operator:external-cwd",
                    "--operation",
                    "terminal.relative.capture",
                    cwd=caller,
                    env=external_env,
                )
            )
            self.assertEqual(recorded["byte_count"], len(caller_source.read_bytes()))
            self.assertTrue((caller / store_name).is_dir())
            self.assertTrue((caller / custody_name).is_dir())

            finalized = _json_result(
                _run(
                    "finalize",
                    "--store",
                    f"./{store_name}",
                    "--custody",
                    f"./{custody_name}",
                    cwd=caller,
                    env=external_env,
                )
            )
            self.assertTrue(finalized["integrity_verified"])

            exported = _json_result(
                _run(
                    "export",
                    "--store",
                    f"./{store_name}",
                    "--custody",
                    f"./{custody_name}",
                    "--destination",
                    f"./{export_name}",
                    cwd=caller,
                    env=external_env,
                )
            )
            self.assertTrue(exported["integrity_verified"])
            self.assertTrue((caller / export_name).is_dir())

            self.assertFalse(repo_store.exists())
            self.assertFalse(repo_custody.exists())
            self.assertFalse(repo_source.exists())
            self.assertFalse(repo_export.exists())

    def test_concurrent_cli_records_merge_one_shared_working_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "store"
            custody = root / "custody"

            command_a = [
                str(CLI_BIN),
                "record",
                "--store",
                str(store),
                "--custody",
                str(custody),
                "--text",
                "writer A",
                "--actor",
                "operator:A",
                "--operation",
                "terminal.concurrent.A",
            ]
            command_b = [
                str(CLI_BIN),
                "record",
                "--store",
                str(store),
                "--custody",
                str(custody),
                "--text",
                "writer B",
                "--actor",
                "operator:B",
                "--operation",
                "terminal.concurrent.B",
            ]

            proc_a = subprocess.Popen(
                command_a,
                cwd=REPO_ROOT,
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc_b = subprocess.Popen(
                command_b,
                cwd=REPO_ROOT,
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_a, stderr_a = proc_a.communicate(timeout=15)
            stdout_b, stderr_b = proc_b.communicate(timeout=15)

            self.assertEqual(proc_a.returncode, 0, stderr_a)
            self.assertEqual(proc_b.returncode, 0, stderr_b)
            result_a = json.loads(stdout_a)["result"]
            result_b = json.loads(stdout_b)["result"]

            inspected = _json_result(
                _run(
                    "inspect",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            self.assertEqual(inspected["artifact_count"], 4)
            self.assertEqual(inspected["event_count"], 4)

            finalized = _json_result(
                _run(
                    "finalize",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            verified = _json_result(
                _run(
                    "verify",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            self.assertTrue(verified["bundle"]["integrity_verified"])
            self.assertTrue(verified["custody"]["integrity_verified"])

            for result in (result_a, result_b):
                artifact = _json_result(
                    _run(
                        "inspect",
                        "--store",
                        str(store),
                        "--custody",
                        str(custody),
                        "--identity",
                        result["artifact_identity"],
                    )
                )
                self.assertEqual(artifact["kind"], "artifact")

            self.assertEqual(
                verified["bundle"]["manifest_identity"],
                finalized["manifest_identity"],
            )

    def test_mcp_and_cli_share_one_working_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "store"
            custody = root / "custody"

            mcp = ProvenanceMCPServer(store, custody)
            mcp_record = mcp._record(
                {
                    "actor": "mcp:test",
                    "operation": "cross-interface.mcp",
                    "value": {"source": "mcp"},
                }
            )

            cli_record = _json_result(
                _run(
                    "record",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                    "--text",
                    "cli evidence",
                    "--actor",
                    "operator:cli",
                    "--operation",
                    "cross-interface.cli",
                )
            )

            inspected = _json_result(
                _run(
                    "inspect",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            self.assertEqual(inspected["artifact_count"], 4)
            self.assertEqual(inspected["event_count"], 4)

            _json_result(
                _run(
                    "finalize",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            verified = _json_result(
                _run(
                    "verify",
                    "--store",
                    str(store),
                    "--custody",
                    str(custody),
                )
            )
            self.assertTrue(verified["bundle"]["integrity_verified"])
            self.assertTrue(verified["custody"]["integrity_verified"])

            identities = (
                mcp_record["declaration_artifact_identity"],
                mcp_record["receipt_artifact_identity"],
                mcp_record["declaration_event_identity"],
                mcp_record["receipt_event_identity"],
                cli_record["artifact_identity"],
                cli_record["receipt_artifact_identity"],
                cli_record["event_identity"],
                cli_record["receipt_event_identity"],
            )
            for identity in identities:
                resolved = _json_result(
                    _run(
                        "inspect",
                        "--store",
                        str(store),
                        "--custody",
                        str(custody),
                        "--identity",
                        identity,
                    )
                )
                self.assertIn(
                    resolved["kind"],
                    {"artifact", "event"},
                )

    def test_tui_returns_nonzero_if_any_backend_command_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = _run(
                "tui",
                "--store",
                str(root / "store"),
                "--custody",
                str(root / "custody"),
                input_text="/verify\n/quit\n",
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("command exited with status 1", completed.stdout)
            self.assertIn('"ok":false', completed.stderr)
            self.assertIn(
                "store has no finalized snapshot",
                completed.stderr,
            )

    def test_tui_slash_palette_filters_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = _run(
                "tui",
                "--store",
                str(root / "store"),
                "--custody",
                str(root / "custody"),
                input_text="/\n/ver\n/quit\n",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("/record", completed.stdout)
            self.assertIn("/inspect", completed.stdout)
            self.assertIn("/verify", completed.stdout)
            self.assertIn("/finalize", completed.stdout)
            self.assertIn("/export", completed.stdout)


if __name__ == "__main__":
    unittest.main()
