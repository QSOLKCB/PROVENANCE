from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from provenance_core import canonical_json_bytes, parse_canonical_json_bytes
import provenance_mcp.server as mcp_server_module
from provenance_custody import LocalCustodyLedger
from provenance_mcp import ProvenanceMCPServer
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


PROTOCOL_VERSION = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {
        "name": "provenance-phase7-test",
        "version": "1.0.0",
    },
}


class _StdioClient:
    def __init__(self, store_root: Path, custody_root: Path):
        repo_root = Path(__file__).resolve().parents[1]
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "provenance_mcp",
                "--store",
                str(store_root),
                "--custody",
                str(custody_root),
            ],
            cwd=repo_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self._next_id = 1

    def request(
        self,
        method: str,
        params: dict | None = None,
        *,
        modern: bool = True,
    ) -> dict:
        request_id = self._next_id
        self._next_id += 1
        value_params = dict(params or {})
        if modern:
            value_params["_meta"] = dict(META)
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": value_params,
        }
        self.process.stdin.write(
            json.dumps(request, separators=(",", ":"), sort_keys=True) + "\n"
        )
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read()
            raise AssertionError(
                f"MCP server closed before response to {method}: {stderr}"
            )
        response = json.loads(line)
        if response.get("id") != request_id:
            raise AssertionError(
                f"MCP response id mismatch: expected {request_id}, got {response!r}"
            )
        return response

    def notify(
        self,
        method: str,
        params: dict | None = None,
    ) -> None:
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": dict(params or {}),
        }
        self.process.stdin.write(
            json.dumps(request, separators=(",", ":"), sort_keys=True) + "\n"
        )
        self.process.stdin.flush()

    def close(self) -> tuple[int, str]:
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        returncode = self.process.wait(timeout=10)
        stderr = self.process.stderr.read()
        if self.process.stdout is not None and not self.process.stdout.closed:
            self.process.stdout.close()
        if self.process.stderr is not None and not self.process.stderr.closed:
            self.process.stderr.close()
        return returncode, stderr


def _tool_payload(response: dict) -> dict:
    result = response.get("result")
    if not isinstance(result, dict):
        raise AssertionError(response)
    payload = result.get("structuredContent")
    if not isinstance(payload, dict):
        raise AssertionError(response)
    return payload


class ProvenanceMCPTests(unittest.TestCase):
    def test_modern_stdio_self_demonstration_preserves_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"
            export_root = root / "exported"
            client = _StdioClient(store_root, custody_root)
            try:
                discovered = client.request("server/discover")
                discover_result = discovered["result"]
                self.assertEqual(
                    discover_result["supportedVersions"][0],
                    PROTOCOL_VERSION,
                )
                self.assertEqual(discover_result["resultType"], "complete")
                self.assertEqual(discover_result["ttlMs"], 0)
                self.assertEqual(discover_result["cacheScope"], "private")

                listed = client.request("tools/list")
                tools = listed["result"]["tools"]
                self.assertEqual(
                    [item["name"] for item in tools],
                    [
                        "provenance.finalize",
                        "provenance.inspect",
                        "provenance.record",
                        "provenance.verify",
                        "provenance.export",
                    ],
                )
                finalize_tool = next(
                    item
                    for item in tools
                    if item["name"] == "provenance.finalize"
                )
                self.assertFalse(
                    finalize_tool["annotations"]["idempotentHint"]
                )

                arguments = {
                    "actor": "test-client:declared-actor",
                    "operation": "test.declaration",
                    "value": {
                        "claim": "caller supplied",
                        "sequence": 1,
                    },
                }
                first = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.record",
                            "arguments": arguments,
                        },
                    )
                )
                second = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.record",
                            "arguments": arguments,
                        },
                    )
                )

                self.assertEqual(first["classification"], "DECLARED")
                self.assertEqual(
                    first["occurrence_classification"],
                    "OBSERVED",
                )
                self.assertEqual(
                    first["declaration_artifact_identity"],
                    second["declaration_artifact_identity"],
                )
                self.assertEqual(
                    first["declaration_event_identity"],
                    second["declaration_event_identity"],
                )
                self.assertNotEqual(
                    first["receipt_artifact_identity"],
                    second["receipt_artifact_identity"],
                )
                self.assertNotEqual(
                    first["receipt_event_identity"],
                    second["receipt_event_identity"],
                )

                prefinal = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.inspect",
                            "arguments": {},
                        },
                    )
                )
                self.assertIsNone(prefinal["current_manifest_identity"])
                self.assertEqual(prefinal["artifact_count"], 3)
                self.assertEqual(prefinal["event_count"], 3)

                finalized = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.finalize",
                            "arguments": {"scope": "closed"},
                        },
                    )
                )
                self.assertTrue(finalized["integrity_verified"])
                self.assertTrue(finalized["custody_verified"])
                manifest_identity = finalized["manifest_identity"]

                declaration_resource = client.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://event/"
                            + first["declaration_event_identity"]
                        )
                    },
                )
                declaration_text = declaration_resource["result"]["contents"][0]["text"]
                declaration_event = parse_canonical_json_bytes(
                    declaration_text.encode("utf-8")
                )
                self.assertEqual(
                    declaration_event["core"]["evidence_class"],
                    "DECLARED",
                )
                self.assertEqual(
                    declaration_event["core"]["actor"],
                    "test-client:declared-actor",
                )

                receipt_resource = client.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://event/"
                            + first["receipt_event_identity"]
                        )
                    },
                )
                receipt_text = receipt_resource["result"]["contents"][0]["text"]
                receipt_event = parse_canonical_json_bytes(
                    receipt_text.encode("utf-8")
                )
                self.assertEqual(
                    receipt_event["core"]["evidence_class"],
                    "OBSERVED",
                )
                self.assertEqual(
                    receipt_event["core"]["actor"],
                    "provenance-mcp:stdio/v1",
                )

                resources = client.request("resources/list")
                uris = [
                    item["uri"]
                    for item in resources["result"]["resources"]
                ]
                self.assertIn(
                    f"provenance://manifest/{manifest_identity}",
                    uris,
                )
                self.assertIn(
                    (
                        "provenance://artifact/"
                        + first["declaration_artifact_identity"]
                    ),
                    uris,
                )

                verified = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.verify",
                            "arguments": {},
                        },
                    )
                )
                self.assertTrue(
                    verified["bundle"]["integrity_verified"],
                    verified,
                )
                self.assertTrue(
                    verified["custody"]["integrity_verified"],
                    verified,
                )
                self.assertEqual(
                    verified["bundle"]["manifest_identity"],
                    manifest_identity,
                )

                forbidden_export = store_root / "nested-export"
                forbidden = client.request(
                    "tools/call",
                    {
                        "name": "provenance.export",
                        "arguments": {
                            "destination": str(forbidden_export),
                        },
                    },
                )
                self.assertTrue(forbidden["result"]["isError"])
                self.assertIn(
                    "outside the live store",
                    forbidden["result"]["content"][0]["text"],
                )
                self.assertFalse(forbidden_export.exists())

                exported = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.export",
                            "arguments": {
                                "destination": str(export_root),
                            },
                        },
                    )
                )
                self.assertTrue(exported["integrity_verified"])
                self.assertTrue(exported["custody_verified"])
                self.assertEqual(
                    exported["manifest_identity"],
                    manifest_identity,
                )
                exported_report = verify_bundle(export_root)
                self.assertTrue(
                    exported_report.integrity_verified,
                    exported_report.errors,
                )
                self.assertEqual(
                    exported_report.manifest_identity,
                    manifest_identity,
                )
            finally:
                returncode, stderr = client.close()

            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_concurrent_servers_merge_acknowledged_working_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"

            client_a = _StdioClient(store_root, custody_root)
            client_b = _StdioClient(store_root, custody_root)
            results: dict[str, dict] = {}
            errors: list[BaseException] = []
            barrier = threading.Barrier(3)

            try:
                client_a.request("server/discover")
                client_b.request("server/discover")

                def record(
                    label: str,
                    client: _StdioClient,
                ) -> None:
                    try:
                        barrier.wait(timeout=5)
                        results[label] = _tool_payload(
                            client.request(
                                "tools/call",
                                {
                                    "name": "provenance.record",
                                    "arguments": {
                                        "actor": f"concurrent-{label}",
                                        "operation": f"concurrent.record.{label}",
                                        "value": {"writer": label},
                                    },
                                },
                            )
                        )
                    except BaseException as exc:
                        errors.append(exc)

                thread_a = threading.Thread(
                    target=record,
                    args=("A", client_a),
                )
                thread_b = threading.Thread(
                    target=record,
                    args=("B", client_b),
                )
                thread_a.start()
                thread_b.start()
                barrier.wait(timeout=5)
                thread_a.join(timeout=10)
                thread_b.join(timeout=10)

                self.assertFalse(thread_a.is_alive())
                self.assertFalse(thread_b.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(set(results), {"A", "B"})
            finally:
                returncode_a, stderr_a = client_a.close()
                returncode_b, stderr_b = client_b.close()

            self.assertEqual(returncode_a, 0, stderr_a)
            self.assertEqual(stderr_a, "")
            self.assertEqual(returncode_b, 0, stderr_b)
            self.assertEqual(stderr_b, "")

            state_path = store_root / ".provenance-mcp-working.json"
            state = parse_canonical_json_bytes(state_path.read_bytes())
            self.assertEqual(state["phase"], "recording")
            self.assertEqual(len(state["artifacts"]), 4)
            self.assertEqual(len(state["events"]), 4)
            self.assertEqual(
                len(state["pending_verified_artifacts"]),
                4,
            )

            finalizer = _StdioClient(store_root, custody_root)
            try:
                finalizer.request("server/discover")
                prefinal = _tool_payload(
                    finalizer.request(
                        "tools/call",
                        {
                            "name": "provenance.inspect",
                            "arguments": {},
                        },
                    )
                )
                self.assertEqual(prefinal["artifact_count"], 4)
                self.assertEqual(prefinal["event_count"], 4)

                finalized = _tool_payload(
                    finalizer.request(
                        "tools/call",
                        {
                            "name": "provenance.finalize",
                            "arguments": {"scope": "closed"},
                        },
                    )
                )
                self.assertTrue(finalized["integrity_verified"])
                self.assertTrue(finalized["custody_verified"])

                manifest_response = finalizer.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://manifest/"
                            + finalized["manifest_identity"]
                        )
                    },
                )
                manifest = parse_canonical_json_bytes(
                    manifest_response["result"]["contents"][0]["text"].encode(
                        "utf-8"
                    )
                )
                artifact_ids = {
                    item["content_identity"]
                    for item in manifest["core"]["artifacts"]
                }
                event_ids = set(manifest["core"]["events"])

                for result in results.values():
                    self.assertIn(
                        result["declaration_artifact_identity"],
                        artifact_ids,
                    )
                    self.assertIn(
                        result["receipt_artifact_identity"],
                        artifact_ids,
                    )
                    self.assertIn(
                        result["declaration_event_identity"],
                        event_ids,
                    )
                    self.assertIn(
                        result["receipt_event_identity"],
                        event_ids,
                    )

                verified = _tool_payload(
                    finalizer.request(
                        "tools/call",
                        {
                            "name": "provenance.verify",
                            "arguments": {},
                        },
                    )
                )
                self.assertTrue(verified["bundle"]["integrity_verified"])
                self.assertTrue(verified["custody"]["integrity_verified"])
                self.assertEqual(
                    verified["custody"]["record_count"],
                    13,
                )
            finally:
                returncode, stderr = finalizer.close()

            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")
            self.assertFalse(state_path.exists())

    def test_record_rejects_root_swap_during_journal_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"
            moved_root = root / "store-original"

            server = ProvenanceMCPServer(store_root, custody_root)
            original_write = server._write_working_state
            swapped = False

            def swap_then_write(
                *,
                phase: str,
                finalized_manifest_identity: str | None = None,
            ) -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    store_root.rename(moved_root)
                    LocalEvidenceStore(store_root)
                original_write(
                    phase=phase,
                    finalized_manifest_identity=finalized_manifest_identity,
                )

            with mock.patch.object(
                server,
                "_write_working_state",
                side_effect=swap_then_write,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "store root filesystem identity changed",
                ):
                    server._record(
                        {
                            "actor": "root-swap-record-test",
                            "operation": "record.swap",
                            "value": {"x": 1},
                        }
                    )

            self.assertTrue(swapped)
            self.assertTrue(
                (moved_root / ".provenance-mcp-working.json").is_file()
            )
            self.assertFalse(
                (store_root / ".provenance-mcp-working.json").exists()
            )

            replacement = ProvenanceMCPServer(store_root, custody_root)
            replacement_state = replacement._inspect({})
            self.assertIsNone(replacement_state["current_manifest_identity"])
            self.assertEqual(replacement_state["artifact_count"], 0)
            self.assertEqual(replacement_state["event_count"], 0)

            recovered = ProvenanceMCPServer(moved_root, custody_root)
            recovered_state = recovered._inspect({})
            self.assertEqual(recovered_state["artifact_count"], 2)
            self.assertEqual(recovered_state["event_count"], 2)

    def test_long_lived_server_rejects_replacement_store_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"

            server = ProvenanceMCPServer(store_root, custody_root)
            server._record(
                {
                    "actor": "root-binding-test",
                    "operation": "root.binding",
                    "value": {"generation": 1},
                }
            )
            finalized = server._finalize({"scope": "closed"})
            original_identity = finalized["manifest_identity"]

            moved_root = root / "store-original"
            store_root.rename(moved_root)
            replacement = LocalEvidenceStore(store_root)
            self.assertIsNone(replacement.current_manifest_identity)

            with self.assertRaisesRegex(
                RuntimeError,
                "store root filesystem identity changed",
            ):
                server._inspect({})

            reopened_original = LocalEvidenceStore(moved_root)
            self.assertEqual(
                reopened_original.current_manifest_identity,
                original_identity,
            )
            self.assertTrue(
                reopened_original.verify_current().integrity_verified
            )
            self.assertIsNone(
                LocalEvidenceStore(store_root).current_manifest_identity
            )

    def test_finalized_journal_rejects_unretained_verified_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"

            producer = ProvenanceMCPServer(store_root, custody_root)
            producer._record(
                {
                    "actor": "journal-validation-test",
                    "operation": "journal.valid",
                    "value": {"x": 1},
                }
            )
            finalized = producer._finalize({"scope": "closed"})
            manifest_identity = finalized["manifest_identity"]

            before = LocalCustodyLedger(custody_root).verify()
            self.assertTrue(before.integrity_verified)
            before_count = before.record_count

            forged_subject = "sha256:" + "0" * 64
            forged_state = {
                "schema": "provenance.mcp-working-state.v1",
                "phase": "finalized",
                "base_manifest_identity": manifest_identity,
                "finalized_manifest_identity": manifest_identity,
                "artifacts": [],
                "events": [],
                "pending_verified_artifacts": [forged_subject],
            }
            state_path = store_root / ".provenance-mcp-working.json"
            state_path.write_bytes(canonical_json_bytes(forged_state))

            with self.assertRaisesRegex(
                RuntimeError,
                "pending verification subjects must exactly match",
            ):
                ProvenanceMCPServer(store_root, custody_root)

            after = LocalCustodyLedger(custody_root).verify()
            self.assertTrue(after.integrity_verified)
            self.assertEqual(after.record_count, before_count)
            self.assertTrue(state_path.is_file())

    def test_long_lived_server_refreshes_latest_head_for_current_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"

            stale = ProvenanceMCPServer(store_root, custody_root)
            writer = ProvenanceMCPServer(store_root, custody_root)

            first_record = writer._record(
                {
                    "actor": "writer",
                    "operation": "snapshot.first",
                    "value": {"generation": 1},
                }
            )
            self.assertEqual(first_record["classification"], "DECLARED")
            first = writer._finalize({"scope": "closed"})

            # This server existed before any finalized HEAD. Verification must
            # refresh rather than reporting "no finalized snapshot".
            verified_first = stale._verify({})
            self.assertTrue(verified_first["bundle"]["integrity_verified"])
            self.assertEqual(
                verified_first["bundle"]["manifest_identity"],
                first["manifest_identity"],
            )

            second_record = writer._record(
                {
                    "actor": "writer",
                    "operation": "snapshot.second",
                    "value": {"generation": 2},
                }
            )
            self.assertEqual(second_record["classification"], "DECLARED")
            second = writer._finalize({"scope": "closed"})
            self.assertNotEqual(
                first["manifest_identity"],
                second["manifest_identity"],
            )

            inspected = stale._inspect({})
            self.assertEqual(
                inspected["current_manifest_identity"],
                second["manifest_identity"],
            )
            self.assertEqual(
                inspected["manifest"]["manifest_identity"],
                second["manifest_identity"],
            )

            verified_second = stale._verify({})
            self.assertTrue(verified_second["bundle"]["integrity_verified"])
            self.assertEqual(
                verified_second["bundle"]["manifest_identity"],
                second["manifest_identity"],
            )

            export_root = root / "latest-export"
            exported = stale._export(
                {"destination": str(export_root)}
            )
            self.assertEqual(
                exported["manifest_identity"],
                second["manifest_identity"],
            )
            exported_report = verify_bundle(export_root)
            self.assertTrue(
                exported_report.integrity_verified,
                exported_report.errors,
            )
            self.assertEqual(
                exported_report.manifest_identity,
                second["manifest_identity"],
            )

    def test_restart_recovers_unfinalized_record_membership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"

            first_client = _StdioClient(store_root, custody_root)
            try:
                first_client.request("server/discover")
                recorded = _tool_payload(
                    first_client.request(
                        "tools/call",
                        {
                            "name": "provenance.record",
                            "arguments": {
                                "actor": "restart-test",
                                "operation": "restart.pending",
                                "value": {"pending": True},
                            },
                        },
                    )
                )
            finally:
                returncode, stderr = first_client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

            state_path = store_root / ".provenance-mcp-working.json"
            self.assertTrue(state_path.is_file())

            second_client = _StdioClient(store_root, custody_root)
            try:
                second_client.request("server/discover")
                prefinal = _tool_payload(
                    second_client.request(
                        "tools/call",
                        {
                            "name": "provenance.inspect",
                            "arguments": {},
                        },
                    )
                )
                self.assertEqual(prefinal["artifact_count"], 2)
                self.assertEqual(prefinal["event_count"], 2)

                finalized = _tool_payload(
                    second_client.request(
                        "tools/call",
                        {
                            "name": "provenance.finalize",
                            "arguments": {"scope": "closed"},
                        },
                    )
                )
                self.assertTrue(finalized["integrity_verified"])
                self.assertTrue(finalized["custody_verified"])

                manifest_response = second_client.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://manifest/"
                            + finalized["manifest_identity"]
                        )
                    },
                )
                manifest = parse_canonical_json_bytes(
                    manifest_response["result"]["contents"][0]["text"].encode(
                        "utf-8"
                    )
                )
                artifacts = {
                    item["content_identity"]
                    for item in manifest["core"]["artifacts"]
                }
                events = set(manifest["core"]["events"])
                self.assertIn(
                    recorded["declaration_artifact_identity"],
                    artifacts,
                )
                self.assertIn(
                    recorded["receipt_artifact_identity"],
                    artifacts,
                )
                self.assertIn(
                    recorded["declaration_event_identity"],
                    events,
                )
                self.assertIn(
                    recorded["receipt_event_identity"],
                    events,
                )

                verified = _tool_payload(
                    second_client.request(
                        "tools/call",
                        {
                            "name": "provenance.verify",
                            "arguments": {},
                        },
                    )
                )
                self.assertTrue(verified["bundle"]["integrity_verified"])
                self.assertTrue(verified["custody"]["integrity_verified"])
                self.assertEqual(
                    verified["custody"]["record_count"],
                    7,
                )
            finally:
                returncode, stderr = second_client.close()

            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")
            self.assertFalse(state_path.exists())

    def test_artifact_read_uses_unfinalized_retention_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            arguments = {
                "actor": "retention-test",
                "operation": "retention.upgrade",
                "value": {"payload": "same-content"},
            }
            try:
                client.request("server/discover")
                first = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.record",
                            "arguments": {
                                **arguments,
                                "retainContent": False,
                            },
                        },
                    )
                )
                _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.finalize",
                            "arguments": {"scope": "closed"},
                        },
                    )
                )

                second = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.record",
                            "arguments": arguments,
                        },
                    )
                )
                self.assertEqual(
                    first["declaration_artifact_identity"],
                    second["declaration_artifact_identity"],
                )

                resource = client.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://artifact/"
                            + second["declaration_artifact_identity"]
                        )
                    },
                )
                content = resource["result"]["contents"][0]
                self.assertIn("blob", content)
                self.assertNotIn("text", content)
                expected = canonical_json_bytes(
                    {
                        "schema": "provenance.mcp-declaration.v1",
                        "actor": arguments["actor"],
                        "operation": arguments["operation"],
                        "value": arguments["value"],
                    }
                )
                self.assertEqual(
                    base64.b64decode(content["blob"]),
                    expected,
                )

                _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.finalize",
                            "arguments": {"scope": "closed"},
                        },
                    )
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_export_parent_swap_cannot_escape_descriptor_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            custody_root = root / "custody"
            export_parent = root / "exports"
            moved_parent = root / "exports-moved"
            export_parent.mkdir()

            server = ProvenanceMCPServer(store_root, custody_root)
            recorded = server._record(
                {
                    "actor": "export-race-test",
                    "operation": "export.race",
                    "value": {"x": 1},
                }
            )
            self.assertEqual(recorded["classification"], "DECLARED")
            server._finalize({"scope": "closed"})

            destination = export_parent / "bundle"
            original_copy = mcp_server_module._copy_directory_contents
            raced = False

            def race_then_copy(source_fd: int, destination_fd: int) -> None:
                nonlocal raced
                if not raced:
                    raced = True
                    export_parent.rename(moved_parent)
                    export_parent.symlink_to(
                        store_root,
                        target_is_directory=True,
                    )
                original_copy(source_fd, destination_fd)

            try:
                with mock.patch.object(
                    mcp_server_module,
                    "_copy_directory_contents",
                    side_effect=race_then_copy,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "parent changed during publication",
                    ):
                        server._export({"destination": str(destination)})
            finally:
                if export_parent.is_symlink():
                    export_parent.unlink()
                if moved_parent.exists():
                    moved_parent.rename(export_parent)

            self.assertTrue(raced)
            self.assertFalse((store_root / "bundle").exists())
            self.assertFalse((export_parent / "bundle").exists())
            self.assertTrue(server.store.verify_current().integrity_verified)
            self.assertTrue(server.custody.verify().integrity_verified)

    def test_record_rejects_caller_evidence_class_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                client.request("server/discover")
                response = client.request(
                    "tools/call",
                    {
                        "name": "provenance.record",
                        "arguments": {
                            "actor": "caller",
                            "operation": "attempted.override",
                            "value": {"x": 1},
                            "evidenceClass": "OBSERVED",
                        },
                    },
                )
                self.assertTrue(response["result"]["isError"])
                self.assertIn(
                    "unsupported fields",
                    response["result"]["content"][0]["text"],
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_legacy_initialize_and_tools_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                initialized = client.request(
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "legacy-test",
                            "version": "1.0",
                        },
                    },
                    modern=False,
                )
                self.assertEqual(
                    initialized["result"]["protocolVersion"],
                    "2025-11-25",
                )
                client.notify("notifications/initialized")
                listed = client.request(
                    "tools/list",
                    {},
                    modern=False,
                )
                self.assertIn("tools", listed["result"])
                self.assertNotIn("resultType", listed["result"])
                ping = client.request(
                    "ping",
                    {},
                    modern=False,
                )
                self.assertEqual(ping["result"], {})
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_legacy_request_before_initialize_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                response = client.request(
                    "tools/list",
                    {},
                    modern=False,
                )
                self.assertEqual(response["error"]["code"], -32600)
                self.assertIn(
                    "before initialize",
                    response["error"]["message"],
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_stdio_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                client.process.stdin.write(
                    '{"jsonrpc":"2.0","id":1,'
                    '"method":"server/discover",'
                    '"method":"tools/list","params":{}}\n'
                )
                client.process.stdin.flush()
                response = json.loads(client.process.stdout.readline())
                self.assertIsNone(response["id"])
                self.assertEqual(response["error"]["code"], -32700)
                self.assertIn(
                    "duplicate JSON key",
                    response["error"]["message"],
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_resource_reads_recompute_bound_identities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            client = _StdioClient(store_root, root / "custody")
            try:
                client.request("server/discover")
                recorded = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.record",
                            "arguments": {
                                "actor": "tamper-test",
                                "operation": "tamper.resource",
                                "value": {"message": "original"},
                            },
                        },
                    )
                )
                _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.finalize",
                            "arguments": {"scope": "closed"},
                        },
                    )
                )

                event_identity = recorded["receipt_event_identity"]
                event_digest = event_identity.split(":", 1)[1]
                event_path = (
                    store_root
                    / "objects"
                    / "events"
                    / "sha256"
                    / f"{event_digest}.json"
                )
                original_event = event_path.read_bytes()
                event_value = parse_canonical_json_bytes(original_event)
                event_value["core"]["operation"] = "tampered.operation"
                event_path.write_bytes(canonical_json_bytes(event_value))

                event_response = client.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://event/"
                            + event_identity
                        )
                    },
                )
                self.assertEqual(
                    event_response["error"]["code"],
                    -32603,
                )
                event_detail = event_response["error"]["data"]["detail"]
                self.assertTrue(
                    "does not match resource identity" in event_detail
                    or "differs from verified snapshot" in event_detail,
                    event_detail,
                )
                event_path.write_bytes(original_event)

                artifact_identity = recorded["declaration_artifact_identity"]
                artifact_digest = artifact_identity.split(":", 1)[1]
                artifact_path = (
                    store_root
                    / "objects"
                    / "artifacts"
                    / "sha256"
                    / artifact_digest
                )
                original_artifact = artifact_path.read_bytes()
                self.assertGreater(len(original_artifact), 0)
                tampered_artifact = (
                    bytes([original_artifact[0] ^ 1])
                    + original_artifact[1:]
                )
                artifact_path.write_bytes(tampered_artifact)

                artifact_response = client.request(
                    "resources/read",
                    {
                        "uri": (
                            "provenance://artifact/"
                            + artifact_identity
                        )
                    },
                )
                self.assertEqual(
                    artifact_response["error"]["code"],
                    -32603,
                )
                artifact_detail = artifact_response["error"]["data"]["detail"]
                self.assertTrue(
                    "content does not match resource identity" in artifact_detail
                    or "differs from verified snapshot" in artifact_detail,
                    artifact_detail,
                )
                artifact_path.write_bytes(original_artifact)

                verified = _tool_payload(
                    client.request(
                        "tools/call",
                        {
                            "name": "provenance.verify",
                            "arguments": {},
                        },
                    )
                )
                self.assertTrue(verified["bundle"]["integrity_verified"])
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_modern_missing_resource_is_invalid_params(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                client.request("server/discover")
                missing = (
                    "provenance://event/sha256:"
                    + "0" * 64
                )
                response = client.request(
                    "resources/read",
                    {"uri": missing},
                )
                self.assertEqual(response["error"]["code"], -32602)
                self.assertEqual(
                    response["error"]["data"],
                    {"uri": missing},
                )
                self.assertIn(
                    "does not exist",
                    response["error"]["message"],
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_modern_unsupported_version_returns_negotiation_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                request_id = client._next_id
                client._next_id += 1
                request = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/list",
                    "params": {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion":
                                "2099-01-01",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        }
                    },
                }
                client.process.stdin.write(
                    json.dumps(
                        request,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                )
                client.process.stdin.flush()
                response = json.loads(client.process.stdout.readline())
                self.assertEqual(response["id"], request_id)
                self.assertEqual(response["error"]["code"], -32022)
                self.assertIn(
                    "2026-07-28",
                    response["error"]["data"]["supportedVersions"],
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_modern_ping_is_not_defined(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                client.request("server/discover")
                response = client.request("ping")
                self.assertEqual(response["error"]["code"], -32601)
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(stderr, "")

    def test_modern_connection_rejects_era_switch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _StdioClient(root / "store", root / "custody")
            try:
                client.request("server/discover")
                response = client.request(
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "wrong-era",
                            "version": "1.0",
                        },
                    },
                    modern=False,
                )
                self.assertEqual(response["error"]["code"], -32600)
                self.assertIn(
                    "already pinned",
                    response["error"]["message"],
                )
            finally:
                returncode, stderr = client.close()
            self.assertEqual(returncode, 0, stderr)


if __name__ == "__main__":
    unittest.main()
