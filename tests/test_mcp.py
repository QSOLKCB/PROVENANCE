from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from provenance_core import parse_canonical_json_bytes
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
