#!/usr/bin/env python3
"""Real Ollama smoke test for PROVENANCE Phase 6."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from provenance_adapters import OllamaAdapter
from provenance_custody import LocalCustodyLedger
from provenance_store import LocalEvidenceStore
from provenance_verify import verify_bundle


def _safe_label(value: str) -> str:
    return "".join(
        char if char.isalnum() or char in {"-", "_", "."} else "_"
        for char in value
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--host",
        default="http://127.0.0.1:11434",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    store = LocalEvidenceStore(output / "store")
    custody = LocalCustodyLedger(output / "custody")
    adapter = OllamaAdapter(args.host, timeout_seconds=180)

    observation = adapter.observe_generate(
        model=args.model,
        prompt=(
            "Reply with one short sentence confirming that this is a "
            "PROVENANCE integration smoke test."
        ),
        options={
            "num_ctx": 512,
            "num_predict": 24,
            "temperature": 0,
        },
        store=store,
        custody=custody,
    )

    bundle_report = verify_bundle(observation.snapshot.path)
    if not bundle_report.integrity_verified:
        raise SystemExit(
            "independent bundle verification failed: "
            + "; ".join(bundle_report.errors)
        )

    custody_report = custody.verify()
    if not custody_report.integrity_verified:
        raise SystemExit(
            "custody verification failed: "
            + "; ".join(custody_report.errors)
        )

    tampered = output / "tamper-copy"
    shutil.copytree(observation.snapshot.path, tampered)
    response_digest = observation.response.content_identity.split(":", 1)[1]
    response_path = tampered / "artifacts" / "sha256" / response_digest
    original = response_path.read_bytes()
    if not original:
        raise SystemExit("retained Ollama response is unexpectedly empty")
    response_path.write_bytes(
        bytes([original[0] ^ 0x01]) + original[1:]
    )
    tampered_report = verify_bundle(tampered)
    if tampered_report.integrity_verified:
        raise SystemExit("tampered bundle unexpectedly verified")
    shutil.rmtree(tampered)

    summary = {
        "schema": "provenance.ollama-smoke-summary.v1",
        "requested_model": args.model,
        "declared_model": observation.declared_model,
        "request_identity": observation.request.content_identity,
        "response_identity": observation.response.content_identity,
        "request_event_identity": observation.request_event.event_identity,
        "response_event_identity": observation.response_event.event_identity,
        "declaration_event_identity": (
            observation.declaration_event.event_identity
        ),
        "manifest_identity": observation.snapshot.manifest_identity,
        "bundle_integrity_verified": True,
        "custody_integrity_verified": True,
        "tamper_detected": not tampered_report.integrity_verified,
        "response_text": observation.response_text,
    }
    summary_path = output / f"summary-{_safe_label(args.model)}.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
