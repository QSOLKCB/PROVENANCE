#!/usr/bin/env python3
"""Environment-scoped Phase 13 verifier benchmark with parity gates."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time

from provenance_core import EvidenceClass, EventCore, EventEnvelope
from provenance_custody import LocalCustodyLedger
from provenance_export import create_forensic_package
from provenance_store import LocalEvidenceStore
from provenance_verify import (
    verify_bundle,
    verify_bundle_reference,
    verify_forensic_package,
    verify_forensic_package_reference,
)
from provenance_verify._parallel import DEFAULT_MAX_VERIFY_WORKERS


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            if line.lower().startswith("model name") and ":" in line:
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _make_workload(
    root: Path,
    *,
    artifact_count: int,
    artifact_bytes: int,
) -> tuple[Path, Path]:
    store = LocalEvidenceStore(root / "store")
    for index in range(artifact_count):
        prefix = index.to_bytes(8, "big")
        payload = prefix + bytes([index % 251]) * (
            artifact_bytes - len(prefix)
        )
        artifact = store.put_artifact(
            payload,
            media_type="application/octet-stream",
            retain_content=True,
        )
        store.put_event(
            EventEnvelope.seal(
                EventCore(
                    evidence_class=EvidenceClass.OBSERVED,
                    actor="phase13:benchmark",
                    operation=f"benchmark.capture.{index}",
                    outputs=(artifact.content_identity,),
                )
            )
        )
    snapshot = store.finalize(scope="closed")

    LocalCustodyLedger(root / "custody")
    package = create_forensic_package(
        root / "store",
        root / "custody",
        root / "package",
    )
    return snapshot.path, package.path


def _measure_pair(
    reference,
    optimized,
    *,
    repetitions: int,
) -> dict[str, object]:
    reference_report = reference()
    optimized_report = optimized()
    if optimized_report != reference_report:
        raise RuntimeError(
            "optimized verifier result differs from serial reference"
        )

    reference_times: list[float] = []
    optimized_times: list[float] = []

    # Alternate order to reduce systematic cache/order bias.
    for repetition in range(repetitions):
        pair = (
            ((reference, reference_times), (optimized, optimized_times))
            if repetition % 2 == 0
            else ((optimized, optimized_times), (reference, reference_times))
        )
        for function, measurements in pair:
            start = time.perf_counter_ns()
            report = function()
            elapsed = time.perf_counter_ns() - start
            if report != reference_report:
                raise RuntimeError(
                    "verification result changed during benchmark"
                )
            measurements.append(elapsed / 1_000_000.0)

    def stats(values: list[float]) -> dict[str, float]:
        return {
            "median_ms": statistics.median(values),
            "min_ms": min(values),
            "max_ms": max(values),
            "mean_ms": statistics.mean(values),
            "stdev_ms": (
                statistics.stdev(values) if len(values) > 1 else 0.0
            ),
        }

    ref_stats = stats(reference_times)
    opt_stats = stats(optimized_times)
    ratio = (
        opt_stats["median_ms"] / ref_stats["median_ms"]
        if ref_stats["median_ms"] > 0
        else 1.0
    )
    return {
        "reference": ref_stats,
        "optimized": opt_stats,
        "optimized_to_reference_median_ratio": ratio,
        "median_improvement_percent": (1.0 - ratio) * 100.0,
        "equivalent": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-count", type=int, default=32)
    parser.add_argument("--artifact-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()

    if args.artifact_count < 2:
        parser.error("--artifact-count must be at least 2")
    if args.artifact_bytes < 4096:
        parser.error("--artifact-bytes must be at least 4096")
    if args.repetitions < 3:
        parser.error("--repetitions must be at least 3")

    with tempfile.TemporaryDirectory(prefix="provenance-phase13-") as tmp:
        snapshot, package = _make_workload(
            Path(tmp),
            artifact_count=args.artifact_count,
            artifact_bytes=args.artifact_bytes,
        )

        bundle = _measure_pair(
            lambda: verify_bundle_reference(snapshot),
            lambda: verify_bundle(snapshot),
            repetitions=args.repetitions,
        )
        forensic_package = _measure_pair(
            lambda: verify_forensic_package_reference(package),
            lambda: verify_forensic_package(package),
            repetitions=args.repetitions,
        )

    output = {
        "schema": "provenance.phase13-benchmark.v1",
        "environment": {
            "runner": os.environ.get("RUNNER_NAME", "local"),
            "os": platform.platform(),
            "machine": platform.machine(),
            "cpu_model": _cpu_model(),
            "logical_cpu_count": os.cpu_count(),
            "python": sys.version.replace("\n", " "),
            "python_implementation": platform.python_implementation(),
        },
        "workload": {
            "artifact_count": args.artifact_count,
            "artifact_bytes_each": args.artifact_bytes,
            "retained_artifact_bytes_total": (
                args.artifact_count * args.artifact_bytes
            ),
            "event_count": args.artifact_count,
            "repetitions": args.repetitions,
            "default_max_verify_workers": DEFAULT_MAX_VERIFY_WORKERS,
        },
        "bundle_verification": bundle,
        "forensic_package_verification": forensic_package,
        "claim_scope": (
            "environment-specific observation; not a universal performance default"
        ),
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
