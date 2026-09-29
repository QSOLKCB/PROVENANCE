"""Local process/CLI adapter implemented through the Phase 10 adapter contract."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from provenance_core import canonical_json_bytes

from .base import (
    AdapterContract,
    AdapterExecutionError,
    AdapterFailure,
    AdapterObservation,
    CapturedArtifact,
    build_observation,
)


PROCESS_ADAPTER_CONTRACT = AdapterContract(
    adapter_id="provenance-adapter:process/v1",
    source_kind="process",
    observation_boundary=(
        "argv/stdin supplied to a child process and stdout/stderr/exit status "
        "returned to the parent; child-internal execution is not observed"
    ),
    extension_namespace="provenance.adapter.process",
)

_DEFAULT_MAX_BYTES = 16 * 1024 * 1024


class ProcessAdapterError(AdapterExecutionError):
    """Process operation failed after a provider-neutral observation was built."""


class ProcessAdapter:
    """Observe a child process without shell interpretation."""

    contract = PROCESS_ADAPTER_CONTRACT

    def __init__(
        self,
        *,
        timeout_seconds: int = 30,
        max_output_bytes: int = _DEFAULT_MAX_BYTES,
    ):
        if type(timeout_seconds) is not int or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")
        if type(max_output_bytes) is not int or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be a positive integer")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    @staticmethod
    def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise TypeError("argv must be a sequence of strings")
        normalized = tuple(argv)
        if not normalized:
            raise ValueError("argv must contain at least one element")
        for index, value in enumerate(normalized):
            if not isinstance(value, str) or not value:
                raise ValueError(f"argv[{index}] must be a non-empty string")
            if "\x00" in value:
                raise ValueError(f"argv[{index}] must not contain NUL")
        return normalized

    @staticmethod
    def _source_actor(argv: tuple[str, ...]) -> str:
        executable = Path(argv[0]).name or argv[0]
        return f"process:{executable}"

    def _inputs(
        self,
        argv: tuple[str, ...],
        stdin: bytes,
        cwd: str | None,
        stdin_media_type: str,
    ) -> tuple[CapturedArtifact, ...]:
        invocation = {
            "argv": list(argv),
            "cwd": cwd,
            "shell": False,
            "environment_retained": False,
        }
        return (
            CapturedArtifact(
                label="invocation",
                data=canonical_json_bytes(invocation),
                media_type="application/json",
            ),
            CapturedArtifact(
                label="stdin",
                data=stdin,
                media_type=stdin_media_type,
            ),
        )

    def _observation(
        self,
        *,
        argv: tuple[str, ...],
        inputs: tuple[CapturedArtifact, ...],
        outputs: tuple[CapturedArtifact, ...],
        returncode: int | None,
        cwd: str | None,
        declared_metadata: Mapping[str, Any] | None,
        extensions: Mapping[str, Any] | None,
        failure: AdapterFailure | None,
    ) -> AdapterObservation:
        metadata = {
            "process": {
                "argv0": argv[0],
                "argc": len(argv),
                "cwd": cwd,
                "returncode": returncode,
                "shell": False,
                "environment_retained": False,
            },
            "caller": dict(declared_metadata or {}),
        }
        return build_observation(
            self.contract,
            source_actor=self._source_actor(argv),
            operation="process.exec",
            inputs=inputs,
            outputs=outputs,
            declared_metadata=metadata,
            extensions=extensions,
            failure=failure,
        )

    def _bounded_outputs(
        self,
        stdout: bytes,
        stderr: bytes,
    ) -> tuple[tuple[CapturedArtifact, ...], AdapterFailure | None]:
        too_large: list[str] = []
        output_items: list[CapturedArtifact] = []
        for label, data in (("stdout", stdout), ("stderr", stderr)):
            if len(data) > self.max_output_bytes:
                too_large.append(label)
                output_items.append(
                    CapturedArtifact(
                        label=f"{label}_prefix",
                        data=data[: self.max_output_bytes],
                    )
                )
            else:
                output_items.append(CapturedArtifact(label=label, data=data))
        failure = None
        if too_large:
            failure = AdapterFailure(
                category="output_too_large",
                detail=(
                    "process output exceeded the configured capture limit for: "
                    + ", ".join(too_large)
                    + "; only observed prefixes are retained"
                ),
            )
        return tuple(output_items), failure

    def observe(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes = b"",
        cwd: Path | str | None = None,
        stdin_media_type: str = "application/octet-stream",
        declared_metadata: Mapping[str, Any] | None = None,
        extensions: Mapping[str, Any] | None = None,
    ) -> AdapterObservation:
        normalized_argv = self._validate_argv(argv)
        if not isinstance(stdin, bytes):
            raise TypeError("stdin must be bytes")
        if not isinstance(stdin_media_type, str) or not stdin_media_type:
            raise ValueError("stdin_media_type must be a non-empty string")

        cwd_text: str | None
        if cwd is None:
            cwd_text = None
        else:
            cwd_text = os.fspath(cwd)
            if not isinstance(cwd_text, str) or not cwd_text:
                raise ValueError("cwd must resolve to a non-empty string")

        inputs = self._inputs(
            normalized_argv,
            stdin,
            cwd_text,
            stdin_media_type,
        )

        try:
            completed = subprocess.run(
                list(normalized_argv),
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd_text,
                shell=False,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = bytes(exc.stdout or b"")
            stderr = bytes(exc.stderr or b"")
            outputs, size_failure = self._bounded_outputs(stdout, stderr)
            failure = size_failure or AdapterFailure(
                category="timeout",
                detail=(
                    "child process exceeded the configured timeout and was terminated"
                ),
            )
            observation = self._observation(
                argv=normalized_argv,
                inputs=inputs,
                outputs=outputs,
                returncode=None,
                cwd=cwd_text,
                declared_metadata=declared_metadata,
                extensions=extensions,
                failure=failure,
            )
            raise ProcessAdapterError(
                failure.detail,
                observation=observation,
            ) from exc
        except OSError as exc:
            failure = AdapterFailure(
                category="launch_failure",
                detail=f"child process could not be launched: {exc}",
            )
            observation = self._observation(
                argv=normalized_argv,
                inputs=inputs,
                outputs=(),
                returncode=None,
                cwd=cwd_text,
                declared_metadata=declared_metadata,
                extensions=extensions,
                failure=failure,
            )
            raise ProcessAdapterError(
                failure.detail,
                observation=observation,
            ) from exc

        stdout = bytes(completed.stdout)
        stderr = bytes(completed.stderr)
        outputs, size_failure = self._bounded_outputs(stdout, stderr)
        failure = size_failure
        if failure is None and completed.returncode != 0:
            failure = AdapterFailure(
                category="nonzero_exit",
                code=completed.returncode,
                detail=f"child process exited with status {completed.returncode}",
            )

        observation = self._observation(
            argv=normalized_argv,
            inputs=inputs,
            outputs=outputs,
            returncode=completed.returncode,
            cwd=cwd_text,
            declared_metadata=declared_metadata,
            extensions=extensions,
            failure=failure,
        )
        if failure is not None:
            raise ProcessAdapterError(
                failure.detail,
                observation=observation,
            )
        return observation
