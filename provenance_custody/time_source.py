"""Observe existing host clock tooling for custody timestamps."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
import re
import shutil
import subprocess

from provenance_core import ClockAssurance

_SELECTED_RE = re.compile(r"^([\^=#])\*\s+(\S+)", re.MULTILINE)
_OFFSET_RE = re.compile(r"\boffset\s+([+-]?\d+(?:\.\d+)?)\s+sec\b")


class TimeSourceError(RuntimeError):
    """Raised when a specifically requested clock observation cannot be made."""


@dataclass(frozen=True, slots=True)
class ClockObservation:
    recorded_at: str
    clock_source: str
    clock_assurance: ClockAssurance


def _format_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _system_now() -> datetime:
    return datetime.now(timezone.utc)


def system_clock_observation() -> ClockObservation:
    return ClockObservation(
        recorded_at=_format_utc(_system_now()),
        clock_source="system-clock",
        clock_assurance=ClockAssurance.LOCAL,
    )


def _run(
    argv: list[str],
    *,
    timeout: float,
) -> str:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TimeSourceError(
            f"clock command failed: {argv[0]}: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise TimeSourceError(
            f"clock command failed: {' '.join(argv)}: "
            f"exit={completed.returncode}: {detail}"
        )
    return completed.stdout


def _chrony_auth_mode(
    source: str,
    authdata: str,
) -> str | None:
    for line in authdata.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        if fields[0] == source:
            return fields[1]
    return None


def chrony_clock_observation(
    *,
    timeout: float = 3.0,
) -> ClockObservation:
    if shutil.which("chronyc") is None:
        raise TimeSourceError("chronyc is not installed")

    sources = _run(["chronyc", "-n", "sources"], timeout=timeout)
    match = _SELECTED_RE.search(sources)
    if match is None:
        raise TimeSourceError("chrony has no selected synchronization source")

    mode_marker, selected = match.groups()
    tracking = _run(["chronyc", "tracking"], timeout=timeout)
    if "Leap status" in tracking and "Normal" not in tracking:
        raise TimeSourceError("chrony selected source is not in normal leap status")

    if mode_marker == "#":
        return ClockObservation(
            recorded_at=_format_utc(_system_now()),
            clock_source=f"chrony-refclock:{selected}",
            clock_assurance=ClockAssurance.LOCAL,
        )

    assurance = ClockAssurance.NETWORK
    try:
        authdata = _run(["chronyc", "-n", "authdata", "-a"], timeout=timeout)
    except TimeSourceError:
        authdata = ""
    auth_mode = _chrony_auth_mode(selected, authdata)
    if auth_mode == "NTS":
        assurance = ClockAssurance.AUTHENTICATED_NETWORK

    suffix = f";auth={auth_mode}" if auth_mode else ""
    return ClockObservation(
        recorded_at=_format_utc(_system_now()),
        clock_source=f"chrony:{selected}{suffix}",
        clock_assurance=assurance,
    )


def ntpdate_clock_observation(
    server: str = "pool.ntp.org",
    *,
    timeout: float = 5.0,
) -> ClockObservation:
    if not isinstance(server, str) or not server or any(
        char.isspace() for char in server
    ):
        raise ValueError("NTP server must be one non-empty hostname/address token")
    if shutil.which("ntpdate") is None:
        raise TimeSourceError("ntpdate is not installed")

    output = _run(["ntpdate", "-q", server], timeout=timeout)
    offsets = [float(item) for item in _OFFSET_RE.findall(output)]
    if not offsets:
        raise TimeSourceError("ntpdate returned no parseable offset")

    # ntpdate may query multiple addresses for a pool name. Use the median
    # observed offset so one outlier is not silently promoted.
    offsets.sort()
    midpoint = len(offsets) // 2
    if len(offsets) % 2:
        offset = offsets[midpoint]
    else:
        offset = (offsets[midpoint - 1] + offsets[midpoint]) / 2.0

    observed = _system_now() + timedelta(seconds=offset)
    return ClockObservation(
        recorded_at=_format_utc(observed),
        clock_source=f"ntpdate:{server};offset={offset:+.9f}s",
        clock_assurance=ClockAssurance.NETWORK,
    )


def observe_clock(
    *,
    ntp_server: str = "pool.ntp.org",
    timeout: float = 3.0,
) -> ClockObservation:
    """Prefer existing chrony discipline, then query-only ntpdate, then local UTC."""

    try:
        return chrony_clock_observation(timeout=timeout)
    except TimeSourceError:
        pass

    try:
        return ntpdate_clock_observation(
            ntp_server,
            timeout=max(timeout, 1.0),
        )
    except TimeSourceError:
        return system_clock_observation()
