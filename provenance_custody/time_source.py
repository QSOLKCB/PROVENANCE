"""Observe existing host clock tooling for custody timestamps."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
import shutil
import subprocess
import time

from provenance_core import ClockAssurance

_NANOSECONDS_PER_SECOND = 1_000_000_000
_SELECTED_RE = re.compile(r"^([\^=#])\*\s+(\S+)", re.MULTILINE)
_LEAP_RE = re.compile(r"^Leap status\s*:\s*(\S+)\s*$", re.MULTILINE)
_SERVER_OFFSET_RE = re.compile(
    r"^server\s+.*?\boffset\s+([+-]?\d+(?:\.\d+)?),",
    re.MULTILINE,
)
_SUMMARY_OFFSET_RE = re.compile(
    r"\boffset\s+([+-]?\d+(?:\.\d+)?)\s+sec\b"
)
_DECIMAL_SECONDS_RE = re.compile(
    r"^(?P<sign>[+-]?)(?P<whole>\d+)(?:\.(?P<fraction>\d{1,9}))?$"
)


class TimeSourceError(RuntimeError):
    """Raised when a specifically requested clock observation cannot be made."""


@dataclass(frozen=True, slots=True)
class ClockObservation:
    recorded_at: str
    clock_source: str
    clock_assurance: ClockAssurance


def _system_now_ns() -> int:
    return time.time_ns()


def _format_unix_ns_utc(value_ns: int) -> str:
    if type(value_ns) is not int:
        raise TypeError("UTC nanoseconds must be an integer")
    seconds, nanoseconds = divmod(value_ns, _NANOSECONDS_PER_SECOND)
    value = datetime.fromtimestamp(seconds, tz=timezone.utc)
    microseconds = nanoseconds // 1_000
    return value.strftime("%Y-%m-%dT%H:%M:%S") + f".{microseconds:06d}Z"


def _parse_decimal_seconds_to_ns(value: str) -> int:
    match = _DECIMAL_SECONDS_RE.fullmatch(value)
    if match is None:
        raise TimeSourceError(
            f"time offset is not an exact decimal with at most 9 fractional digits: {value!r}"
        )
    whole = int(match.group("whole"), 10)
    fraction = (match.group("fraction") or "").ljust(9, "0")
    nanoseconds = whole * _NANOSECONDS_PER_SECOND + int(fraction or "0", 10)
    if match.group("sign") == "-":
        nanoseconds = -nanoseconds
    return nanoseconds


def _median_ns(values: list[int]) -> int:
    if not values:
        raise ValueError("median requires at least one value")
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]

    total = ordered[midpoint - 1] + ordered[midpoint]
    # Exact integer arithmetic. If the mathematical midpoint lies on a
    # half-nanosecond, truncate toward zero rather than introducing float state.
    if total >= 0:
        return total // 2
    return -((-total) // 2)


def _format_offset_ns(value_ns: int) -> str:
    sign = "+" if value_ns >= 0 else "-"
    magnitude = abs(value_ns)
    seconds, nanoseconds = divmod(magnitude, _NANOSECONDS_PER_SECOND)
    return f"{sign}{seconds}.{nanoseconds:09d}s"


def system_clock_observation() -> ClockObservation:
    return ClockObservation(
        recorded_at=_format_unix_ns_utc(_system_now_ns()),
        clock_source="system-clock",
        clock_assurance=ClockAssurance.LOCAL,
    )


def _run(
    argv: list[str],
    *,
    timeout: int,
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
    timeout: int = 3,
) -> ClockObservation:
    """Inspect an already-running local chrony daemon; do not initiate NTP."""

    if shutil.which("chronyc") is None:
        raise TimeSourceError("chronyc is not installed")

    sources = _run(["chronyc", "-n", "sources"], timeout=timeout)
    match = _SELECTED_RE.search(sources)
    if match is None:
        raise TimeSourceError("chrony has no selected synchronization source")

    mode_marker, selected = match.groups()
    tracking = _run(["chronyc", "-n", "tracking"], timeout=timeout)
    leap = _LEAP_RE.search(tracking)
    if leap is None or leap.group(1) != "Normal":
        raise TimeSourceError("chrony selected source is not in normal leap status")

    if mode_marker == "#":
        return ClockObservation(
            recorded_at=_format_unix_ns_utc(_system_now_ns()),
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
        recorded_at=_format_unix_ns_utc(_system_now_ns()),
        clock_source=f"chrony:{selected}{suffix}",
        clock_assurance=assurance,
    )


def ntpdate_clock_observation(
    server: str = "pool.ntp.org",
    *,
    timeout: int = 5,
) -> ClockObservation:
    """Explicit opt-in query-only network observation using existing ntpdate."""

    if not isinstance(server, str) or not server or any(
        char.isspace() for char in server
    ):
        raise ValueError("NTP server must be one non-empty hostname/address token")
    if shutil.which("ntpdate") is None:
        raise TimeSourceError("ntpdate is not installed")

    output = _run(["ntpdate", "-q", server], timeout=timeout)
    samples = _SERVER_OFFSET_RE.findall(output)
    if not samples:
        samples = _SUMMARY_OFFSET_RE.findall(output)
    if not samples:
        raise TimeSourceError("ntpdate returned no parseable offset")

    offsets_ns = [_parse_decimal_seconds_to_ns(item) for item in samples]
    offset_ns = _median_ns(offsets_ns)
    observed_ns = _system_now_ns() + offset_ns

    return ClockObservation(
        recorded_at=_format_unix_ns_utc(observed_ns),
        clock_source=f"ntpdate:{server};offset={_format_offset_ns(offset_ns)}",
        clock_assurance=ClockAssurance.NETWORK,
    )


def observe_clock(
    *,
    timeout: int = 3,
) -> ClockObservation:
    """Ask the host what time it believes it is; never initiate network I/O."""

    try:
        return chrony_clock_observation(timeout=timeout)
    except TimeSourceError:
        return system_clock_observation()
