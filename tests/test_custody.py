from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from provenance_core import (
    ClockAssurance,
    CustodyAction,
    CustodyCore,
    CustodyEnvelope,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    sha256_identity,
)
import provenance_custody.ledger as ledger_module
import provenance_custody.time_source as time_module
from provenance_custody import (
    CUSTODY_LEDGER_FORMAT,
    ClockObservation,
    CustodyLedgerError,
    LocalCustodyLedger,
    TimeSourceError,
    chrony_clock_observation,
    ntpdate_clock_observation,
    observe_clock,
)
from provenance_verify import verify_custody_records


def _clock(
    timestamp: str = "2026-09-29T00:00:00.000000Z",
    *,
    source: str = "system-clock",
    assurance: ClockAssurance = ClockAssurance.LOCAL,
) -> ClockObservation:
    return ClockObservation(
        recorded_at=timestamp,
        clock_source=source,
        clock_assurance=assurance,
    )


def _custody(
    subject: str,
    action: CustodyAction,
    *,
    previous: str | None = None,
    recorded_at: str = "2026-09-29T00:00:00.000000Z",
    actor: str | None = "test:actor",
    source: str | None = "test:source",
    related_identity: str | None = None,
) -> CustodyEnvelope:
    return CustodyEnvelope.seal(
        CustodyCore(
            subject_identity=subject,
            action=action,
            recorded_at=recorded_at,
            clock_source="system-clock",
            clock_assurance=ClockAssurance.LOCAL,
            actor=actor,
            source=source,
            previous_custody=previous,
            related_identity=related_identity,
        )
    )


class CustodyCoreTests(unittest.TestCase):
    def test_identical_custody_core_has_identical_identity(self) -> None:
        subject = sha256_identity(b"artifact")
        first = _custody(subject, CustodyAction.CAPTURED)
        second = _custody(subject, CustodyAction.CAPTURED)
        self.assertEqual(first.custody_identity, second.custody_identity)

    def test_fixed_v1_custody_identity_fixture(self) -> None:
        record = _custody(
            "sha256:1182aacc53fdf9fbaa29c0cd18a20e6ac7429e3610cc3a381d49a0aef45cf62c",
            CustodyAction.CAPTURED,
            actor="fixture:actor",
            source="fixture:source",
        )
        self.assertEqual(
            record.custody_identity,
            "sha256:845a235957f279bd2e09e52ec4bd9c111d3c1a12a076f9fdab4671abaee92126",
        )

    def test_unknown_actor_and_source_remain_null(self) -> None:
        subject = sha256_identity(b"artifact")
        record = _custody(
            subject,
            CustodyAction.CAPTURED,
            actor=None,
            source=None,
        )
        core = record.to_dict()["core"]
        self.assertIsNone(core["actor"])
        self.assertIsNone(core["source"])

    def test_invalid_timestamp_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "recorded_at"):
            CustodyCore(
                subject_identity=sha256_identity(b"artifact"),
                action=CustodyAction.CAPTURED,
                recorded_at="2026-09-29 00:00:00",
                clock_source="system-clock",
                clock_assurance=ClockAssurance.LOCAL,
            )

    def test_superseded_requires_related_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "related_identity"):
            CustodyCore(
                subject_identity=sha256_identity(b"artifact"),
                action=CustodyAction.SUPERSEDED,
                recorded_at="2026-09-29T00:00:00.000000Z",
                clock_source="system-clock",
                clock_assurance=ClockAssurance.LOCAL,
            )


class CustodyVerifierTests(unittest.TestCase):
    def test_valid_linear_chain_verifies(self) -> None:
        subject = sha256_identity(b"artifact")
        captured = _custody(subject, CustodyAction.CAPTURED)
        stored = _custody(
            subject,
            CustodyAction.STORED,
            previous=captured.custody_identity,
            recorded_at="2026-09-29T00:00:01.000000Z",
        )
        verified = _custody(
            subject,
            CustodyAction.VERIFIED,
            previous=stored.custody_identity,
            recorded_at="2026-09-29T00:00:02.000000Z",
        )

        report = verify_custody_records(
            [
                canonical_json_bytes(captured.to_dict()),
                canonical_json_bytes(stored.to_dict()),
                canonical_json_bytes(verified.to_dict()),
            ]
        )

        self.assertTrue(report.integrity_verified, report.errors)
        self.assertEqual(report.record_count, 3)
        self.assertEqual(dict(report.tips)[subject], verified.custody_identity)

    def test_tampered_action_fails_identity_recomputation(self) -> None:
        subject = sha256_identity(b"artifact")
        record = _custody(subject, CustodyAction.CAPTURED)
        value = parse_canonical_json_bytes(
            canonical_json_bytes(record.to_dict())
        )
        assert isinstance(value, dict)
        core = value["core"]
        assert isinstance(core, dict)
        core["action"] = CustodyAction.STORED.value

        report = verify_custody_records([canonical_json_bytes(value)])

        self.assertFalse(report.integrity_verified)
        self.assertTrue(
            any("identity does not match" in item for item in report.errors),
            report.errors,
        )

    def test_fork_is_rejected(self) -> None:
        subject = sha256_identity(b"artifact")
        root = _custody(subject, CustodyAction.CAPTURED)
        left = _custody(
            subject,
            CustodyAction.STORED,
            previous=root.custody_identity,
            recorded_at="2026-09-29T00:00:01.000000Z",
        )
        right = _custody(
            subject,
            CustodyAction.EXPORTED,
            previous=root.custody_identity,
            recorded_at="2026-09-29T00:00:02.000000Z",
        )

        report = verify_custody_records(
            [
                canonical_json_bytes(root.to_dict()),
                canonical_json_bytes(left.to_dict()),
                canonical_json_bytes(right.to_dict()),
            ]
        )

        self.assertFalse(report.integrity_verified)
        self.assertTrue(
            any("multiple children" in item for item in report.errors),
            report.errors,
        )

    def test_dangling_predecessor_is_rejected(self) -> None:
        subject = sha256_identity(b"artifact")
        record = _custody(
            subject,
            CustodyAction.STORED,
            previous=sha256_identity(b"missing custody"),
        )

        report = verify_custody_records(
            [canonical_json_bytes(record.to_dict())]
        )

        self.assertFalse(report.integrity_verified)
        self.assertTrue(
            any("dangling predecessor" in item for item in report.errors),
            report.errors,
        )

    def test_cross_subject_predecessor_is_rejected(self) -> None:
        first_subject = sha256_identity(b"first")
        second_subject = sha256_identity(b"second")
        first = _custody(first_subject, CustodyAction.CAPTURED)
        second = _custody(
            second_subject,
            CustodyAction.STORED,
            previous=first.custody_identity,
        )

        report = verify_custody_records(
            [
                canonical_json_bytes(first.to_dict()),
                canonical_json_bytes(second.to_dict()),
            ]
        )

        self.assertFalse(report.integrity_verified)
        self.assertTrue(
            any("links across subjects" in item for item in report.errors),
            report.errors,
        )


class ClockObservationTests(unittest.TestCase):
    def test_chrony_nts_selected_source_is_authenticated_network(self) -> None:
        fixed_ns = 1_790_640_000_000_000_000
        commands: list[list[str]] = []

        def run(argv: list[str], *, timeout: int) -> str:
            commands.append(list(argv))
            if argv[-1] == "sources":
                return (
                    "MS Name/IP address Stratum Poll Reach LastRx Last sample\n"
                    "^* 192.0.2.10 2 6 377 10 +1us[+2us] +/- 1ms\n"
                )
            if argv[-1] == "tracking":
                return "Leap status     : Normal\n"
            if "authdata" in argv:
                return (
                    "Name/IP address Mode KeyID Type KLen Last Atmp NAK Cook CLen\n"
                    "192.0.2.10 NTS 1 15 256 1m 0 0 8 100\n"
                )
            raise AssertionError(argv)

        with mock.patch.object(
            time_module.shutil,
            "which",
            return_value="/usr/bin/chronyc",
        ), mock.patch.object(
            time_module,
            "_run",
            side_effect=run,
        ), mock.patch.object(
            time_module,
            "_system_now_ns",
            return_value=fixed_ns,
        ):
            observation = chrony_clock_observation()

        self.assertEqual(
            observation.clock_assurance,
            ClockAssurance.AUTHENTICATED_NETWORK,
        )
        self.assertIn("chrony:192.0.2.10;auth=NTS", observation.clock_source)
        self.assertEqual(
            commands,
            [
                ["chronyc", "-n", "sources"],
                ["chronyc", "-n", "tracking"],
                ["chronyc", "-n", "authdata", "-a"],
            ],
        )

    def test_ntpdate_query_applies_median_offset(self) -> None:
        fixed_ns = 1_790_640_000_000_000_000
        output = "\n".join(
            [
                "server 192.0.2.1, stratum 2, offset -0.002000, delay 0.02",
                "server 192.0.2.2, stratum 2, offset 0.004000, delay 0.03",
                "29 Sep 00:00:00 ntpdate[1]: adjust time server 192.0.2.1 offset 0.001000 sec",
            ]
        )

        with mock.patch.object(
            time_module.shutil,
            "which",
            return_value="/usr/sbin/ntpdate",
        ), mock.patch.object(
            time_module,
            "_run",
            return_value=output,
        ), mock.patch.object(
            time_module,
            "_system_now_ns",
            return_value=fixed_ns,
        ):
            observation = ntpdate_clock_observation("pool.ntp.org")

        self.assertEqual(
            observation.recorded_at,
            "2026-09-29T00:00:00.001000Z",
        )
        self.assertEqual(
            observation.clock_assurance,
            ClockAssurance.NETWORK,
        )
        self.assertIn("offset=+0.001000000s", observation.clock_source)

    def test_auto_clock_never_initiates_ntpdate_network_query(self) -> None:
        fixed_ns = 1_790_640_000_000_000_000

        with mock.patch.object(
            time_module,
            "chrony_clock_observation",
            side_effect=TimeSourceError("no chrony"),
        ), mock.patch.object(
            time_module,
            "ntpdate_clock_observation",
            side_effect=AssertionError("automatic network query is forbidden"),
        ) as ntpdate, mock.patch.object(
            time_module,
            "_system_now_ns",
            return_value=fixed_ns,
        ):
            observation = observe_clock()

        ntpdate.assert_not_called()
        self.assertEqual(observation.clock_assurance, ClockAssurance.LOCAL)
        self.assertEqual(observation.clock_source, "system-clock")
        self.assertEqual(
            observation.recorded_at,
            "2026-09-29T00:00:00.000000Z",
        )

    def test_decimal_offset_parsing_is_exact_integer_nanoseconds(self) -> None:
        self.assertEqual(
            time_module._parse_decimal_seconds_to_ns("-0.002269"),
            -2_269_000,
        )
        self.assertEqual(
            time_module._parse_decimal_seconds_to_ns("+1.000000001"),
            1_000_000_001,
        )
        self.assertEqual(
            time_module._median_ns([-2_000_000, 4_000_000]),
            1_000_000,
        )
        self.assertEqual(
            time_module._format_offset_ns(-2_269_000),
            "-0.002269000s",
        )
        with self.assertRaisesRegex(TimeSourceError, "at most 9"):
            time_module._parse_decimal_seconds_to_ns("0.0000000001")


class LocalCustodyLedgerTests(unittest.TestCase):
    def test_concurrent_first_construction_atomically_publishes_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            barrier = threading.Barrier(2)
            counter_lock = threading.Lock()
            missing_reads = 0
            real_open = os.open
            format_read_flags = ledger_module._file_read_flags()

            def synchronized_open(
                path,
                flags,
                mode=0o777,
                *,
                dir_fd=None,
            ):
                nonlocal missing_reads
                force_missing = False
                if path == ledger_module._FORMAT and flags == format_read_flags:
                    with counter_lock:
                        if missing_reads < 2:
                            missing_reads += 1
                            force_missing = True
                if force_missing:
                    barrier.wait(timeout=10)
                    raise FileNotFoundError(
                        2,
                        "No such file or directory",
                        ledger_module._FORMAT,
                    )
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                ledger_module.os,
                "open",
                side_effect=synchronized_open,
            ):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    ledgers = list(
                        pool.map(
                            lambda _index: LocalCustodyLedger(root),
                            (0, 1),
                        )
                    )

            self.assertEqual(missing_reads, 2)
            self.assertEqual(len(ledgers), 2)
            self.assertEqual(
                (root / ledger_module._FORMAT).read_text(encoding="ascii"),
                CUSTODY_LEDGER_FORMAT + "\n",
            )
            self.assertFalse(
                any(
                    path.name.startswith(
                        f".{ledger_module._FORMAT}."
                    )
                    for path in root.iterdir()
                )
            )
            for ledger in ledgers:
                report = ledger.verify()
                self.assertTrue(report.integrity_verified, report.errors)

    def test_append_reopen_and_verify_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            subject = sha256_identity(b"artifact")
            ledger = LocalCustodyLedger(root)

            captured = ledger.append(
                subject,
                CustodyAction.CAPTURED,
                actor="operator:test",
                source="adapter:test",
                clock=_clock(),
            )
            stored = ledger.append(
                subject,
                CustodyAction.STORED,
                actor=None,
                source="local-store",
                clock=_clock("2026-09-29T00:00:01.000000Z"),
            )
            verified = ledger.append(
                subject,
                CustodyAction.VERIFIED,
                source="provenance-verify",
                clock=_clock("2026-09-29T00:00:02.000000Z"),
            )

            self.assertIsNone(captured.core.previous_custody)
            self.assertEqual(
                stored.core.previous_custody,
                captured.custody_identity,
            )
            self.assertEqual(
                verified.core.previous_custody,
                stored.custody_identity,
            )

            report = ledger.verify()
            self.assertTrue(report.integrity_verified, report.errors)

            reopened = LocalCustodyLedger(root)
            reopened_report = reopened.verify()
            self.assertTrue(reopened_report.integrity_verified)
            self.assertEqual(
                dict(reopened_report.tips)[subject],
                verified.custody_identity,
            )

    def test_two_subjects_keep_independent_tips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = LocalCustodyLedger(Path(tmp) / "custody")
            first = sha256_identity(b"first")
            second = sha256_identity(b"second")

            first_record = ledger.append(
                first,
                CustodyAction.CAPTURED,
                clock=_clock(),
            )
            second_record = ledger.append(
                second,
                CustodyAction.CAPTURED,
                clock=_clock(),
            )

            report = ledger.verify()
            self.assertTrue(report.integrity_verified)
            tips = dict(report.tips)
            self.assertEqual(tips[first], first_record.custody_identity)
            self.assertEqual(tips[second], second_record.custody_identity)

    def test_same_process_instances_serialize_appends_without_fork(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            first = LocalCustodyLedger(root)
            second = LocalCustodyLedger(root)
            subject = sha256_identity(b"threaded subject")
            barrier = threading.Barrier(3)
            results: list[CustodyEnvelope] = []
            errors: list[BaseException] = []

            def worker(
                ledger: LocalCustodyLedger,
                action: CustodyAction,
                timestamp: str,
            ) -> None:
                barrier.wait()
                try:
                    results.append(
                        ledger.append(
                            subject,
                            action,
                            clock=_clock(timestamp),
                        )
                    )
                except BaseException as exc:
                    errors.append(exc)

            threads = [
                threading.Thread(
                    target=worker,
                    args=(
                        first,
                        CustodyAction.CAPTURED,
                        "2026-09-29T00:00:00.000000Z",
                    ),
                ),
                threading.Thread(
                    target=worker,
                    args=(
                        second,
                        CustodyAction.STORED,
                        "2026-09-29T00:00:01.000000Z",
                    ),
                ),
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

            self.assertEqual(errors, [])
            self.assertEqual(len(results), 2)
            report = LocalCustodyLedger(root).verify()
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.record_count, 2)
            self.assertEqual(report.subject_count, 1)
            self.assertIn(dict(report.tips)[subject], {
                item.custody_identity for item in results
            })
            self.assertEqual(
                sum(item.core.previous_custody is None for item in results),
                1,
            )

    def test_reopen_recovers_staging_file_from_crash_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            LocalCustodyLedger(root)
            staging = root / "staging"
            stale = staging / ".orphan.before.json.deadbeef.tmp"
            stale.write_bytes(b"partial crash residue")
            self.assertTrue(stale.exists())

            reopened = LocalCustodyLedger(root)

            self.assertFalse(stale.exists())
            report = reopened.verify()
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.record_count, 0)

    def test_reopen_recovers_staging_file_from_crash_after_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            ledger = LocalCustodyLedger(root)
            subject = sha256_identity(b"published before crash")
            record = ledger.append(
                subject,
                CustodyAction.CAPTURED,
                clock=_clock(),
            )
            record_path = (
                root
                / "records"
                / "sha256"
                / f"{record.custody_identity.split(':', 1)[1]}.json"
            )
            staging = root / "staging"
            stale = staging / ".published.after.json.deadbeef.tmp"
            stale.write_bytes(record_path.read_bytes())
            self.assertTrue(record_path.exists())
            self.assertTrue(stale.exists())

            reopened = LocalCustodyLedger(root)

            self.assertFalse(stale.exists())
            self.assertTrue(record_path.exists())
            report = reopened.verify()
            self.assertTrue(report.integrity_verified, report.errors)
            self.assertEqual(report.record_count, 1)
            self.assertEqual(
                dict(report.tips)[subject],
                record.custody_identity,
            )

    def test_records_directory_remains_strict_about_non_record_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            LocalCustodyLedger(root)
            bad = root / "records" / "sha256" / ".should-not-be-here.tmp"
            bad.write_bytes(b"not authoritative evidence")

            with self.assertRaisesRegex(
                CustodyLedgerError,
                "failed verification",
            ):
                LocalCustodyLedger(root)

    def test_second_instance_open_cannot_release_held_custody_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            ledger = LocalCustodyLedger(root)
            lock_path = root / ".custody.lock"
            ready = Path(tmp) / "child-ready"
            acquired = Path(tmp) / "child-acquired"
            script = (
                "import fcntl, os, pathlib, sys\n"
                "lock_path, ready, acquired = sys.argv[1:4]\n"
                "fd = os.open(lock_path, os.O_RDWR)\n"
                "pathlib.Path(ready).write_text('ready')\n"
                "fcntl.lockf(fd, fcntl.LOCK_EX, 0, 0, os.SEEK_SET)\n"
                "pathlib.Path(acquired).write_text('acquired')\n"
                "fcntl.lockf(fd, fcntl.LOCK_UN, 0, 0, os.SEEK_SET)\n"
                "os.close(fd)\n"
            )
            constructed: list[LocalCustodyLedger] = []
            constructor_errors: list[BaseException] = []
            constructor: threading.Thread | None = None
            child: subprocess.Popen[str] | None = None

            def construct_second() -> None:
                try:
                    constructed.append(LocalCustodyLedger(root))
                except BaseException as exc:
                    constructor_errors.append(exc)

            try:
                with ledger._exclusive_lock():
                    child = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            script,
                            str(lock_path),
                            str(ready),
                            str(acquired),
                        ],
                        text=True,
                    )
                    deadline = time.monotonic() + 3.0
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())

                    constructor = threading.Thread(target=construct_second)
                    constructor.start()
                    time.sleep(0.15)

                    self.assertTrue(constructor.is_alive())
                    self.assertFalse(acquired.exists())
                    self.assertIsNone(child.poll())

                assert constructor is not None
                constructor.join(timeout=5)
                self.assertFalse(constructor.is_alive())
                assert child is not None
                self.assertEqual(child.wait(timeout=5), 0)
            finally:
                if constructor is not None and constructor.is_alive():
                    constructor.join(timeout=5)
                if child is not None and child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)

            self.assertEqual(constructor_errors, [])
            self.assertEqual(len(constructed), 1)
            self.assertTrue(acquired.exists())

    def test_append_uses_posix_record_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = LocalCustodyLedger(Path(tmp) / "custody")
            subject = sha256_identity(b"lock subject")
            real_lockf = ledger_module.fcntl.lockf

            with mock.patch.object(
                ledger_module.fcntl,
                "lockf",
                wraps=real_lockf,
            ) as lockf:
                ledger.append(
                    subject,
                    CustodyAction.CAPTURED,
                    clock=_clock(),
                )

            commands = [call.args[1] for call in lockf.call_args_list]
            self.assertIn(ledger_module.fcntl.LOCK_EX, commands)
            self.assertIn(ledger_module.fcntl.LOCK_UN, commands)

    def test_interrupted_publication_leaves_no_authoritative_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            ledger = LocalCustodyLedger(root)
            subject = sha256_identity(b"artifact")
            real_write = os.write

            def partial_then_fail(fd: int, data: bytes) -> None:
                real_write(fd, data[: max(1, len(data) // 2)])
                raise OSError("injected interruption")

            with mock.patch.object(
                ledger_module,
                "_write_all",
                side_effect=partial_then_fail,
            ):
                with self.assertRaisesRegex(
                    CustodyLedgerError,
                    "temporary write failed",
                ):
                    ledger.append(
                        subject,
                        CustodyAction.CAPTURED,
                        clock=_clock(),
                    )

            records = root / "records" / "sha256"
            staging = root / "staging"
            self.assertEqual(
                [path for path in records.iterdir() if path.suffix == ".json"],
                [],
            )
            self.assertEqual(list(staging.iterdir()), [])

    def test_tampered_record_rejects_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            ledger = LocalCustodyLedger(root)
            subject = sha256_identity(b"artifact")
            record = ledger.append(
                subject,
                CustodyAction.CAPTURED,
                clock=_clock(),
            )
            path = (
                root
                / "records"
                / "sha256"
                / f"{record.custody_identity.split(':', 1)[1]}.json"
            )
            value = parse_canonical_json_bytes(path.read_bytes())
            assert isinstance(value, dict)
            core = value["core"]
            assert isinstance(core, dict)
            core["actor"] = "tampered"
            path.write_bytes(canonical_json_bytes(value))

            with self.assertRaisesRegex(
                CustodyLedgerError,
                "failed verification",
            ):
                LocalCustodyLedger(root)

    def test_format_marker_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custody"
            LocalCustodyLedger(root)
            self.assertEqual(
                (root / "CUSTODY_FORMAT").read_text(encoding="ascii"),
                CUSTODY_LEDGER_FORMAT + "\n",
            )


if __name__ == "__main__":
    unittest.main()
