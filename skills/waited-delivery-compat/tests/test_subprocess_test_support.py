from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

import _subprocess_test_support as support
from _subprocess_test_support import run_before_stdin_eof


class _FakeCFunction:
    def __init__(self, callback):
        self._callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self._callback(*args)


class SubprocessTestSupportTests(unittest.TestCase):
    def _environment(self, root: Path) -> dict[str, str]:
        return {
            "HOME": str(root),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def _discard_recovery_process(self, process: object) -> None:
        support._UNREAPED_RECOVERY_PROCESSES[:] = [
            candidate
            for candidate in support._UNREAPED_RECOVERY_PROCESSES
            if candidate is not process
        ]

    def _write_proc_stat(
        self,
        proc_root: Path,
        *,
        pid: int,
        state: str,
        process_group: int,
        comm: bytes = b"fixture ) name",
    ) -> None:
        process_dir = proc_root / str(pid)
        process_dir.mkdir(parents=True)
        (process_dir / "stat").write_bytes(
            str(pid).encode("ascii")
            + b" ("
            + comm
            + b") "
            + state.encode("ascii")
            + b" 1 "
            + str(process_group).encode("ascii")
            + b" 1 0\n"
        )

    def test_darwin_proc_scan_treats_list_result_as_pid_count_and_zombies(
        self,
    ) -> None:
        process_group = 801
        listed_pids = (801, 802)
        inspected: list[tuple[int, int, int]] = []

        def list_group(pgid, pid_array, buffer_size):
            self.assertEqual(pgid, process_group)
            self.assertEqual(buffer_size, ctypes.sizeof(pid_array))
            for index, pid in enumerate(listed_pids):
                pid_array[index] = pid
            return len(listed_pids)

        def pid_info(pid, flavor, argument, info_pointer, info_size):
            inspected.append((pid, flavor, argument))
            self.assertEqual(info_size, ctypes.sizeof(support._DarwinProcBSDInfo))
            info = ctypes.cast(
                info_pointer,
                ctypes.POINTER(support._DarwinProcBSDInfo),
            ).contents
            info.pbi_pid = pid
            info.pbi_pgid = process_group
            info.pbi_status = 5
            return ctypes.sizeof(info)

        class FakeLibproc:
            proc_listpgrppids = _FakeCFunction(list_group)
            proc_pidinfo = _FakeCFunction(pid_info)

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=FakeLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "zombie-only",
            )

        self.assertEqual(
            inspected,
            [(801, 3, 1), (802, 3, 1)],
        )

    def test_darwin_proc_scan_ignores_only_attested_leader_stale_status(
        self,
    ) -> None:
        process_group = 806
        listed_pids = [process_group]

        def list_group(_pgid, pid_array, _buffer_size):
            for index, pid in enumerate(listed_pids):
                pid_array[index] = pid
            return len(listed_pids)

        def pid_info(pid, _flavor, _argument, info_pointer, info_size):
            info = ctypes.cast(
                info_pointer,
                ctypes.POINTER(support._DarwinProcBSDInfo),
            ).contents
            info.pbi_pid = pid
            info.pbi_pgid = process_group
            info.pbi_status = 2
            return info_size

        class FakeLibproc:
            proc_listpgrppids = _FakeCFunction(list_group)
            proc_pidinfo = _FakeCFunction(pid_info)

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=FakeLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    max_entries=8,
                ),
                "live",
            )
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "zombie-only",
            )
            listed_pids.append(process_group + 1)
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "live",
            )

    def test_darwin_proc_scan_fails_closed_on_libproc_permission_errors(
        self,
    ) -> None:
        process_group = 811

        def list_denied(_pgid, _pid_array, _buffer_size):
            ctypes.set_errno(errno.EPERM)
            return 0

        class ListDeniedLibproc:
            proc_listpgrppids = _FakeCFunction(list_denied)
            proc_pidinfo = _FakeCFunction(
                lambda *_args: self.fail("pid info must not run")
            )

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=ListDeniedLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "unknown",
            )

        def list_leader(_pgid, pid_array, _buffer_size):
            pid_array[0] = process_group
            return 1

        def pid_info_denied(_pid, _flavor, _argument, _info, _info_size):
            ctypes.set_errno(errno.EPERM)
            return 0

        class PidInfoDeniedLibproc:
            proc_listpgrppids = _FakeCFunction(list_leader)
            proc_pidinfo = _FakeCFunction(pid_info_denied)

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=PidInfoDeniedLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "unknown",
            )

    def test_darwin_proc_scan_uses_only_known_leader_esrch_as_zombie(
        self,
    ) -> None:
        process_group = 821

        def list_leader(_pgid, pid_array, _buffer_size):
            pid_array[0] = process_group
            return 1

        def missing_pid(_pid, flavor, argument, _info, _info_size):
            self.assertEqual((flavor, argument), (3, 1))
            ctypes.set_errno(errno.ESRCH)
            return 0

        class MissingLeaderLibproc:
            proc_listpgrppids = _FakeCFunction(list_leader)
            proc_pidinfo = _FakeCFunction(missing_pid)

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=MissingLeaderLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    max_entries=8,
                ),
                "unknown",
            )
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "zombie-only",
            )

        def list_descendant(_pgid, pid_array, _buffer_size):
            pid_array[0] = process_group + 1
            return 1

        class MissingDescendantLibproc:
            proc_listpgrppids = _FakeCFunction(list_descendant)
            proc_pidinfo = _FakeCFunction(missing_pid)

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=MissingDescendantLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=8,
                ),
                "unknown",
            )

    def test_darwin_proc_scan_treats_full_pid_buffer_as_unknown(self) -> None:
        process_group = 831

        def full_group(_pgid, pid_array, _buffer_size):
            pid_array[0] = process_group
            pid_array[1] = process_group + 1
            return 2

        pid_info = _FakeCFunction(
            lambda *_args: self.fail("a full PID list must not be inspected")
        )

        class FullGroupLibproc:
            proc_listpgrppids = _FakeCFunction(full_group)
            proc_pidinfo = pid_info

        with mock.patch.object(
            support.ctypes,
            "CDLL",
            return_value=FullGroupLibproc(),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    max_entries=2,
                ),
                "unknown",
            )

    def test_darwin_proc_scan_stops_when_libproc_crosses_deadline(self) -> None:
        process_group = 832

        def list_group(_pgid, pid_array, _buffer_size):
            pid_array[0] = process_group
            return 1

        pid_info = _FakeCFunction(
            lambda *_args: self.fail("deadline must stop before proc_pidinfo")
        )

        class SlowListLibproc:
            proc_listpgrppids = _FakeCFunction(list_group)
            proc_pidinfo = pid_info

        with (
            mock.patch.object(
                support.ctypes,
                "CDLL",
                return_value=SlowListLibproc(),
            ),
            mock.patch.object(
                support.time,
                "monotonic",
                side_effect=[0.0, 0.0, 2.0],
            ),
        ):
            self.assertEqual(
                support._darwin_process_group_state(
                    process_group,
                    known_exited_leader_pid=process_group,
                    deadline=1.0,
                    max_entries=8,
                ),
                "unknown",
            )

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin kqueue and libproc",
    )
    def test_real_darwin_unreaped_leader_is_reported_as_zombie(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(0.05)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
        observer: support._UnreapedLeaderObserver | None = None
        try:
            observer = support._UnreapedLeaderObserver(
                process.pid,
                platform="darwin",
            )
            deadline = time.monotonic() + 3
            while not observer.exited():
                if time.monotonic() >= deadline:
                    self.fail("Darwin child did not become an unreaped zombie")
                time.sleep(0.01)

            self.assertEqual(
                support._darwin_process_group_state(
                    process.pid,
                    known_exited_leader_pid=process.pid,
                ),
                "zombie-only",
            )
            observer.reap(
                process,
                timeout=max(0.001, deadline - time.monotonic()),
            )
        finally:
            if observer is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)
            elif not observer._reaped:
                cleanup_deadline = time.monotonic() + 1
                if not observer.exited():
                    observer.signal_group(signal.SIGKILL)
                while not observer.exited() and time.monotonic() < cleanup_deadline:
                    time.sleep(0.01)
                if observer.exited():
                    observer.reap(
                        process,
                        timeout=max(
                            0.001,
                            cleanup_deadline - time.monotonic(),
                        ),
                    )
                observer.close()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_linux_proc_scan_classifies_zombie_only_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_root = Path(temp_dir)
            self._write_proc_stat(
                proc_root,
                pid=201,
                state="Z",
                process_group=77,
            )
            self._write_proc_stat(
                proc_root,
                pid=202,
                state="Z",
                process_group=77,
            )
            self._write_proc_stat(
                proc_root,
                pid=203,
                state="S",
                process_group=88,
            )

            self.assertEqual(
                support._linux_process_group_state(77, proc_root=proc_root),
                "zombie-only",
            )
            with mock.patch.object(support.os, "killpg", return_value=None):
                self.assertFalse(
                    support._process_group_exists(
                        77,
                        proc_root=proc_root,
                        platform="linux",
                    )
                )

    def test_linux_proc_scan_keeps_real_live_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_root = Path(temp_dir)
            self._write_proc_stat(
                proc_root,
                pid=301,
                state="Z",
                process_group=91,
            )
            self._write_proc_stat(
                proc_root,
                pid=302,
                state="S",
                process_group=91,
            )

            self.assertEqual(
                support._linux_process_group_state(91, proc_root=proc_root),
                "live",
            )
            with mock.patch.object(support.os, "killpg", return_value=None):
                self.assertTrue(
                    support._process_group_exists(
                        91,
                        proc_root=proc_root,
                        platform="linux",
                    )
                )

    def test_linux_proc_scan_handles_non_utf8_process_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_root = Path(temp_dir)
            self._write_proc_stat(
                proc_root,
                pid=351,
                state="Z",
                process_group=95,
                comm=b"same \xff zombie",
            )
            self._write_proc_stat(
                proc_root,
                pid=352,
                state="S",
                process_group=96,
                comm=b"unrelated \xfe live",
            )

            self.assertEqual(
                support._linux_process_group_state(95, proc_root=proc_root),
                "zombie-only",
            )
            self._write_proc_stat(
                proc_root,
                pid=353,
                state="S",
                process_group=95,
                comm=b"same \xfd live",
            )
            self.assertEqual(
                support._linux_process_group_state(95, proc_root=proc_root),
                "live",
            )

    def test_linux_proc_scan_deadline_unreadable_and_ambiguity_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_root = Path(temp_dir)
            self._write_proc_stat(
                proc_root,
                pid=401,
                state="Z",
                process_group=101,
            )
            self.assertEqual(
                support._linux_process_group_state(
                    101,
                    proc_root=proc_root,
                    deadline=time.monotonic() - 1,
                ),
                "unknown",
            )

            stat_path = proc_root / "401" / "stat"
            stat_path.unlink()
            stat_path.mkdir()
            self.assertEqual(
                support._linux_process_group_state(101, proc_root=proc_root),
                "unknown",
            )
            stat_path.rmdir()
            stat_path.write_bytes(b"ambiguous\n")
            self.assertEqual(
                support._linux_process_group_state(101, proc_root=proc_root),
                "unknown",
            )
            stat_path.write_bytes(b"401 (fixture) \xff 1 101 1 0\n")
            self.assertEqual(
                support._linux_process_group_state(101, proc_root=proc_root),
                "unknown",
            )
            with mock.patch.object(support.os, "killpg", return_value=None):
                self.assertTrue(
                    support._process_group_exists(
                        101,
                        proc_root=proc_root,
                        platform="linux",
                    )
                )

    def test_linux_proc_scan_iteration_error_fails_closed(self) -> None:
        class FailingProcEntries:
            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                raise OSError("injected proc iteration failure")

        with mock.patch.object(
            support.os,
            "scandir",
            side_effect=lambda _root: FailingProcEntries(),
        ):
            self.assertEqual(
                support._linux_process_group_state(111),
                "unknown",
            )
            with mock.patch.object(support.os, "killpg", return_value=None):
                self.assertTrue(
                    support._process_group_exists(
                        111,
                        platform="linux",
                    )
                )

    def test_cleanup_signals_and_proves_group_absence_before_leader_reap(
        self,
    ) -> None:
        events: list[str] = []

        class FakeProcess:
            pid = 731

            def wait(self, *, timeout):
                raise AssertionError("observer owns the only reap")

        class FakeObserver:
            pid = 731
            reaped = False

            def signal_group(self, signum: int) -> None:
                self.assert_not_reaped()
                self.assert_signal(signum)
                events.append("signal")

            def exited(self) -> bool:
                self.assert_not_reaped()
                events.append("observe-exit")
                return True

            def reap(self, process, *, timeout: float) -> int:
                self.assert_not_reaped()
                self.assert_process(process)
                if timeout <= 0:
                    raise AssertionError("cleanup used an unbounded reap")
                events.append("reap")
                self.reaped = True
                return 0

            def assert_not_reaped(self) -> None:
                if self.reaped:
                    raise AssertionError("operation occurred after leader reap")

            def assert_signal(self, signum: int) -> None:
                if signum != signal.SIGKILL:
                    raise AssertionError("cleanup used an unexpected signal")

            def assert_process(self, process) -> None:
                if process.pid != self.pid:
                    raise AssertionError("cleanup reaped an unrelated process")

        class FakeSelector:
            def get_map(self):
                return {}

        observer = FakeObserver()

        def group_state(pgid: int, **kwargs: object) -> str:
            observer.assert_not_reaped()
            self.assertEqual(pgid, observer.pid)
            self.assertEqual(
                kwargs.get("known_exited_leader_pid"),
                observer.pid,
            )
            events.append("prove-group-absence")
            return "no-members"

        with (
            mock.patch.object(support, "_drain_once"),
            mock.patch.object(
                support,
                "_process_group_state",
                side_effect=group_state,
            ),
        ):
            support._bounded_cleanup(
                FakeProcess(),
                observer,
                FakeSelector(),
                {"stdout": bytearray(), "stderr": bytearray()},
                deadline=time.monotonic() + 1,
                platform="linux",
            )

        self.assertEqual(
            events,
            ["signal", "observe-exit", "prove-group-absence", "reap"],
        )

    def test_cleanup_deadline_never_reaps_and_retains_process_fence(self) -> None:
        events: list[str] = []

        class FakeProcess:
            pid = 732

            def wait(self, *, timeout):
                raise AssertionError("timed-out cleanup must not wait")

        class FakeObserver:
            pid = 732

            def signal_group(self, signum: int) -> None:
                self_outer.assertEqual(signum, signal.SIGKILL)
                events.append("signal")

            def exited(self) -> bool:
                events.append("observe-exit")
                return True

            def reap(self, process, *, timeout: float) -> int:
                raise AssertionError("timed-out cleanup must not reap")

        class FakeSelector:
            def get_map(self):
                return {}

        self_outer = self
        process = FakeProcess()
        self.addCleanup(self._discard_recovery_process, process)
        with (
            mock.patch.object(support, "_drain_once"),
            mock.patch.object(
                support,
                "_process_group_state",
                side_effect=lambda *_args, **_kwargs: "no-members",
            ) as group_state,
            self.assertRaisesRegex(
                AssertionError,
                "remains unreaped and retained for recovery",
            ),
        ):
            support._bounded_cleanup(
                process,
                FakeObserver(),
                FakeSelector(),
                {"stdout": bytearray(), "stderr": bytearray()},
                deadline=time.monotonic() - 1,
                platform="linux",
            )

        self.assertEqual(events, ["signal"])
        group_state.assert_not_called()
        self.assertTrue(
            any(
                candidate is process
                for candidate in support._UNREAPED_RECOVERY_PROCESSES
            )
        )

    def test_observer_refuses_group_signal_after_reap(self) -> None:
        observer = object.__new__(support._UnreapedLeaderObserver)
        observer.pid = 733
        observer._reaped = True

        with (
            mock.patch.object(support.os, "killpg") as killpg,
            mock.patch.object(support.os, "waitid", create=True) as waitid,
        ):
            with self.assertRaisesRegex(AssertionError, "after leader reap"):
                observer.signal_group(signal.SIGKILL)
            with self.assertRaisesRegex(AssertionError, "already reaped"):
                observer.exited()

        killpg.assert_not_called()
        waitid.assert_not_called()

    def test_nondefault_sigchld_preflight_precedes_resource_creation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(
                    support.signal,
                    "getsignal",
                    return_value=signal.SIG_IGN,
                ),
                mock.patch.object(support.selectors, "DefaultSelector") as selector,
                mock.patch.object(support.os, "pipe") as pipe,
                mock.patch.object(support.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    AssertionError,
                    "default SIGCHLD disposition",
                ),
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        selector.assert_not_called()
        pipe.assert_not_called()
        popen.assert_not_called()

    def test_non_cpython_preflight_precedes_resource_creation(self) -> None:
        implementation = mock.Mock()
        implementation.name = "pypy"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(support.sys, "implementation", implementation),
                mock.patch.object(support.selectors, "DefaultSelector") as selector,
                mock.patch.object(support.os, "pipe") as pipe,
                mock.patch.object(support.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    AssertionError,
                    "reviewed CPython Popen finalizer semantics",
                ),
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        selector.assert_not_called()
        pipe.assert_not_called()
        popen.assert_not_called()

    def test_native_no_cldwait_preflight_precedes_all_supervision_resources(
        self,
    ) -> None:
        payload = support.run_native_no_cldwait_preflight_probe(
            Path(support.__file__).resolve(),
            entrypoint="support",
        )

        self.assertTrue(payload["auto_reaped"])
        self.assertTrue(payload["restored_waitable"])
        self.assertIn("SA_NOCLDWAIT", payload["rejection"])
        self.assertEqual(
            payload["calls"],
            {
                "killpg": 0,
                "kqueue": 0,
                "pipe": 0,
                "popen": 0,
                "selector": 0,
            },
        )

    def test_native_no_cldwait_flags_fail_closed_for_both_supported_layouts(
        self,
    ) -> None:
        if ctypes.sizeof(ctypes.c_void_p) == 8 and ctypes.sizeof(ctypes.c_ulong) == 8:
            self.assertEqual(ctypes.sizeof(support._LinuxSigaction), 152)
            self.assertEqual(support._LinuxSigaction.handler.offset, 0)
            self.assertEqual(support._LinuxSigaction.mask.offset, 8)
            self.assertEqual(support._LinuxSigaction.flags.offset, 136)
            self.assertEqual(support._LinuxSigaction.restorer.offset, 144)
        cases = (
            (
                "darwin",
                "_darwin_sigchld_action",
                support._DARWIN_SA_NOCLDWAIT,
            ),
            (
                "linux",
                "_linux_sigchld_action",
                support._LINUX_SA_NOCLDWAIT,
            ),
        )
        for platform_name, action_name, no_cldwait_flag in cases:
            with self.subTest(platform=platform_name):
                with (
                    mock.patch.object(
                        support.signal,
                        "getsignal",
                        return_value=signal.SIG_DFL,
                    ),
                    mock.patch.object(
                        support,
                        action_name,
                        return_value=(0, no_cldwait_flag),
                    ),
                    self.assertRaisesRegex(
                        support._WaitableSigchldUnavailable,
                        "SA_NOCLDWAIT",
                    ),
                ):
                    support._require_waitable_sigchld_semantics(
                        platform=platform_name,
                    )

    def test_unreviewed_linux_sigaction_abi_fails_before_libc(self) -> None:
        rejected_abis = (
            ("x86_64", "x86_64-linux-musl"),
            ("aarch64", "aarch64-linux-musl"),
            ("riscv64", "riscv64-linux-gnu"),
        )
        for machine, multiarch in rejected_abis:
            with self.subTest(machine=machine, multiarch=multiarch):
                implementation = mock.Mock(_multiarch=multiarch)
                with (
                    mock.patch.object(
                        support.os,
                        "uname",
                        return_value=mock.Mock(machine=machine),
                    ),
                    mock.patch.object(
                        support.sys,
                        "implementation",
                        implementation,
                    ),
                    mock.patch.object(support.ctypes, "CDLL") as cdll,
                    self.assertRaisesRegex(
                        support._WaitableSigchldUnavailable,
                        "no reviewed sigaction layout",
                    ),
                ):
                    support._linux_sigchld_action()
                cdll.assert_not_called()

    def test_native_sigaction_query_failure_is_bounded_and_restores_errno(
        self,
    ) -> None:
        def fail_sigaction(*_args: object) -> int:
            ctypes.set_errno(errno.EPERM)
            return -1

        fake_sigaction = _FakeCFunction(fail_sigaction)
        fake_library = mock.Mock(sigaction=fake_sigaction)
        previous_errno = ctypes.get_errno()
        try:
            ctypes.set_errno(errno.EBUSY)
            with (
                mock.patch.object(
                    support.ctypes,
                    "CDLL",
                    return_value=fake_library,
                ),
                self.assertRaisesRegex(
                    support._WaitableSigchldUnavailable,
                    "failed to inspect Darwin SIGCHLD disposition",
                ),
            ):
                support._darwin_sigchld_action()
            self.assertEqual(ctypes.get_errno(), errno.EBUSY)
        finally:
            ctypes.set_errno(previous_errno)

    def test_unexpected_sigchld_query_failure_latches_after_spawn(self) -> None:
        for error_type in (RuntimeError, KeyboardInterrupt):
            with self.subTest(error_type=error_type.__name__):
                query_error = error_type("injected native-query failure")
                with (
                    mock.patch.object(
                        support,
                        "_waitable_sigchld_failure",
                        side_effect=query_error,
                    ),
                    self.assertRaises(support._ProcessIdentityLost) as after_spawn,
                ):
                    support._require_waitable_sigchld_semantics(after_spawn=True)
                self.assertIs(after_spawn.exception.__cause__, query_error)

                pre_spawn_error = error_type("injected pre-spawn native-query failure")
                with (
                    mock.patch.object(
                        support,
                        "_waitable_sigchld_failure",
                        side_effect=pre_spawn_error,
                    ),
                    self.assertRaises(
                        support._WaitableSigchldUnavailable
                    ) as before_spawn,
                ):
                    support._require_waitable_sigchld_semantics()
                self.assertIs(before_spawn.exception.__cause__, pre_spawn_error)

    def test_late_sigchld_loss_blocks_direct_signal_and_group_probe(self) -> None:
        observer = object.__new__(support._UnreapedLeaderObserver)
        observer.pid = 849
        observer.platform = sys.platform
        observer._reaped = False
        observer._exited = False
        observer._kqueue = None

        with (
            mock.patch.object(
                support,
                "_waitable_sigchld_failure",
                return_value="SIGCHLD gained SA_NOCLDWAIT after observer binding",
            ),
            mock.patch.object(support.os, "killpg") as killpg,
        ):
            with self.assertRaises(support._ProcessIdentityLost):
                observer.signal_group(signal.SIGKILL)
            with self.assertRaises(support._ProcessIdentityLost):
                support._process_group_state(849)

        killpg.assert_not_called()

    def test_darwin_observer_ctor_closes_early_kqueue_on_every_failure(
        self,
    ) -> None:
        cases = (
            (
                "post-spawn-reattest",
                support._ProcessIdentityLost("injected identity loss"),
                False,
            ),
            (
                "non-oserror-control",
                RuntimeError("injected control failure"),
                True,
            ),
        )
        for name, expected_error, fail_control in cases:
            with self.subTest(name=name):
                queue = mock.Mock()
                if fail_control:
                    queue.control.side_effect = expected_error
                    require = mock.Mock(return_value=None)
                    queue.close.side_effect = RuntimeError(
                        "injected close failure must not mask primary"
                    )
                else:
                    require = mock.Mock(side_effect=expected_error)
                with (
                    mock.patch.object(
                        support,
                        "_preflight_unreaped_leader_observer",
                        return_value="darwin",
                    ),
                    mock.patch.object(
                        support,
                        "_require_waitable_sigchld_semantics",
                        require,
                    ),
                    mock.patch.object(
                        support.select,
                        "kqueue",
                        return_value=queue,
                        create=True,
                    ),
                    mock.patch.object(
                        support.select,
                        "kevent",
                        return_value=object(),
                        create=True,
                    ),
                    mock.patch.object(support.select, "KQ_FILTER_PROC", 1, create=True),
                    mock.patch.object(support.select, "KQ_EV_ADD", 2, create=True),
                    mock.patch.object(support.select, "KQ_EV_ENABLE", 4, create=True),
                    mock.patch.object(support.select, "KQ_EV_ONESHOT", 8, create=True),
                    mock.patch.object(support.select, "KQ_NOTE_EXIT", 16, create=True),
                    self.assertRaises(type(expected_error)) as raised,
                ):
                    support._UnreapedLeaderObserver(851, platform="darwin")

                self.assertIs(raised.exception, expected_error)
                queue.close.assert_called_once_with()
                if fail_control:
                    queue.control.assert_called_once()
                else:
                    queue.control.assert_not_called()

        expected_error = support._ProcessIdentityLost(
            "injected identity loss after ownership transfer"
        )
        queue = mock.Mock()
        queue.control.return_value = []
        queue.close.side_effect = RuntimeError(
            "injected transferred-close failure must not mask primary"
        )
        require = mock.Mock(side_effect=[None, expected_error])
        with (
            mock.patch.object(
                support,
                "_preflight_unreaped_leader_observer",
                return_value="darwin",
            ),
            mock.patch.object(
                support,
                "_require_waitable_sigchld_semantics",
                require,
            ),
            mock.patch.object(
                support.select,
                "kqueue",
                return_value=queue,
                create=True,
            ),
            mock.patch.object(
                support.select,
                "kevent",
                return_value=object(),
                create=True,
            ),
            mock.patch.object(support.select, "KQ_FILTER_PROC", 1, create=True),
            mock.patch.object(support.select, "KQ_EV_ADD", 2, create=True),
            mock.patch.object(support.select, "KQ_EV_ENABLE", 4, create=True),
            mock.patch.object(support.select, "KQ_EV_ONESHOT", 8, create=True),
            mock.patch.object(support.select, "KQ_NOTE_EXIT", 16, create=True),
            self.assertRaises(type(expected_error)) as raised,
        ):
            support._UnreapedLeaderObserver(852, platform="darwin")

        self.assertIs(raised.exception, expected_error)
        queue.control.assert_called_once()
        queue.close.assert_called_once_with()

    def test_post_spawn_sigchld_loss_never_signals_or_probes_numeric_group(
        self,
    ) -> None:
        class FakeProcess:
            pid = 847
            stdin = None

            def __init__(self) -> None:
                self.stdout = None
                self.stderr = None
                self.wait = mock.Mock(
                    side_effect=AssertionError("identity loss must never wait")
                )
                self.poll = mock.Mock(
                    side_effect=AssertionError("identity loss must never poll")
                )

        process = FakeProcess()
        support._UNREAPED_RECOVERY_PROCESSES.clear()
        waitability = mock.Mock(
            side_effect=[
                None,
                None,
                "SIGCHLD gained SA_NOCLDWAIT after process launch",
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(
                    support,
                    "_waitable_sigchld_failure",
                    waitability,
                ),
                mock.patch.object(
                    support.subprocess,
                    "Popen",
                    return_value=process,
                ) as popen,
                mock.patch.object(support.os, "killpg") as killpg,
                mock.patch.object(
                    support,
                    "_process_group_state",
                ) as group_state,
                self.assertRaisesRegex(
                    support._ProcessIdentityLost,
                    "changed after process launch",
                ) as raised,
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        popen.assert_called_once()
        killpg.assert_not_called()
        group_state.assert_not_called()
        self.assertIsInstance(raised.exception.__cause__, AssertionError)
        self.assertIn(
            "cleanup-incomplete",
            str(raised.exception.__cause__),
        )
        self.assertIn("status is unavailable", str(raised.exception.__cause__))
        process.wait.assert_not_called()
        process.poll.assert_not_called()
        self.assertIn(process, support._UNREAPED_RECOVERY_PROCESSES)

    def test_post_spawn_sigchld_query_failure_preserves_nested_cause(
        self,
    ) -> None:
        class FakeProcess:
            pid = 848
            stdin = None

            def __init__(self) -> None:
                self.stdout = None
                self.stderr = None
                self.wait = mock.Mock(
                    side_effect=AssertionError("identity loss must never wait")
                )
                self.poll = mock.Mock(
                    side_effect=AssertionError("identity loss must never poll")
                )

        process = FakeProcess()
        query_error = KeyboardInterrupt("injected SIGCHLD query interruption")
        support._UNREAPED_RECOVERY_PROCESSES.clear()
        waitability = mock.Mock(side_effect=[None, None, query_error])
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(
                    support,
                    "_waitable_sigchld_failure",
                    waitability,
                ),
                mock.patch.object(
                    support.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(support.os, "killpg") as killpg,
                mock.patch.object(
                    support,
                    "_process_group_state",
                ) as group_state,
                self.assertRaises(support._ProcessIdentityLost) as raised,
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        cleanup_evidence = raised.exception.__cause__
        self.assertIsInstance(cleanup_evidence, AssertionError)
        self.assertIs(cleanup_evidence.__cause__, query_error)
        killpg.assert_not_called()
        group_state.assert_not_called()
        process.wait.assert_not_called()
        process.poll.assert_not_called()
        self.assertIn(process, support._UNREAPED_RECOVERY_PROCESSES)

    def test_identity_loss_disarms_real_popen_finalizer(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "raise SystemExit(0)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        waited_pid, _status = os.waitpid(process.pid, 0)
        self.assertEqual(waited_pid, process.pid)
        self.assertIsNone(process.returncode)

        support._UNREAPED_RECOVERY_PROCESSES.clear()
        cleanup_error = support._identity_loss_cleanup_error(
            process,
            support._ProcessIdentityLost("injected identity loss"),
            context="real-Popen finalizer regression",
        )

        self.assertIn("numeric-child polling disarmed", str(cleanup_error))
        self.assertEqual(process.returncode, support._IDENTITY_LOST_RETURN_CODE)
        self.assertIs(process._child_created, False)
        self.assertIn(process, support._UNREAPED_RECOVERY_PROCESSES)

        support._UNREAPED_RECOVERY_PROCESSES.clear()
        object.__setattr__(process, "returncode", None)
        object.__setattr__(process, "_child_created", True)
        real_disarm = support._disarm_process_after_identity_loss
        attempts = 0

        def interrupt_first_disarm(candidate) -> None:
            nonlocal attempts
            attempts += 1
            self.assertIn(candidate, support._UNREAPED_RECOVERY_PROCESSES)
            if attempts == 1:
                raise KeyboardInterrupt("injected disarm interruption")
            real_disarm(candidate)

        with mock.patch.object(
            support,
            "_disarm_process_after_identity_loss",
            side_effect=interrupt_first_disarm,
        ):
            retry_error = support._identity_loss_cleanup_error(
                process,
                support._ProcessIdentityLost("injected retry identity loss"),
                context="retention-before-disarm regression",
            )

        self.assertEqual(attempts, 2)
        self.assertIn(
            "safety retries=disarm:KeyboardInterrupt",
            str(retry_error),
        )
        self.assertEqual(process.returncode, support._IDENTITY_LOST_RETURN_CODE)
        self.assertIs(process._child_created, False)
        self._discard_recovery_process(process)
        internal_poll = mock.Mock(
            side_effect=AssertionError("disarmed finalizer must not poll")
        )
        object.__setattr__(process, "_internal_poll", internal_poll)
        process.__del__()
        internal_poll.assert_not_called()

    def test_identity_loss_sentinel_survives_retain_interrupt_and_pin_fallback(
        self,
    ) -> None:
        class FakeProcess:
            pid = 853
            stdin = None
            stdout = None
            stderr = None

        process = FakeProcess()
        support._UNREAPED_RECOVERY_PROCESSES.clear()
        real_retain = support._retain_unreaped_process
        retain_attempts = 0

        def interrupt_first_retain(candidate) -> None:
            nonlocal retain_attempts
            retain_attempts += 1
            self.assertEqual(
                candidate.returncode,
                support._IDENTITY_LOST_RETURN_CODE,
            )
            if retain_attempts == 1:
                raise KeyboardInterrupt("injected retain interruption")
            real_retain(candidate)

        with mock.patch.object(
            support,
            "_retain_unreaped_process",
            side_effect=interrupt_first_retain,
        ):
            cleanup_error = support._identity_loss_cleanup_error(
                process,
                support._ProcessIdentityLost("injected identity loss"),
                context="sentinel-before-retain regression",
            )

        self.assertEqual(retain_attempts, 2)
        self.assertIn("retain:KeyboardInterrupt", str(cleanup_error))
        self.assertIn(process, support._UNREAPED_RECOVERY_PROCESSES)

        class UndisarmableProcess:
            __slots__ = ("pid", "stdin", "stdout", "stderr")

            def __init__(self, pid: int) -> None:
                self.pid = pid
                self.stdin = None
                self.stdout = None
                self.stderr = None

        support._UNREAPED_RECOVERY_PROCESSES.clear()
        undisarmable = UndisarmableProcess(854)
        with (
            mock.patch.object(
                support,
                "_disarm_process_after_identity_loss",
                side_effect=RuntimeError("injected disarm failure"),
            ),
            mock.patch.object(
                support,
                "_permanently_pin_process_after_identity_loss",
            ) as pin,
        ):
            pinned_error = support._identity_loss_cleanup_error(
                undisarmable,
                support._ProcessIdentityLost("injected identity loss"),
                context="permanent-pin fallback",
            )
        pin.assert_called_once_with(undisarmable)
        self.assertIn("permanently pinned", str(pinned_error))

        fatal = UndisarmableProcess(855)
        with (
            mock.patch.object(
                support,
                "_disarm_process_after_identity_loss",
                side_effect=RuntimeError("injected disarm failure"),
            ),
            mock.patch.object(
                support,
                "_permanently_pin_process_after_identity_loss",
                side_effect=RuntimeError("injected pin failure"),
            ) as pin,
            mock.patch.object(
                support.os,
                "_exit",
                side_effect=SystemExit(70),
            ) as fatal_exit,
            self.assertRaises(SystemExit),
        ):
            support._identity_loss_cleanup_error(
                fatal,
                support._ProcessIdentityLost("injected identity loss"),
                context="fatal safety fallback",
            )
        self.assertEqual(pin.call_count, 2)
        fatal_exit.assert_called_once_with(70)

    def test_final_cleanup_cannot_mask_primary_baseexception(self) -> None:
        resource = mock.Mock()
        resource.close.side_effect = KeyboardInterrupt(
            "injected final cleanup interruption"
        )
        primary = support._ProcessIdentityLost("identity-lost primary")

        with self.assertRaises(type(primary)) as raised:
            try:
                raise primary
            finally:
                support._best_effort_close_resource(resource)

        self.assertIs(raised.exception, primary)
        resource.close.assert_called_once_with()

    def test_darwin_primitive_preflight_precedes_process_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(support.sys, "platform", "darwin"),
                mock.patch.object(support, "select", object()),
                mock.patch.object(support.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    AssertionError,
                    "requires kqueue NOTE_EXIT",
                ),
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        popen.assert_not_called()

    def test_linux_waitid_preflight_precedes_process_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(support.sys, "platform", "linux"),
                mock.patch.object(support.os, "waitid", None, create=True),
                mock.patch.object(support.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    AssertionError,
                    "Linux process supervision requires waitid",
                ),
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        popen.assert_not_called()

    def test_unsupported_platform_preflight_precedes_process_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(support.sys, "platform", "freebsd14"),
                mock.patch.object(support.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    AssertionError,
                    "unsupported on platform freebsd14",
                ),
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                )

        popen.assert_not_called()

    def test_observer_constructor_failure_uses_ordered_bounded_cleanup(
        self,
    ) -> None:
        class ObserverBindError(RuntimeError):
            pass

        stdout_read_fd, stdout_write_fd = os.pipe()
        stderr_read_fd, stderr_write_fd = os.pipe()
        os.close(stdout_write_fd)
        os.close(stderr_write_fd)
        input_read_fd, input_write_fd = os.pipe()
        stdout = os.fdopen(stdout_read_fd, "rb", buffering=0)
        stderr = os.fdopen(stderr_read_fd, "rb", buffering=0)
        events: list[str] = []
        cleanup_deadlines: list[float] = []
        real_close = os.close

        class FakeProcess:
            pid = 841
            reaped = False

            def __init__(self):
                self.stdout = stdout
                self.stderr = stderr

            def wait(self, *, timeout):
                if self.reaped:
                    raise AssertionError("process was reaped twice")
                if timeout is None or timeout <= 0:
                    raise AssertionError("observer cleanup used an unbounded wait")
                events.append("bounded-wait")
                self.reaped = True
                return -signal.SIGKILL

        process = FakeProcess()
        observer_error = ObserverBindError("injected observer bind failure")

        def kill_group(pgid: int, signum: int) -> None:
            if process.reaped:
                raise AssertionError("signal occurred after emergency reap")
            self.assertEqual((pgid, signum), (process.pid, signal.SIGKILL))
            events.append("signal-group")

        def tracked_close(fd: int) -> None:
            if fd == input_write_fd:
                events.append("close-input")
            real_close(fd)

        def group_state(pgid: int, **kwargs: object) -> str:
            if process.reaped:
                raise AssertionError("group probe occurred after emergency reap")
            self.assertEqual(pgid, process.pid)
            cleanup_deadlines.append(kwargs["deadline"])  # type: ignore[arg-type]
            events.append("prove-group-state")
            return "no-members"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            started_at = time.monotonic()
            with (
                mock.patch.object(
                    support,
                    "_preflight_unreaped_leader_observer",
                    return_value="linux",
                ) as preflight,
                mock.patch.object(
                    support.subprocess,
                    "Popen",
                    return_value=process,
                ) as popen,
                mock.patch.object(
                    support.os,
                    "pipe",
                    return_value=(input_read_fd, input_write_fd),
                ),
                mock.patch.object(
                    support.os,
                    "close",
                    side_effect=tracked_close,
                ),
                mock.patch.object(
                    support,
                    "_UnreapedLeaderObserver",
                    side_effect=observer_error,
                ) as observer_ctor,
                mock.patch.object(
                    support.os,
                    "killpg",
                    side_effect=kill_group,
                ),
                mock.patch.object(
                    support,
                    "_process_group_state",
                    side_effect=group_state,
                ),
                self.assertRaises(ObserverBindError) as caught,
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                    timeout=0.5,
                )

        self.assertIs(caught.exception, observer_error)
        self.assertIsNone(caught.exception.__cause__)
        preflight.assert_called_once_with()
        observer_ctor.assert_called_once_with(process.pid, platform="linux")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(
            events,
            [
                "signal-group",
                "close-input",
                "prove-group-state",
                "bounded-wait",
            ],
        )
        self.assertEqual(len(cleanup_deadlines), 1)
        self.assertGreater(cleanup_deadlines[0], started_at)
        self.assertLessEqual(cleanup_deadlines[0], started_at + 0.6)
        self.assertFalse(
            any(
                candidate is process
                for candidate in support._UNREAPED_RECOVERY_PROCESSES
            )
        )

    def test_observer_constructor_cleanup_failure_retains_original_primary(
        self,
    ) -> None:
        class ObserverBindError(RuntimeError):
            pass

        stdout_read_fd, stdout_write_fd = os.pipe()
        stderr_read_fd, stderr_write_fd = os.pipe()
        stdout = os.fdopen(stdout_read_fd, "rb", buffering=0)
        stderr = os.fdopen(stderr_read_fd, "rb", buffering=0)
        wait_calls: list[float] = []
        events: list[str] = []
        cleanup_deadlines: list[float] = []

        class FakeProcess:
            pid = 851

            def __init__(self):
                self.stdout = stdout
                self.stderr = stderr

            def wait(self, *, timeout):
                wait_calls.append(timeout)
                raise AssertionError("incomplete cleanup must not reap")

        process = FakeProcess()
        self.addCleanup(self._discard_recovery_process, process)
        observer_error = ObserverBindError("injected observer bind failure")

        def kill_group(pgid: int, signum: int) -> None:
            self.assertEqual((pgid, signum), (process.pid, signal.SIGKILL))
            events.append("signal-group")

        def group_state(pgid: int, **kwargs: object) -> str:
            self.assertEqual(pgid, process.pid)
            cleanup_deadlines.append(kwargs["deadline"])  # type: ignore[arg-type]
            events.append("group-state-unknown")
            return "unknown"

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                started_at = time.monotonic()
                with (
                    mock.patch.object(
                        support,
                        "_preflight_unreaped_leader_observer",
                        return_value="linux",
                    ),
                    mock.patch.object(
                        support.subprocess,
                        "Popen",
                        return_value=process,
                    ),
                    mock.patch.object(
                        support,
                        "_UnreapedLeaderObserver",
                        side_effect=observer_error,
                    ),
                    mock.patch.object(
                        support.os,
                        "killpg",
                        side_effect=kill_group,
                    ),
                    mock.patch.object(
                        support,
                        "_process_group_state",
                        side_effect=group_state,
                    ),
                    self.assertRaises(ObserverBindError) as caught,
                ):
                    run_before_stdin_eof(
                        [sys.executable, "-c", "raise SystemExit(0)"],
                        cwd=root,
                        env=self._environment(root),
                        input_text="",
                        timeout=0.08,
                    )
        finally:
            os.close(stdout_write_fd)
            os.close(stderr_write_fd)

        self.assertIs(caught.exception, observer_error)
        self.assertIsInstance(caught.exception.__cause__, AssertionError)
        self.assertIn(
            "emergency cleanup did not complete before its hard deadline",
            str(caught.exception.__cause__),
        )
        self.assertEqual(events[0], "signal-group")
        self.assertGreater(len(cleanup_deadlines), 0)
        self.assertEqual(len(set(cleanup_deadlines)), 1)
        self.assertGreater(cleanup_deadlines[0], started_at)
        self.assertLessEqual(cleanup_deadlines[0], started_at + 0.2)
        self.assertEqual(wait_calls, [])
        self.assertTrue(
            any(
                candidate is process
                for candidate in support._UNREAPED_RECOVERY_PROCESSES
            )
        )

    def test_normal_cleanup_failure_keeps_original_exception_primary(
        self,
    ) -> None:
        class PrimaryError(RuntimeError):
            pass

        class CleanupError(RuntimeError):
            pass

        stdout_read_fd, stdout_write_fd = os.pipe()
        stderr_read_fd, stderr_write_fd = os.pipe()
        os.close(stdout_write_fd)
        os.close(stderr_write_fd)
        stdout = os.fdopen(stdout_read_fd, "rb", buffering=0)
        stderr = os.fdopen(stderr_read_fd, "rb", buffering=0)

        class FakeProcess:
            pid = 861

            def __init__(self):
                self.stdout = stdout
                self.stderr = stderr

            def wait(self, *, timeout):
                raise AssertionError("fake process must not be reaped")

        class FakeObserver:
            def exited(self) -> bool:
                raise primary_error

            def close(self) -> None:
                pass

        process = FakeProcess()
        primary_error = PrimaryError("injected monitor failure")
        cleanup_error = CleanupError("injected cleanup failure")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(
                    support,
                    "_preflight_unreaped_leader_observer",
                    return_value="linux",
                ),
                mock.patch.object(
                    support.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    support,
                    "_UnreapedLeaderObserver",
                    return_value=FakeObserver(),
                ),
                mock.patch.object(
                    support,
                    "_bounded_cleanup",
                    side_effect=cleanup_error,
                ) as cleanup,
                self.assertRaises(PrimaryError) as caught,
            ):
                run_before_stdin_eof(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                    timeout=0.5,
                )

        self.assertIs(caught.exception, primary_error)
        self.assertIs(caught.exception.__cause__, cleanup_error)
        cleanup.assert_called_once()

    def test_selector_initialization_failure_precedes_pipe_and_process_launch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with mock.patch.object(
                support.selectors,
                "DefaultSelector",
                side_effect=OSError("selector unavailable"),
            ):
                with mock.patch.object(
                    support.os,
                    "pipe",
                    wraps=support.os.pipe,
                ) as pipe:
                    with mock.patch.object(
                        support.subprocess,
                        "Popen",
                        wraps=support.subprocess.Popen,
                    ) as popen:
                        with self.assertRaisesRegex(
                            OSError,
                            "selector unavailable",
                        ):
                            run_before_stdin_eof(
                                [sys.executable, "-c", "raise SystemExit(0)"],
                                cwd=root,
                                env=self._environment(root),
                                input_text="",
                            )

            pipe.assert_not_called()
            popen.assert_not_called()

    def test_empty_open_stdin_blocks_a_single_byte_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            reader = root / "read-one-byte.py"
            reader.write_text(
                textwrap.dedent(
                    """\
                    import sys

                    sys.stdin.buffer.read(1)
                    print("unexpected read completion")
                    """
                ),
                encoding="utf-8",
            )
            started_at = time.monotonic()

            with self.assertRaisesRegex(
                AssertionError,
                "did not exit while the stdin writer remained open",
            ):
                run_before_stdin_eof(
                    [sys.executable, str(reader)],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                    timeout=1.5,
                )

            self.assertLess(time.monotonic() - started_at, 2.0)

    def test_large_payload_cannot_block_before_child_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            child = root / "ignore-stdin.py"
            child.write_text(
                'print("child started")\n',
                encoding="utf-8",
            )
            probe = root / "large-payload-probe.py"
            support_dir = Path(__file__).resolve().parent
            probe.write_text(
                textwrap.dedent(
                    f"""\
                    import os
                    from pathlib import Path
                    import sys

                    sys.path.insert(0, {str(support_dir)!r})
                    from _subprocess_test_support import run_before_stdin_eof

                    root = Path(sys.argv[1])
                    completed = run_before_stdin_eof(
                        [sys.executable, str(root / "ignore-stdin.py")],
                        cwd=root,
                        env={{
                            **os.environ,
                            "PYTHONDONTWRITEBYTECODE": "1",
                        }},
                        input_text="x" * (4 * 1024 * 1024),
                        timeout=2,
                    )
                    if completed.returncode != 0:
                        raise SystemExit(completed.returncode)
                    print(completed.stdout, end="")
                    """
                ),
                encoding="utf-8",
            )
            env = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            started_at = time.monotonic()

            completed = subprocess.run(
                [sys.executable, str(probe), str(root)],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=5,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "child started\n")
            self.assertLess(time.monotonic() - started_at, 4.0)

    def test_descendant_held_pipes_are_killed_before_failure_returns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            child_pid_path = root / "child.pid"
            process_group_path = root / "process-group.pid"
            producer = root / "spawn-pipe-holder.py"
            producer.write_text(
                textwrap.dedent(
                    """\
                    import os
                    import pathlib
                    import subprocess
                    import sys
                    import time

                    pathlib.Path(sys.argv[2]).write_text(
                        str(os.getpgrp()),
                        encoding="utf-8",
                    )
                    child_code = '''
                    import os
                    import pathlib
                    import sys
                    import time

                    pathlib.Path(sys.argv[1]).write_text(
                        str(os.getpid()),
                        encoding="utf-8",
                    )
                    print("child inherited parent pipes", flush=True)
                    time.sleep(2)
                    '''
                    subprocess.Popen(
                        [sys.executable, "-c", child_code, sys.argv[1]],
                    )
                    marker = pathlib.Path(sys.argv[1])
                    deadline = time.monotonic() + 2
                    while not marker.exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("child did not publish its pid")
                        time.sleep(0.01)
                    print("{}")
                    """
                ),
                encoding="utf-8",
            )

            started_at = time.monotonic()
            with self.assertRaisesRegex(
                AssertionError,
                "left a child in its process group",
            ):
                run_before_stdin_eof(
                    [
                        sys.executable,
                        str(producer),
                        str(child_pid_path),
                        str(process_group_path),
                    ],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                    timeout=3,
                )

            process_group = int(process_group_path.read_text(encoding="utf-8"))
            self.assertFalse(support._process_group_exists(process_group))
            self.assertLess(time.monotonic() - started_at, 3.5)

    def test_cleanup_reaps_child_when_proc_iteration_fails(self) -> None:
        class FailingProcEntries:
            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                raise OSError("injected cleanup proc iteration failure")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            child_pid_path = root / "child.pid"
            child = root / "sleep-after-pid.py"
            child.write_text(
                textwrap.dedent(
                    """\
                    import os
                    import pathlib
                    import sys
                    import time

                    pathlib.Path(sys.argv[1]).write_text(
                        str(os.getpid()),
                        encoding="utf-8",
                    )
                    time.sleep(60)
                    """
                ),
                encoding="utf-8",
            )
            real_killpg = os.killpg
            zero_probes = 0

            def controlled_killpg(process_group: int, sig: int) -> None:
                nonlocal zero_probes
                if sig == 0:
                    zero_probes += 1
                    if zero_probes == 1:
                        return
                    raise ProcessLookupError
                real_killpg(process_group, sig)

            with (
                mock.patch.object(
                    support.os,
                    "scandir",
                    side_effect=lambda _root: FailingProcEntries(),
                ),
                mock.patch.object(
                    support.os,
                    "killpg",
                    side_effect=controlled_killpg,
                ),
                self.assertRaisesRegex(
                    AssertionError,
                    "did not exit while the stdin writer remained open",
                ),
            ):
                run_before_stdin_eof(
                    [sys.executable, str(child), str(child_pid_path)],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                    timeout=1.5,
                )

            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            if sys.platform.startswith("linux"):
                self.assertGreaterEqual(zero_probes, 2)
            else:
                self.assertEqual(zero_probes, 0)


if __name__ == "__main__":
    unittest.main()
