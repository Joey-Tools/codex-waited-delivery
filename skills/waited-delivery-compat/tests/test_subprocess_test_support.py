from __future__ import annotations

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


class SubprocessTestSupportTests(unittest.TestCase):
    def _environment(self, root: Path) -> dict[str, str]:
        return {
            "HOME": str(root),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

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

            def wait(self):
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

            def reap(self, process) -> int:
                self.assert_not_reaped()
                self.assert_process(process)
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

        def group_exists(pgid: int) -> bool:
            observer.assert_not_reaped()
            self.assertEqual(pgid, observer.pid)
            events.append("prove-group-absence")
            return False

        with (
            mock.patch.object(support, "_drain_once"),
            mock.patch.object(
                support,
                "_process_group_exists",
                side_effect=group_exists,
            ),
        ):
            support._bounded_cleanup(
                FakeProcess(),
                observer,
                FakeSelector(),
                {"stdout": bytearray(), "stderr": bytearray()},
                deadline=time.monotonic() + 1,
                terminate_group=True,
            )

        self.assertEqual(
            events,
            ["signal", "observe-exit", "prove-group-absence", "reap"],
        )

    def test_observer_refuses_group_signal_after_reap(self) -> None:
        observer = object.__new__(support._UnreapedLeaderObserver)
        observer.pid = 733
        observer._reaped = True

        with (
            mock.patch.object(support.os, "killpg") as killpg,
            self.assertRaisesRegex(
                AssertionError,
                "after leader reap",
            ),
        ):
            observer.signal_group(signal.SIGKILL)

        killpg.assert_not_called()

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
