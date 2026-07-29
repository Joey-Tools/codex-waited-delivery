from __future__ import annotations

import os
from pathlib import Path
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
    ) -> None:
        process_dir = proc_root / str(pid)
        process_dir.mkdir(parents=True)
        (process_dir / "stat").write_text(
            f"{pid} (fixture ) name) {state} 1 {process_group} 1 0\n",
            encoding="utf-8",
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
            stat_path.write_text(
                "ambiguous\n",
                encoding="utf-8",
            )
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


if __name__ == "__main__":
    unittest.main()
