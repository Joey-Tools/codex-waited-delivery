from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

from _subprocess_test_support import run_before_stdin_eof


class SubprocessTestSupportTests(unittest.TestCase):
    def _environment(self, root: Path) -> dict[str, str]:
        return {
            "HOME": str(root),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

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
            producer = root / "spawn-pipe-holder.py"
            producer.write_text(
                textwrap.dedent(
                    """\
                    import pathlib
                    import subprocess
                    import sys
                    import time

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

            with self.assertRaisesRegex(
                AssertionError,
                "left a child in its process group",
            ):
                run_before_stdin_eof(
                    [sys.executable, str(producer), str(child_pid_path)],
                    cwd=root,
                    env=self._environment(root),
                    input_text="",
                    timeout=3,
                )

            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)


if __name__ == "__main__":
    unittest.main()
