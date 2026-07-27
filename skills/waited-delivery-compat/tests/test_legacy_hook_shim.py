from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from _subprocess_test_support import run_before_stdin_eof


LEGACY_ADAPTER = (
    Path(__file__).resolve().parents[3]
    / "legacy-hook-shims"
    / "waited-delivery"
    / "scripts"
    / "waited_delivery_hook_adapter.py"
)


class LegacyHookShimTests(unittest.TestCase):
    def test_legacy_path_is_not_a_discoverable_skill(self) -> None:
        legacy_root = LEGACY_ADAPTER.parents[1]

        self.assertTrue(LEGACY_ADAPTER.is_file())
        self.assertFalse((legacy_root / "SKILL.md").exists())
        self.assertNotIn("skills", legacy_root.parts[-2:])

    def test_every_legacy_invocation_is_inert_and_fail_open(self) -> None:
        invocations = (
            (),
            ("user-prompt-submit-hook",),
            ("stop-hook",),
            ("stop-hook", "--enable-compat-hook"),
            ("--malformed", "value"),
        )
        for arguments in invocations:
            with self.subTest(arguments=arguments):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    environment = {
                        "HOME": str(root),
                        "PATH": os.environ.get("PATH", ""),
                        "PYTHONDONTWRITEBYTECODE": "1",
                    }
                    completed = subprocess.run(
                        [sys.executable, str(LEGACY_ADAPTER), *arguments],
                        check=False,
                        cwd=root,
                        env=environment,
                        input="{not valid hook JSON\n",
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                    )

                    self.assertEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout, "{}\n")
                    self.assertEqual(completed.stderr, "")
                    self.assertEqual(list(root.iterdir()), [])

    def test_legacy_shim_exits_before_stdin_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            environment = {
                "HOME": str(root),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            completed = run_before_stdin_eof(
                [
                    sys.executable,
                    str(LEGACY_ADAPTER),
                    "stop-hook",
                    "--enable-compat-hook",
                ],
                cwd=root,
                env=environment,
                input_text="{not valid hook JSON and no EOF",
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "{}\n")
            self.assertEqual(completed.stderr, "")
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
