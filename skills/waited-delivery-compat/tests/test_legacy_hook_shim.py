from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from _subprocess_test_support import run_before_stdin_eof


LEGACY_ADAPTER = (
    Path(__file__).resolve().parents[3]
    / "legacy-hook-shims"
    / "waited-delivery"
    / "scripts"
    / "waited_delivery_hook_adapter.py"
)
HISTORICAL_TARGET_ADAPTER = (
    Path(__file__).resolve().parents[3]
    / "skills"
    / "waited-delivery"
    / "scripts"
    / "waited_delivery_hook_adapter.py"
)
LEGACY_RUNNER = LEGACY_ADAPTER.with_name("waited_delivery_runner.py")
HISTORICAL_TARGET_RUNNER = HISTORICAL_TARGET_ADAPTER.with_name(
    "waited_delivery_runner.py"
)
COMPAT_RUNNER = (
    Path(__file__).resolve().parents[1] / "scripts" / "waited_delivery_runner.py"
)


class LegacyHookShimTests(unittest.TestCase):
    def _load_redirect_module(self, redirect: Path):
        spec = importlib.util.spec_from_file_location(
            "waited_delivery_legacy_redirect_test_module",
            redirect,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to load waited-delivery legacy redirect")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _invoke_registered_hook(
        self,
        adapter: Path,
        *,
        root: Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "HOME": str(root),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return subprocess.run(
            [
                sys.executable,
                str(adapter),
                "stop-hook",
                "--enable-compat-hook",
            ],
            check=False,
            cwd=root,
            env=environment,
            input="{not valid hook JSON\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )

    def _assert_inert(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "{}\n")
        self.assertEqual(completed.stderr, "")

    def _invoke_runner(
        self,
        runner: Path,
        *args: str,
        root: Path,
        umask: int = -1,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "HOME": str(root),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return subprocess.run(
            [sys.executable, str(runner), *args],
            check=False,
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            umask=umask,
        )

    def test_legacy_paths_are_identical_and_not_discoverable_skills(self) -> None:
        legacy_asset_root = LEGACY_ADAPTER.parents[1]
        historical_target_root = HISTORICAL_TARGET_ADAPTER.parents[1]

        self.assertTrue(LEGACY_ADAPTER.is_file())
        self.assertTrue(HISTORICAL_TARGET_ADAPTER.is_file())
        self.assertTrue(LEGACY_RUNNER.is_file())
        self.assertTrue(HISTORICAL_TARGET_RUNNER.is_file())
        self.assertEqual(
            LEGACY_ADAPTER.read_bytes(),
            HISTORICAL_TARGET_ADAPTER.read_bytes(),
        )
        self.assertEqual(
            LEGACY_RUNNER.read_bytes(),
            HISTORICAL_TARGET_RUNNER.read_bytes(),
        )
        self.assertEqual(
            LEGACY_ADAPTER.stat().st_mode & 0o777,
            HISTORICAL_TARGET_ADAPTER.stat().st_mode & 0o777,
        )
        self.assertTrue(os.access(HISTORICAL_TARGET_ADAPTER, os.X_OK))
        self.assertTrue(os.access(LEGACY_RUNNER, os.X_OK))
        self.assertTrue(os.access(HISTORICAL_TARGET_RUNNER, os.X_OK))
        self.assertFalse((legacy_asset_root / "SKILL.md").exists())
        self.assertFalse((historical_target_root / "SKILL.md").exists())
        self.assertNotIn("skills", legacy_asset_root.parts[-2:])

    def test_legacy_runner_paths_redirect_to_packaged_compat_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            expected = self._invoke_runner(COMPAT_RUNNER, "--help", root=root)
            self.assertEqual(expected.returncode, 0, expected.stderr)
            for runner in (LEGACY_RUNNER, HISTORICAL_TARGET_RUNNER):
                with self.subTest(runner=runner):
                    completed = self._invoke_runner(runner, "--help", root=root)
                    self.assertEqual(completed.returncode, expected.returncode)
                    self.assertEqual(completed.stdout, expected.stdout)
                    self.assertEqual(completed.stderr, expected.stderr)

    def test_legacy_runner_pipe_survives_owner_bit_masking_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            expected = self._invoke_runner(COMPAT_RUNNER, "--help", root=root)
            self.assertEqual(expected.returncode, 0, expected.stderr)
            for runner in (LEGACY_RUNNER, HISTORICAL_TARGET_RUNNER):
                with self.subTest(runner=runner):
                    completed = self._invoke_runner(
                        runner,
                        "--help",
                        root=root,
                        umask=0o777,
                    )
                    self.assertEqual(completed.returncode, expected.returncode)
                    self.assertEqual(completed.stdout, expected.stdout)
                    self.assertEqual(completed.stderr, expected.stderr)

    def test_legacy_runner_pipe_writer_and_exec_failures_are_reaped(self) -> None:
        for runner in (LEGACY_RUNNER, HISTORICAL_TARGET_RUNNER):
            with self.subTest(runner=runner, failure="writer"):
                module = self._load_redirect_module(runner)
                with mock.patch.object(
                    module.os,
                    "write",
                    side_effect=OSError("injected writer failure"),
                ):
                    read_fd, writer_pid = module._runner_source_pipe(
                        b"raise SystemExit(0)\n"
                    )
                try:
                    self.assertTrue(stat.S_ISFIFO(os.fstat(read_fd).st_mode))
                    self.assertEqual(os.read(read_fd, 1), b"")
                finally:
                    os.close(read_fd)
                waited_pid, writer_status = os.waitpid(writer_pid, 0)
                self.assertEqual(waited_pid, writer_pid)
                self.assertTrue(os.WIFEXITED(writer_status))
                self.assertEqual(os.WEXITSTATUS(writer_status), 126)

            with self.subTest(runner=runner, failure="exec"):
                module = self._load_redirect_module(runner)
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        module,
                        "_stable_runner_source",
                        return_value=b"raise SystemExit(0)\n",
                    ),
                    mock.patch.object(
                        module.os,
                        "execv",
                        side_effect=OSError("injected exec failure"),
                    ),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(module.main(), 126)
                self.assertIn("injected exec failure", stderr.getvalue())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(-1, os.WNOHANG)

    def test_legacy_runner_executes_pipe_bytes_after_target_symlink_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            redirect = (
                root
                / "legacy-hook-shims"
                / "waited-delivery"
                / "scripts"
                / "waited_delivery_runner.py"
            )
            redirect.parent.mkdir(parents=True)
            shutil.copy2(LEGACY_RUNNER, redirect)
            compat_runner = (
                root
                / "skills"
                / "waited-delivery-compat"
                / "scripts"
                / "waited_delivery_runner.py"
            )
            compat_runner.parent.mkdir(parents=True)
            compat_runner.write_text(
                "\n".join(
                    [
                        "import json",
                        "import sys",
                        'print(json.dumps({"kind": "original", "file": __file__, "argv": sys.argv}))',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            canonical_compat_runner = compat_runner.resolve()
            malicious_runner = root / "malicious_runner.py"
            malicious_runner.write_text(
                'print(\'{"kind":"malicious"}\')\n',
                encoding="utf-8",
            )
            module = self._load_redirect_module(redirect)

            class ExecIntercept(BaseException):
                def __init__(
                    self,
                    completed: subprocess.CompletedProcess[str],
                ) -> None:
                    super().__init__()
                    self.completed = completed

            def intercept_exec(
                _executable: str,
                arguments: list[str],
            ) -> None:
                compat_runner.unlink()
                compat_runner.symlink_to(malicious_runner)
                self.assertEqual(arguments[1:5], ["-I", "-B", "-S", "-c"])
                source_fd = int(arguments[7])
                self.assertTrue(stat.S_ISFIFO(os.fstat(source_fd).st_mode))
                self.assertNotIn("/dev/fd/", " ".join(arguments))
                self.assertNotIn("/proc/self/fd/", " ".join(arguments))
                environment = os.environ.copy()
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                completed = subprocess.run(
                    arguments,
                    check=False,
                    cwd=root,
                    env=environment,
                    pass_fds=(source_fd,),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                raise ExecIntercept(completed)

            with (
                mock.patch.object(
                    module.sys,
                    "argv",
                    [
                        str(redirect),
                        "record-phase",
                        "--marker",
                        "value",
                    ],
                ),
                mock.patch.object(
                    module.os,
                    "execv",
                    side_effect=intercept_exec,
                ),
                self.assertRaises(ExecIntercept) as raised,
            ):
                module.main()

            completed = raised.exception.completed
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["kind"], "original")
            self.assertEqual(payload["file"], str(canonical_compat_runner))
            self.assertEqual(
                payload["argv"],
                [
                    str(canonical_compat_runner),
                    "record-phase",
                    "--marker",
                    "value",
                ],
            )

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
                    for adapter in (LEGACY_ADAPTER, HISTORICAL_TARGET_ADAPTER):
                        completed = subprocess.run(
                            [sys.executable, str(adapter), *arguments],
                            check=False,
                            cwd=root,
                            env=environment,
                            input="{not valid hook JSON\n",
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=5,
                        )
                        self._assert_inert(completed)
                    self.assertEqual(list(root.iterdir()), [])

    def test_direct_repo_link_keeps_registered_legacy_hook_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            installed_skills = root / ".codex" / "skills"
            installed_skills.mkdir(parents=True)
            (installed_skills / "waited-delivery").symlink_to(
                HISTORICAL_TARGET_ADAPTER.parents[1],
                target_is_directory=True,
            )
            registered_adapter = (
                installed_skills
                / "waited-delivery"
                / "scripts"
                / "waited_delivery_hook_adapter.py"
            )

            self._assert_inert(
                self._invoke_registered_hook(registered_adapter, root=root)
            )
            self.assertFalse(
                (installed_skills / "waited-delivery" / "SKILL.md").exists()
            )

    def test_aggregate_and_overlay_installations_preserve_legacy_contract(
        self,
    ) -> None:
        for profile in ("aggregate", "overlay"):
            with self.subTest(profile=profile):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    release_source = (
                        root
                        / profile
                        / "personal_codex"
                        / "legacy-hook-shims"
                        / "waited-delivery"
                    )
                    shutil.copytree(
                        LEGACY_ADAPTER.parents[1],
                        release_source,
                    )
                    compat_source = (
                        root
                        / profile
                        / "personal_codex"
                        / "skills"
                        / "waited-delivery-compat"
                    )
                    (compat_source / "scripts").mkdir(parents=True)
                    shutil.copy2(
                        COMPAT_RUNNER,
                        compat_source / "scripts" / COMPAT_RUNNER.name,
                    )
                    installed_target = root / "home" / ".codex" / "skills"
                    installed_target.mkdir(parents=True)
                    (installed_target / "waited-delivery").symlink_to(
                        release_source,
                        target_is_directory=True,
                    )
                    registered_adapter = (
                        installed_target
                        / "waited-delivery"
                        / "scripts"
                        / "waited_delivery_hook_adapter.py"
                    )
                    registered_runner = registered_adapter.with_name(
                        "waited_delivery_runner.py"
                    )

                    self._assert_inert(
                        self._invoke_registered_hook(registered_adapter, root=root)
                    )
                    expected = self._invoke_runner(
                        compat_source / "scripts" / COMPAT_RUNNER.name,
                        "--help",
                        root=root,
                    )
                    redirected = self._invoke_runner(
                        registered_runner,
                        "--help",
                        root=root,
                    )
                    self.assertEqual(redirected.returncode, expected.returncode)
                    self.assertEqual(redirected.stdout, expected.stdout)
                    self.assertEqual(redirected.stderr, expected.stderr)
                    self.assertFalse((release_source / "SKILL.md").exists())

    def test_removed_link_retirement_stays_two_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            release_target = (
                root
                / "release"
                / "personal_codex"
                / "legacy-hook-shims"
                / "waited-delivery"
            )
            shutil.copytree(
                LEGACY_ADAPTER.parents[1],
                release_target,
            )
            installed_target = root / "home" / ".codex" / "skills"
            installed_target.mkdir(parents=True)
            legacy_link = installed_target / "waited-delivery"
            legacy_link.symlink_to(release_target, target_is_directory=True)
            registered_adapter = (
                legacy_link / "scripts" / "waited_delivery_hook_adapter.py"
            )
            registered_runner = registered_adapter.with_name(
                "waited_delivery_runner.py"
            )
            migrate_active_skill = {
                "id": "migrate-waited-delivery-to-inert-shim",
                "source": "personal_codex/skills/waited-delivery",
                "target": "skills/waited-delivery",
                "kind": "skill",
                "replacement_target": "skills/waited-delivery",
            }
            retire_inert_shim = {
                "id": "retire-waited-delivery-inert-shim",
                "source": "personal_codex/legacy-hook-shims/waited-delivery",
                "target": "skills/waited-delivery",
                "kind": "directory",
                "replacement_target": "skills/change-delivery-workflow",
            }
            phase_one_manifest = {
                "links": [
                    {
                        "source": retire_inert_shim["source"],
                        "target": retire_inert_shim["target"],
                        "kind": retire_inert_shim["kind"],
                    }
                ],
                "removed_links": [migrate_active_skill],
            }
            phase_two_manifest = {
                "links": [],
                "removed_links": [
                    migrate_active_skill,
                    retire_inert_shim,
                ],
            }

            effective_hook_commands = [str(registered_adapter)]
            active_legacy_run_commands = [str(registered_runner)]
            self.assertTrue(effective_hook_commands)
            self.assertTrue(active_legacy_run_commands)
            self.assertEqual(
                phase_one_manifest["links"][0]["target"],
                "skills/waited-delivery",
            )
            self.assertEqual(
                phase_one_manifest["removed_links"],
                [migrate_active_skill],
            )
            self._assert_inert(
                self._invoke_registered_hook(registered_adapter, root=root)
            )
            self.assertTrue(legacy_link.exists())

            effective_hook_commands.clear()
            self.assertEqual(effective_hook_commands, [])
            self.assertTrue(active_legacy_run_commands)
            self.assertTrue(legacy_link.exists())
            active_legacy_run_commands.clear()
            self.assertEqual(phase_two_manifest["links"], [])
            self.assertEqual(
                phase_two_manifest["removed_links"],
                [migrate_active_skill, retire_inert_shim],
            )
            legacy_link.unlink()
            self.assertFalse(legacy_link.exists())

    def test_legacy_shim_exits_before_stdin_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            environment = {
                "HOME": str(root),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            for adapter in (LEGACY_ADAPTER, HISTORICAL_TARGET_ADAPTER):
                completed = run_before_stdin_eof(
                    [
                        sys.executable,
                        str(adapter),
                        "stop-hook",
                        "--enable-compat-hook",
                    ],
                    cwd=root,
                    env=environment,
                    # Keep the writer open with zero bytes so even read(1) blocks.
                    input_text="",
                )
                self._assert_inert(completed)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
