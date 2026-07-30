"""Compatibility tests for the historical waited-delivery hook adapter."""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import io
import json
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import zlib
from collections.abc import Mapping
from unittest import mock

from _subprocess_test_support import run_before_stdin_eof


ADAPTER_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "waited_delivery_hook_adapter.py"
)
BRIDGE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "waited_delivery_bridge.py"
)
RUNNER_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "waited_delivery_runner.py"
)


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
    )


def git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess[str]:
    return run(["git", "-C", str(repo), *args])


def git_commit(repo: pathlib.Path, message: str) -> None:
    completed = run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ]
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr)


class WaitedDeliveryHookAdapterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="waited-delivery-hook-")
        self.root = pathlib.Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.assertEqual(git(self.repo, "init").returncode, 0)
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        self.assertEqual(git(self.repo, "add", "tracked.txt").returncode, 0)
        git_commit(self.repo, "init")
        (self.repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        self.fake_helper = self.root / "fake_external_helper.py"
        self.fake_helper.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                print("READY")
                """
            ),
            encoding="utf-8",
        )
        self.fake_helper.chmod(0o755)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _run_adapter(
        self,
        *args: str,
        input_payload: dict[str, object] | None = None,
        env_overrides: Mapping[str, str | None] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        input_text = None
        if input_payload is not None:
            input_text = json.dumps(input_payload)
        env = os.environ.copy()
        env.pop("CODEX_THREAD_ID", None)
        if env_overrides:
            for key, value in env_overrides.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = value
        adapter_args = list(args)
        if adapter_args and adapter_args[0] in {
            "user-prompt-submit-hook",
            "stop-hook",
        }:
            adapter_args.insert(1, "--enable-compat-hook")
        return run(
            [sys.executable, str(ADAPTER_PATH), *adapter_args],
            env=env,
            input_text=input_text,
        )

    def _run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run([sys.executable, str(RUNNER_PATH), *args])

    def _commit_implementation(self) -> None:
        self.assertEqual(git(self.repo, "add", "tracked.txt").returncode, 0)
        git_commit(self.repo, "freeze implementation")

    def _finish_child(
        self, run_dir: str, session_id: str, child_session_id: str
    ) -> None:
        completed = self._run_adapter(
            "finish-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            run_dir,
            "--child-status",
            "completed",
            "--child-session-id",
            child_session_id,
            "--session-id",
            session_id,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        record = index["sessions"][session_id]
        self.assertEqual(record["status"], "active")
        self.assertEqual(record["run_dir"], run_dir)

    def test_terminal_commands_require_child_session_id(self) -> None:
        for command in ("finish-child-active-run", "reconcile-active-run"):
            with self.subTest(command=command):
                completed = self._run_adapter(
                    command,
                    "--repo",
                    str(self.repo),
                    "--run-dir",
                    "/tmp/waited-delivery-run",
                    "--child-status",
                    "completed",
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("--child-session-id", completed.stderr)

    def _session_payload(
        self,
        *,
        session_id: str = "session-1",
        prompt: str = "Please use waited delivery",
        transcript_path: str = "/tmp/transcript-1.jsonl",
        permission_mode: str = "acceptEdits",
    ) -> dict[str, object]:
        return {
            "session_id": session_id,
            "transcript_path": transcript_path,
            "cwd": str(self.repo),
            "hook_event_name": "UserPromptSubmit",
            "model": "gpt-5.5",
            "permission_mode": permission_mode,
            "prompt": prompt,
        }

    def _index_path(self) -> pathlib.Path:
        return self.repo / ".codex-tmp" / "waited-delivery-hook-adapter" / "index.json"

    def _prepare_indexed_run(self, session_id: str, run_id: str) -> pathlib.Path:
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                transcript_path=f"/tmp/{session_id}.jsonl",
            ),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        prepared = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            f"Prepare {session_id}",
            "--session-id",
            session_id,
            "--run-id",
            run_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        return pathlib.Path(json.loads(prepared.stdout)["run_dir"])

    def _stop_payload_for(self, session_id: str) -> dict[str, object]:
        return {
            "session_id": session_id,
            "transcript_path": f"/tmp/{session_id}.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "unsafe run probe",
        }

    def _home_log_dir(self, home: pathlib.Path) -> pathlib.Path:
        return home / ".codex" / "log"

    def _load_adapter_module(self, adapter_path: pathlib.Path = ADAPTER_PATH):
        spec = importlib.util.spec_from_file_location(
            "waited_delivery_hook_adapter_test_module", adapter_path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to load waited_delivery_hook_adapter module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _private_launch_sources(
        self,
        label: str,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        source_dir = self.root / f"launch-sources-{label}"
        source_dir.mkdir()
        bridge_path = source_dir / BRIDGE_PATH.name
        runner_path = source_dir / RUNNER_PATH.name
        shutil.copy2(BRIDGE_PATH, bridge_path)
        shutil.copy2(RUNNER_PATH, runner_path)
        return bridge_path.resolve(), runner_path.resolve()

    def _run_identity(self, module, run_dir: pathlib.Path):
        run_stat = run_dir.stat()
        return module.RunDirectoryIdentity(
            device=run_stat.st_dev,
            inode=run_stat.st_ino,
            uid=run_stat.st_uid,
            gid=run_stat.st_gid,
            mode=run_stat.st_mode & 0o7777,
        )

    def _write_proc_stat(
        self,
        proc_root: pathlib.Path,
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

    def test_hook_commands_are_inert_without_explicit_compatibility_flag(
        self,
    ) -> None:
        fake_home = self.root / "home-default-inert"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        index_path = adapter_dir / "index.json"
        index_path.write_text("{legacy invalid json\n", encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(fake_home)
        env.pop("CODEX_THREAD_ID", None)

        payloads = {
            "user-prompt-submit-hook": self._session_payload(
                prompt="sensitive compatibility prompt"
            ),
            "stop-hook": {
                "session_id": "session-1",
                "cwd": str(self.repo),
                "last_assistant_message": "sensitive compatibility response",
            },
        }
        for command, payload in payloads.items():
            with self.subTest(command=command):
                completed = run(
                    [sys.executable, str(ADAPTER_PATH), command],
                    env=env,
                    input_text=json.dumps(payload),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), "{}")
                self.assertEqual(completed.stderr, "")

        self.assertEqual(
            index_path.read_text(encoding="utf-8"),
            "{legacy invalid json\n",
        )
        self.assertFalse((fake_home / ".codex" / "log").exists())

    def test_hook_commands_without_exact_flag_exit_before_stdin_eof(self) -> None:
        fake_home = self.root / "home-open-stdin"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        index_path = adapter_dir / "index.json"
        sentinel = "{legacy invalid json\n"
        index_path.write_text(sentinel, encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(fake_home)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.pop("CODEX_THREAD_ID", None)

        for command in ("user-prompt-submit-hook", "stop-hook"):
            with self.subTest(command=command):
                completed = run_before_stdin_eof(
                    [sys.executable, str(ADAPTER_PATH), command],
                    cwd=self.repo,
                    env=env,
                    # Keep the writer open with zero bytes so even read(1) blocks.
                    input_text="",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, "{}\n")
                self.assertEqual(completed.stderr, "")

        self.assertEqual(index_path.read_text(encoding="utf-8"), sentinel)
        self.assertFalse((fake_home / ".codex" / "log").exists())

    def test_hook_commands_without_exact_flag_are_inert_before_argparse(
        self,
    ) -> None:
        fake_home = self.root / "home-abbreviated-flag"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        index_path = adapter_dir / "index.json"
        sentinel = "{legacy invalid json\n"
        index_path.write_text(sentinel, encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(fake_home)
        env.pop("CODEX_THREAD_ID", None)

        cases = (
            (
                ("user-prompt-submit-hook", "--enable"),
                self._session_payload(
                    prompt="abbreviated flag must not read this prompt"
                ),
            ),
            (
                ("stop-hook", "--unknown"),
                {
                    "session_id": "session-unknown",
                    "cwd": str(self.repo),
                    "last_assistant_message": (
                        "unknown flag must not read this response"
                    ),
                },
            ),
            (
                ("user-prompt-submit-hook", "--repo"),
                self._session_payload(prompt="missing value must not read this prompt"),
            ),
            (
                ("stop-hook", "--enable-compat-hook=true"),
                {
                    "session_id": "session-malformed",
                    "cwd": str(self.repo),
                    "last_assistant_message": (
                        "malformed flag must not read this response"
                    ),
                },
            ),
            (
                ("--enable", "stop-hook"),
                {
                    "session_id": "session-reordered",
                    "cwd": str(self.repo),
                    "last_assistant_message": (
                        "reordered flag must not read this response"
                    ),
                },
            ),
            (
                ("stop-hook", "--help"),
                {
                    "session_id": "session-help",
                    "cwd": str(self.repo),
                    "last_assistant_message": ("help flag must not read this response"),
                },
            ),
            (
                ("--help", "user-prompt-submit-hook"),
                self._session_payload(
                    prompt="reordered help must not read this prompt"
                ),
            ),
        )
        for args, payload in cases:
            with self.subTest(args=args):
                completed = run(
                    [
                        sys.executable,
                        str(ADAPTER_PATH),
                        *args,
                    ],
                    env=env,
                    input_text=json.dumps(payload),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), "{}")
                self.assertEqual(completed.stderr, "")
                self.assertNotIn("must not read", completed.stderr)

        self.assertEqual(index_path.read_text(encoding="utf-8"), sentinel)
        self.assertFalse((fake_home / ".codex" / "log").exists())

    def test_exact_flag_parse_errors_fail_open_without_running_hooks(self) -> None:
        fake_home = self.root / "home-exact-malformed"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        index_path = adapter_dir / "index.json"
        sentinel = "{legacy invalid json\n"
        index_path.write_text(sentinel, encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(fake_home)

        cases = (
            (
                "stop-hook",
                "--enable-compat-hook",
                "--unknown",
            ),
            (
                "user-prompt-submit-hook",
                "--enable-compat-hook",
                "--repo",
            ),
            (
                "--enable-compat-hook",
                "stop-hook",
            ),
        )
        for args in cases:
            with self.subTest(args=args):
                completed = run(
                    [sys.executable, str(ADAPTER_PATH), *args],
                    env=env,
                    input_text=json.dumps(
                        {
                            "session_id": "session-exact-malformed",
                            "cwd": str(self.repo),
                            "last_assistant_message": (
                                "parse errors must not run the hook"
                            ),
                        }
                    ),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), "{}")
                self.assertIn("error:", completed.stderr)

        self.assertEqual(index_path.read_text(encoding="utf-8"), sentinel)
        self.assertFalse((fake_home / ".codex" / "log").exists())

    def test_hook_and_non_hook_help_default_interactions(self) -> None:
        exact_hook_help = run(
            [
                sys.executable,
                str(ADAPTER_PATH),
                "stop-hook",
                "--enable-compat-hook",
                "--help",
            ],
            input_text="help must not read stdin",
        )
        self.assertEqual(exact_hook_help.returncode, 0, exact_hook_help.stderr)
        self.assertIn("--enable-compat-hook", exact_hook_help.stdout)
        self.assertNotEqual(exact_hook_help.stdout.strip(), "{}")

        top_level_help = run(
            [sys.executable, str(ADAPTER_PATH), "--help"],
        )
        self.assertEqual(top_level_help.returncode, 0, top_level_help.stderr)
        self.assertIn("prepare-active-run", top_level_help.stdout)
        self.assertNotEqual(top_level_help.stdout.strip(), "{}")

        no_command = run([sys.executable, str(ADAPTER_PATH)])
        self.assertEqual(no_command.returncode, 2)
        self.assertIn(
            "the following arguments are required: command",
            no_command.stderr,
        )

        non_hook_error = run(
            [
                sys.executable,
                str(ADAPTER_PATH),
                "show-index",
                "--unknown",
            ],
        )
        self.assertEqual(non_hook_error.returncode, 2)
        self.assertIn("error:", non_hook_error.stderr)

    def test_exact_compatibility_flag_activates_hook_commands(self) -> None:
        submit = run(
            [
                sys.executable,
                str(ADAPTER_PATH),
                "user-prompt-submit-hook",
                "--enable-compat-hook",
            ],
            input_text=json.dumps(
                self._session_payload(
                    session_id="session-exact-flag",
                    prompt="exact flag prompt",
                )
            ),
        )
        self.assertEqual(submit.returncode, 0, submit.stderr)
        self.assertEqual(submit.stdout.strip(), "{}")
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertIn("session-exact-flag", index["sessions"])

        fake_home = self.root / "home-exact-flag"
        env = os.environ.copy()
        env["HOME"] = str(fake_home)
        stop = run(
            [
                sys.executable,
                str(ADAPTER_PATH),
                "stop-hook",
                "--enable-compat-hook",
            ],
            env=env,
            input_text="{invalid json\n",
        )
        self.assertEqual(stop.returncode, 0, stop.stderr)
        self.assertEqual(stop.stdout.strip(), "{}")
        log_path = self._home_log_dir(fake_home) / "waited-delivery-hooks.jsonl"
        self.assertTrue(log_path.is_file())
        entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(entry["hook_command"], "stop-hook")
        self.assertEqual(entry["error_type"], "JSONDecodeError")

    def test_terminal_stop_prompts_refuse_missing_child_identity(self) -> None:
        module = self._load_adapter_module()
        run_dir = self.repo / ".codex-tmp" / "waited-delivery" / "damaged-run"
        state = {
            "orchestration": {
                "child_status": "completed",
                "child_session_id": "   ",
            },
            "artifacts": {},
        }
        prompts = [
            module._build_stop_continuation_prompt(self.repo, run_dir, state),
            module._build_stop_fallback_prompt(self.repo, run_dir, state),
            module._build_stop_last_resort_prompt(
                self.repo,
                run_dir,
                child_status="completed",
                child_session_id=None,
            ),
            module._build_stop_emergency_prompt(
                self.repo,
                run_dir,
                child_status="completed",
                child_session_id=None,
            ),
        ]
        for prompt in prompts:
            with self.subTest(prompt=prompt):
                self.assertIn("child_session_id", prompt)
                self.assertNotIn("reconcile-active-run", prompt)

        terminal_state = {
            "overall_status": "passed",
            "orchestration": {
                "child_status": "completed",
                "child_session_id": "   ",
            },
            "phases": {
                phase_name: {"status": "passed"}
                for phase_name in (
                    "tests",
                    "docs_sync",
                    "internal_review",
                    "external_review",
                )
            },
        }
        self.assertFalse(module._run_is_terminal(terminal_state))
        terminal_state["orchestration"]["child_session_id"] = "child-exact"
        self.assertTrue(module._run_is_terminal(terminal_state))
        del terminal_state["phases"]["internal_review"]
        self.assertFalse(module._run_is_terminal(terminal_state))

    def test_emergency_prompt_uses_loaded_adapter_distribution_path(self) -> None:
        layouts = (
            pathlib.Path("skills/waited-delivery-compat"),
            pathlib.Path("personal_codex/skills/waited-delivery-compat"),
        )
        for layout in layouts:
            with self.subTest(layout=layout):
                adapter_path = (
                    self.root
                    / "distribution"
                    / layout
                    / "scripts"
                    / "waited_delivery_hook_adapter.py"
                )
                adapter_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ADAPTER_PATH, adapter_path)
                module = self._load_adapter_module(adapter_path)

                prompt = module._build_stop_emergency_prompt(
                    self.repo,
                    self.repo / ".codex-tmp" / "waited-delivery" / "active-run",
                    child_status="failed",
                    child_session_id="child-emergency",
                )

                command = prompt.split("Run this from the repo root:\n", 1)[1]
                argv = shlex.split(command)
                self.assertEqual(argv[0], sys.executable)
                self.assertEqual(argv[1], str(adapter_path.resolve()))
                self.assertEqual(argv[2], "reconcile-active-run")

    def test_user_prompt_submit_hook_records_session_metadata(self) -> None:
        completed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "{}")
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(index["latest_session_id"], "session-1")
        record = index["sessions"]["session-1"]
        self.assertEqual(record["transcript_path"], "/tmp/transcript-1.jsonl")
        self.assertEqual(record["permission_mode"], "acceptEdits")
        self.assertEqual(record["status"], "observed")
        self.assertIsNone(record["run_dir"])

    def test_user_prompt_submit_hook_does_not_follow_index_symlink(self) -> None:
        adapter_dir = self._index_path().parent
        adapter_dir.mkdir(parents=True, mode=0o700)
        external_index = self.root / "external-index.json"
        sentinel = json.dumps(
            {
                "schema_version": 1,
                "latest_session_id": None,
                "updated_at": None,
                "sessions": {},
            },
            indent=2,
            sort_keys=True,
        )
        external_index.write_text(sentinel, encoding="utf-8")
        self._index_path().symlink_to(external_index)

        completed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                prompt="must not be written through the index symlink"
            ),
            env_overrides={"HOME": str(self.root / "home-index-symlink")},
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "{}")
        self.assertEqual(external_index.read_text(encoding="utf-8"), sentinel)
        self.assertTrue(self._index_path().is_symlink())

    def test_index_storage_is_owner_private_under_open_umask(self) -> None:
        previous_umask = os.umask(0)
        try:
            completed = self._run_adapter(
                "user-prompt-submit-hook",
                input_payload=self._session_payload(
                    session_id="session-private-index",
                    prompt="owner-private prompt",
                ),
            )
        finally:
            os.umask(previous_umask)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        adapter_dir = self._index_path().parent
        lock_path = adapter_dir / "index.lock"
        self.assertEqual(adapter_dir.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(self._index_path().stat().st_mode & 0o7777, 0o600)
        self.assertEqual(lock_path.stat().st_mode & 0o7777, 0o600)
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(
            index["sessions"]["session-private-index"]["last_prompt"],
            "owner-private prompt",
        )

    def test_index_directory_creation_survives_restrictive_umask(self) -> None:
        previous_umask = os.umask(0o777)
        try:
            completed = self._run_adapter(
                "user-prompt-submit-hook",
                input_payload=self._session_payload(
                    session_id="session-restrictive-umask",
                    prompt="persist through restrictive umask",
                ),
            )
        finally:
            os.umask(previous_umask)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        adapter_dir = self._index_path().parent
        self.assertEqual(
            (self.repo / ".codex-tmp").stat().st_mode & 0o7777,
            0o700,
        )
        self.assertEqual(adapter_dir.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(self._index_path().stat().st_mode & 0o7777, 0o600)
        self.assertEqual(
            (adapter_dir / "index.lock").stat().st_mode & 0o7777,
            0o600,
        )
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(
            index["sessions"]["session-restrictive-umask"]["last_prompt"],
            "persist through restrictive umask",
        )

    def test_index_transaction_serializes_load_modify_save(self) -> None:
        seeded = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id="session-seed"),
        )
        self.assertEqual(seeded.returncode, 0, seeded.stderr)
        lock_path = self._index_path().parent / "index.lock"
        lock_fd = os.open(lock_path, os.O_RDWR)
        processes: list[subprocess.Popen[str]] = []
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            for session_id in ("session-race-a", "session-race-b"):
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(ADAPTER_PATH),
                        "user-prompt-submit-hook",
                        "--enable-compat-hook",
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                assert process.stdin is not None
                process.stdin.write(
                    json.dumps(self._session_payload(session_id=session_id))
                )
                process.stdin.close()
                process.stdin = None
                processes.append(process)
            time.sleep(0.2)
            self.assertTrue(all(process.poll() is None for process in processes))
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

        for process in processes:
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout.strip(), "{}")
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(
            set(index["sessions"]),
            {"session-seed", "session-race-a", "session-race-b"},
        )

    def test_index_atomic_save_failure_preserves_previous_snapshot(self) -> None:
        seeded = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id="session-before-failure"),
        )
        self.assertEqual(seeded.returncode, 0, seeded.stderr)
        before = self._index_path().read_bytes()
        module = self._load_adapter_module()

        with (
            mock.patch.object(
                module.os,
                "replace",
                side_effect=OSError("injected replace failure"),
            ),
            self.assertRaises(module.RunSafetyError),
        ):
            with module._index_transaction(self.repo.resolve(), write=True) as index:
                module._update_session_observation(
                    index,
                    session_id="session-after-failure",
                    cwd=str(self.repo),
                    transcript_path=None,
                    permission_mode=None,
                    prompt="must not become visible",
                )

        self.assertEqual(self._index_path().read_bytes(), before)
        self.assertEqual(
            list(self._index_path().parent.glob(".index.json.*.tmp")),
            [],
        )

    def test_refresh_timeout_kills_descendants_and_closes_passed_fds(self) -> None:
        module = self._load_adapter_module()
        script = self.root / "refresh-timeout-tree.py"
        pid_path = self.root / "refresh-timeout.pid"
        script.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import subprocess
                import sys
                import time

                inherited_fd = int(sys.argv[1])
                pathlib.Path(sys.argv[2]).write_text(
                    str(os.getpid()),
                    encoding="utf-8",
                )
                os.set_inheritable(inherited_fd, True)
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    pass_fds=(inherited_fd,),
                )
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )
        read_fd, write_fd = os.pipe()
        try:
            completed = module._run_bounded_refresh_process(
                [
                    sys.executable,
                    str(script),
                    str(write_fd),
                    str(pid_path),
                ],
                pass_fds=(write_fd,),
                env=os.environ.copy(),
                timeout=0.3,
                cleanup_timeout=3.0,
                max_capture_bytes=64 * 1024,
            )
        finally:
            os.close(write_fd)
            if pid_path.exists():
                try:
                    os.killpg(int(pid_path.read_text(encoding="utf-8")), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            self.assertEqual(completed.returncode, 124, completed.stderr)
            self.assertIn("hard timeout", completed.stderr)
            os.set_blocking(read_fd, False)
            self.assertEqual(os.read(read_fd, 1), b"")
        finally:
            os.close(read_fd)

    def test_linux_refresh_scan_accepts_zombie_only_process_group(self) -> None:
        module = self._load_adapter_module()
        proc_root = self.root / "proc-zombie-only"
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
            module._linux_refresh_process_group_state(77, proc_root=proc_root),
            "zombie-only",
        )
        with mock.patch.object(module.os, "killpg", return_value=None):
            self.assertFalse(
                module._refresh_process_group_has_live_members(
                    77,
                    proc_root=proc_root,
                    platform="linux",
                )
            )

    def test_linux_refresh_scan_keeps_live_process_group_member(self) -> None:
        module = self._load_adapter_module()
        proc_root = self.root / "proc-live-member"
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
            module._linux_refresh_process_group_state(91, proc_root=proc_root),
            "live",
        )
        with mock.patch.object(module.os, "killpg", return_value=None):
            self.assertTrue(
                module._refresh_process_group_has_live_members(
                    91,
                    proc_root=proc_root,
                    platform="linux",
                )
            )

    def test_linux_refresh_scan_handles_non_utf8_process_name_as_bytes(
        self,
    ) -> None:
        module = self._load_adapter_module()
        proc_root = self.root / "proc-non-utf8-name"
        process_dir = proc_root / "501"
        process_dir.mkdir(parents=True)
        (process_dir / "stat").write_bytes(b"501 (fixture \xff name) Z 1 109 1 0\n")

        self.assertEqual(
            module._linux_refresh_process_group_state(109, proc_root=proc_root),
            "zombie-only",
        )
        with mock.patch.object(module.os, "killpg", return_value=None):
            self.assertFalse(
                module._refresh_process_group_has_live_members(
                    109,
                    proc_root=proc_root,
                    platform="linux",
                )
            )

    def test_linux_refresh_scan_ambiguity_fails_closed(self) -> None:
        module = self._load_adapter_module()
        proc_root = self.root / "proc-ambiguous"
        self._write_proc_stat(
            proc_root,
            pid=401,
            state="Z",
            process_group=101,
        )
        self.assertEqual(
            module._linux_refresh_process_group_state(
                101,
                proc_root=proc_root,
                deadline=time.monotonic() - 1,
            ),
            "unknown",
        )

        stat_path = proc_root / "401" / "stat"
        stat_path.write_text("ambiguous\n", encoding="utf-8")
        self.assertEqual(
            module._linux_refresh_process_group_state(101, proc_root=proc_root),
            "unknown",
        )

        stat_path.unlink()
        stat_path.mkdir()
        self.assertEqual(
            module._linux_refresh_process_group_state(101, proc_root=proc_root),
            "unknown",
        )
        stat_path.rmdir()
        stat_path.write_bytes(b"401 (fixture) \xff 1 101 1 0\n")
        with mock.patch.object(module.os, "killpg", return_value=None):
            self.assertTrue(
                module._refresh_process_group_has_live_members(
                    101,
                    proc_root=proc_root,
                    platform="linux",
                )
            )

    def test_linux_refresh_scan_iteration_error_fails_closed(self) -> None:
        module = self._load_adapter_module()

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
            module.os,
            "scandir",
            side_effect=lambda _root: FailingProcEntries(),
        ):
            self.assertEqual(
                module._linux_refresh_process_group_state(113),
                "unknown",
            )
            with mock.patch.object(module.os, "killpg", return_value=None):
                self.assertTrue(
                    module._refresh_process_group_has_live_members(
                        113,
                        platform="linux",
                    )
                )

    def test_refresh_signal_cleans_process_group_before_redelivery(self) -> None:
        module = self._load_adapter_module()
        script = self.root / "refresh-signal-tree.py"
        pid_path = self.root / "refresh-signal.pid"
        script.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import subprocess
                import sys
                import time

                inherited_fd = int(sys.argv[1])
                pathlib.Path(sys.argv[2]).write_text(
                    str(os.getpid()),
                    encoding="utf-8",
                )
                os.set_inheritable(inherited_fd, True)
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    pass_fds=(inherited_fd,),
                )
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )
        read_fd, write_fd = os.pipe()
        received_signals: list[int] = []
        previous_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(
            signal.SIGTERM,
            lambda signum, _frame: received_signals.append(signum),
        )
        sender = threading.Thread(
            target=lambda: (
                time.sleep(0.3),
                os.kill(os.getpid(), signal.SIGTERM),
            ),
            daemon=True,
        )
        sender.start()
        try:
            completed = module._run_bounded_refresh_process(
                [
                    sys.executable,
                    str(script),
                    str(write_fd),
                    str(pid_path),
                ],
                pass_fds=(write_fd,),
                env=os.environ.copy(),
                timeout=5.0,
                cleanup_timeout=3.0,
                max_capture_bytes=64 * 1024,
            )
        finally:
            sender.join(timeout=2)
            signal.signal(signal.SIGTERM, previous_handler)
            os.close(write_fd)
            if pid_path.exists():
                try:
                    os.killpg(int(pid_path.read_text(encoding="utf-8")), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            self.assertEqual(completed.returncode, 128 + signal.SIGTERM)
            self.assertEqual(received_signals, [signal.SIGTERM])
            os.set_blocking(read_fd, False)
            self.assertEqual(os.read(read_fd, 1), b"")
        finally:
            os.close(read_fd)

    def test_prepare_active_run_registers_run_dir_for_single_observed_session(
        self,
    ) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(),
        )
        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        run_dir = pathlib.Path(payload["run_dir"])
        self.assertTrue(run_dir.is_dir())

        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        record = index["sessions"]["session-1"]
        self.assertEqual(record["status"], "active")
        self.assertEqual(record["run_dir"], str(run_dir))

        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        orchestration = state["orchestration"]
        self.assertEqual(orchestration["parent_session_id"], "session-1")
        self.assertEqual(
            orchestration["parent_transcript_path"], "/tmp/transcript-1.jsonl"
        )
        self.assertEqual(orchestration["permission_mode"], "acceptEdits")

    def test_prepare_active_run_rejects_ambiguous_sessions_without_selector(
        self,
    ) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-1",
                prompt="Prepare delivery for session one",
                transcript_path="/tmp/transcript-1.jsonl",
            ),
        )
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-2",
                prompt="Prepare delivery for session two",
                transcript_path="/tmp/transcript-2.jsonl",
            ),
        )

        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("ambiguous session selection", completed.stderr)
        self.assertIn("session-1", completed.stderr)
        self.assertIn("session-2", completed.stderr)

    def test_prepare_active_run_can_select_by_prompt_text(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-1",
                prompt="Prepare delivery for session one",
                transcript_path="/tmp/transcript-1.jsonl",
            ),
        )
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-2",
                prompt="Prepare delivery for session two",
                transcript_path="/tmp/transcript-2.jsonl",
            ),
        )

        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--prompt-text",
            "Prepare delivery for session one",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run_dir = pathlib.Path(json.loads(completed.stdout)["run_dir"])
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["parent_session_id"], "session-1")

    def test_prepare_active_run_can_select_by_transcript_path(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-1",
                prompt="Prepare delivery for session one",
                transcript_path="/tmp/transcript-1.jsonl",
            ),
        )
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-2",
                prompt="Prepare delivery for session two",
                transcript_path="/tmp/transcript-2.jsonl",
            ),
        )

        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--transcript-path",
            "/tmp/transcript-2.jsonl",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run_dir = pathlib.Path(json.loads(completed.stdout)["run_dir"])
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["parent_session_id"], "session-2")

    def test_prepare_active_run_prefers_current_thread_env_session(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-1",
                prompt="Prepare delivery for session one",
                transcript_path="/tmp/transcript-1.jsonl",
            ),
        )
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-2",
                prompt="Prepare delivery for session two",
                transcript_path="/tmp/transcript-2.jsonl",
            ),
        )

        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"CODEX_THREAD_ID": "session-2"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run_dir = pathlib.Path(json.loads(completed.stdout)["run_dir"])
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["parent_session_id"], "session-2")

    def test_prepare_active_run_rejects_unknown_current_thread_env_session(
        self,
    ) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-1",
                prompt="Prepare delivery for session one",
                transcript_path="/tmp/transcript-1.jsonl",
            ),
        )
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-2",
                prompt="Prepare delivery for session two",
                transcript_path="/tmp/transcript-2.jsonl",
            ),
        )

        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"CODEX_THREAD_ID": "missing-session"},
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "current Codex thread is not recorded for this repo", completed.stderr
        )
        self.assertIn("CODEX_THREAD_ID=missing-session", completed.stderr)

    def test_prepare_active_run_explicit_session_id_overrides_current_thread_env(
        self,
    ) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-1",
                prompt="Prepare delivery for session one",
                transcript_path="/tmp/transcript-1.jsonl",
            ),
        )
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-2",
                prompt="Prepare delivery for session two",
                transcript_path="/tmp/transcript-2.jsonl",
            ),
        )

        completed = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            "session-1",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"CODEX_THREAD_ID": "session-2"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run_dir = pathlib.Path(json.loads(completed.stdout)["run_dir"])
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["parent_session_id"], "session-1")

    def test_attach_child_active_run_rejects_unknown_run_dir(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(),
        )

        completed = self._run_adapter(
            "attach-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            str(self.repo / ".codex-tmp" / "waited-delivery" / "missing-run"),
            "--child-session-id",
            "child-missing",
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "no observed Codex session currently owns run_dir=",
            completed.stderr,
        )

    def test_stop_hook_blocks_active_run_and_allows_after_guard(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(),
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        payload = json.loads(prepare.stdout)
        run_dir = payload["run_dir"]

        stop_payload = {
            "session_id": "session-1",
            "transcript_path": "/tmp/transcript-1.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "I am about to stop",
        }
        completed = self._run_adapter("stop-hook", input_payload=stop_payload)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Do not finish", completed.stderr)
        self.assertIn(str(pathlib.Path(run_dir) / "parent-prompt.md"), completed.stderr)

        stop_payload["stop_hook_active"] = True
        completed = self._run_adapter("stop-hook", input_payload=stop_payload)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "{}")

    def test_stop_hook_keeps_blocking_when_index_commit_fails(self) -> None:
        session_id = "session-index-commit-failure"
        self._prepare_indexed_run(session_id, "index-commit-failure")
        module = self._load_adapter_module()
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        commit_error = module.RunSafetyError("injected index commit failure")

        with (
            mock.patch.object(
                module.sys,
                "stdin",
                io.StringIO(json.dumps(self._stop_payload_for(session_id))),
            ),
            mock.patch.object(module.sys, "stdout", captured_stdout),
            mock.patch.object(module.sys, "stderr", captured_stderr),
            mock.patch.object(
                module,
                "_utc_now",
                return_value="2999-01-01T00:00:00+00:00",
            ),
            mock.patch.object(
                module,
                "_atomic_save_index_at",
                side_effect=commit_error,
            ),
            mock.patch.object(module, "_record_hook_failure") as record_failure,
        ):
            returncode = module._stop_hook(argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertEqual(captured_stdout.getvalue(), "")
        self.assertIn("Do not finish", captured_stderr.getvalue())
        record_failure.assert_called_once_with(commit_error)

    def test_stop_hook_regenerates_legacy_prompts_before_spawning_child(self) -> None:
        session_id = "session-legacy-pending"
        transcript_path = "/tmp/transcript-legacy-pending.jsonl"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="Recover a legacy pending run",
                transcript_path=transcript_path,
            ),
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Recover a legacy pending run",
            "--session-id",
            session_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
        legacy_runner = pathlib.Path(
            "/legacy/skills/waited-delivery/scripts/waited_delivery_runner.py"
        )
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (run_dir / prompt_name).write_text(
                f"legacy prompt sentinel\n`{sys.executable} {legacy_runner}`\n",
                encoding="utf-8",
            )

        completed = self._run_adapter(
            "stop-hook",
            input_payload={
                "session_id": session_id,
                "transcript_path": transcript_path,
                "cwd": str(self.repo),
                "hook_event_name": "Stop",
                "model": "gpt-5.5",
                "permission_mode": "acceptEdits",
                "stop_hook_active": False,
                "last_assistant_message": "recover pending run",
            },
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("regenerated", completed.stderr)
        self.assertIn(str(run_dir / "parent-prompt.md"), completed.stderr)
        self.assertIn(str(run_dir / "child-prompt.md"), completed.stderr)
        self.assertNotIn("legacy prompt sentinel", completed.stderr)
        self.assertNotIn(str(legacy_runner), completed.stderr)
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            prompt = (run_dir / prompt_name).read_text(encoding="utf-8")
            self.assertIn(str(RUNNER_PATH), prompt)
            self.assertNotIn(str(legacy_runner), prompt)
            self.assertNotIn("legacy prompt sentinel", prompt)

    def test_stop_hook_tightens_owned_legacy_run_directory_mode(self) -> None:
        session_id = "session-legacy-directory-mode"
        run_dir = self._prepare_indexed_run(session_id, "legacy-directory-mode")
        run_dir.chmod(0o755)
        legacy_identity = run_dir.stat()

        completed = self._run_adapter(
            "stop-hook",
            input_payload=self._stop_payload_for(session_id),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("Do not finish", completed.stderr)
        hardened_identity = run_dir.stat()
        self.assertEqual(
            (
                hardened_identity.st_dev,
                hardened_identity.st_ino,
                hardened_identity.st_uid,
                hardened_identity.st_gid,
            ),
            (
                legacy_identity.st_dev,
                legacy_identity.st_ino,
                legacy_identity.st_uid,
                legacy_identity.st_gid,
            ),
        )
        self.assertEqual(hardened_identity.st_mode & 0o7777, 0o700)
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            self.assertIn(
                str(RUNNER_PATH),
                (run_dir / prompt_name).read_text(encoding="utf-8"),
            )

    def test_stop_hook_rejects_nonlegacy_open_run_directory_mode(self) -> None:
        session_id = "session-open-directory-mode"
        run_dir = self._prepare_indexed_run(session_id, "open-directory-mode")
        parent_prompt = run_dir / "parent-prompt.md"
        original_prompt = parent_prompt.read_bytes()
        run_dir.chmod(0o777)

        completed = self._run_adapter(
            "stop-hook",
            input_payload=self._stop_payload_for(session_id),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("failed repository/path safety validation", completed.stderr)
        self.assertEqual(run_dir.stat().st_mode & 0o7777, 0o777)
        self.assertEqual(parent_prompt.read_bytes(), original_prompt)

    def test_stop_hook_refreshes_prompt_for_active_legacy_child(self) -> None:
        session_id = "session-legacy-active"
        transcript_path = "/tmp/transcript-legacy-active.jsonl"
        child_session_id = "child-legacy-active"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="Recover an active legacy child",
                transcript_path=transcript_path,
            ),
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Recover an active legacy child",
            "--session-id",
            session_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
        attached = self._run_adapter(
            "attach-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            child_session_id,
            "--session-id",
            session_id,
        )
        self.assertEqual(attached.returncode, 0, attached.stderr)
        legacy_runner = pathlib.Path(
            "/legacy/skills/waited-delivery/scripts/waited_delivery_runner.py"
        )
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (run_dir / prompt_name).write_text(
                f"active legacy prompt\n`{sys.executable} {legacy_runner}`\n",
                encoding="utf-8",
            )

        completed = self._run_adapter(
            "stop-hook",
            input_payload={
                "session_id": session_id,
                "transcript_path": transcript_path,
                "cwd": str(self.repo),
                "hook_event_name": "Stop",
                "model": "gpt-5.5",
                "permission_mode": "acceptEdits",
                "stop_hook_active": False,
                "last_assistant_message": "recover active child",
            },
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn(child_session_id, completed.stderr)
        self.assertIn("re-read the regenerated child prompt", completed.stderr)
        self.assertNotIn(str(legacy_runner), completed.stderr)
        child_prompt = (run_dir / "child-prompt.md").read_text(encoding="utf-8")
        self.assertIn(str(RUNNER_PATH), child_prompt)
        self.assertNotIn(str(legacy_runner), child_prompt)
        self.assertNotIn("active legacy prompt", child_prompt)

    def test_stop_hook_blocks_external_run_dir_without_writing_it(self) -> None:
        session_id = "session-external-run"
        run_dir = self._prepare_indexed_run(session_id, "external-source")
        external_run = self.root / "external-run"
        shutil.copytree(run_dir, external_run)
        sentinel = "external prompt must remain unchanged\n"
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (external_run / prompt_name).write_text(sentinel, encoding="utf-8")
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        index["sessions"][session_id]["run_dir"] = str(external_run)
        self._index_path().write_text(
            json.dumps(index),
            encoding="utf-8",
        )
        fake_home = self.root / "home-external-run"

        completed = self._run_adapter(
            "stop-hook",
            input_payload=self._stop_payload_for(session_id),
            env_overrides={"HOME": str(fake_home)},
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("failed repository/path safety validation", completed.stderr)
        self.assertIn("Do not execute commands", completed.stderr)
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            self.assertEqual(
                (external_run / prompt_name).read_text(encoding="utf-8"),
                sentinel,
            )

    def test_stop_hook_blocks_repo_mismatch_before_prompt_refresh(self) -> None:
        session_id = "session-repo-mismatch"
        run_dir = self._prepare_indexed_run(session_id, "repo-mismatch")
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["repo_root"] = str(self.root / "different-repo")
        state_path.write_text(json.dumps(state), encoding="utf-8")
        sentinel = "repo mismatch prompt\n"
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (run_dir / prompt_name).write_text(sentinel, encoding="utf-8")
        fake_home = self.root / "home-repo-mismatch"

        completed = self._run_adapter(
            "stop-hook",
            input_payload=self._stop_payload_for(session_id),
            env_overrides={"HOME": str(fake_home)},
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("failed repository/path safety validation", completed.stderr)
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            self.assertEqual(
                (run_dir / prompt_name).read_text(encoding="utf-8"),
                sentinel,
            )

    def test_stop_hook_rejects_symlinked_run_components_and_artifacts(self) -> None:
        cases = ("run-dir", "state.json", "child-prompt.md", "parent-prompt.md")
        for index, target_name in enumerate(cases):
            with self.subTest(target=target_name):
                session_id = f"session-symlink-{index}"
                run_dir = self._prepare_indexed_run(
                    session_id,
                    f"symlink-{index}",
                )
                external_target = self.root / f"external-target-{index}"
                if target_name == "run-dir":
                    run_dir.rename(external_target)
                    run_dir.symlink_to(external_target, target_is_directory=True)
                    sentinel_paths = [
                        external_target / "child-prompt.md",
                        external_target / "parent-prompt.md",
                    ]
                else:
                    artifact = run_dir / target_name
                    artifact.rename(external_target)
                    artifact.symlink_to(external_target)
                    sentinel_paths = [external_target]
                sentinel_values = {path: path.read_bytes() for path in sentinel_paths}
                fake_home = self.root / f"home-symlink-{index}"

                completed = self._run_adapter(
                    "stop-hook",
                    input_payload=self._stop_payload_for(session_id),
                    env_overrides={"HOME": str(fake_home)},
                )

                self.assertEqual(completed.returncode, 2)
                self.assertIn(
                    "failed repository/path safety validation",
                    completed.stderr,
                )
                for path, content in sentinel_values.items():
                    self.assertEqual(path.read_bytes(), content)

    def test_stop_artifact_read_allows_metadata_only_churn(self) -> None:
        session_id = "session-read-metadata-churn"
        run_dir = self._prepare_indexed_run(
            session_id,
            "read-metadata-churn",
        )
        module = self._load_adapter_module()
        run_fd = module._open_stop_run_directory(
            self.repo.resolve(),
            run_dir.name,
        )
        state_path = run_dir / "state.json"
        expected = state_path.read_bytes()
        original = state_path.stat()
        real_read = module.os.read
        changed = False

        def read_then_touch(file_fd: int, size: int) -> bytes:
            nonlocal changed
            chunk = real_read(file_fd, size)
            if chunk and not changed:
                changed = True
                os.utime(
                    state_path,
                    ns=(
                        original.st_atime_ns,
                        original.st_mtime_ns + 1_000_000,
                    ),
                )
            return chunk

        try:
            with mock.patch.object(
                module.os,
                "read",
                side_effect=read_then_touch,
            ):
                actual = module._read_stop_regular_file(
                    run_fd,
                    "state.json",
                    max_bytes=module.STATE_MAX_BYTES,
                )
        finally:
            module.os.close(run_fd)

        self.assertTrue(changed)
        self.assertEqual(actual, expected)
        self.assertNotEqual(state_path.stat().st_mtime_ns, original.st_mtime_ns)

    def test_stop_artifact_read_rejects_content_or_access_change(self) -> None:
        for mutation in ("content", "access"):
            with self.subTest(mutation=mutation):
                session_id = f"session-read-{mutation}-change"
                run_dir = self._prepare_indexed_run(
                    session_id,
                    f"read-{mutation}-change",
                )
                module = self._load_adapter_module()
                run_fd = module._open_stop_run_directory(
                    self.repo.resolve(),
                    run_dir.name,
                )
                state_path = run_dir / "state.json"
                original_content = state_path.read_bytes()
                replacement = (
                    b"[" if original_content[:1] != b"[" else b"{"
                ) + original_content[1:]
                real_read = module.os.read
                changed = False

                def read_then_mutate(file_fd: int, size: int) -> bytes:
                    nonlocal changed
                    chunk = real_read(file_fd, size)
                    if chunk and not changed:
                        changed = True
                        if mutation == "content":
                            state_path.write_bytes(replacement)
                        else:
                            state_path.chmod(0o640)
                    return chunk

                try:
                    with mock.patch.object(
                        module.os,
                        "read",
                        side_effect=read_then_mutate,
                    ):
                        with self.assertRaisesRegex(
                            module.RunSafetyError,
                            "identity, access, size, or content changed",
                        ):
                            module._read_stop_regular_file(
                                run_fd,
                                "state.json",
                                max_bytes=module.STATE_MAX_BYTES,
                            )
                finally:
                    module.os.close(run_fd)
                self.assertTrue(changed)

    def test_stop_hook_fails_closed_on_prompt_link_replacement_after_preflight(
        self,
    ) -> None:
        session_id = "session-link-replacement"
        self._prepare_indexed_run(session_id, "link-replacement")
        external_target = self.root / "link-replacement-target"
        external_target.write_text(
            "external replacement sentinel\n",
            encoding="utf-8",
        )
        original_external = external_target.read_bytes()
        module = self._load_adapter_module()
        stdout = io.StringIO()
        stderr = io.StringIO()

        def replace_after_preflight(
            current_run_dir: pathlib.Path,
            _: pathlib.Path,
            __: tuple[int, int],
        ) -> tuple[pathlib.Path, pathlib.Path]:
            child_prompt = current_run_dir / "child-prompt.md"
            child_prompt.unlink()
            child_prompt.symlink_to(external_target)
            raise module.UserError("simulated refresh interruption")

        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.root / "home-link-replacement")},
            clear=False,
        ):
            with mock.patch.object(
                module,
                "_refresh_recovery_prompts",
                side_effect=replace_after_preflight,
            ):
                with mock.patch.object(
                    module.sys,
                    "stdin",
                    io.StringIO(json.dumps(self._stop_payload_for(session_id))),
                ):
                    with mock.patch.object(module.sys, "stdout", stdout):
                        with mock.patch.object(module.sys, "stderr", stderr):
                            returncode = module._stop_hook(argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "failed repository/path safety validation",
            stderr.getvalue(),
        )
        self.assertEqual(external_target.read_bytes(), original_external)

    def test_stop_hook_fails_closed_on_run_directory_replacement_after_preflight(
        self,
    ) -> None:
        session_id = "session-directory-replacement"
        run_dir = self._prepare_indexed_run(
            session_id,
            "directory-replacement",
        )
        module = self._load_adapter_module()
        real_refresh = module._refresh_recovery_prompts
        original_dir = self.root / "original-run-directory"
        sentinel = "replacement directory prompt must remain unchanged\n"
        stdout = io.StringIO()
        stderr = io.StringIO()

        def replace_after_preflight(
            current_run_dir: pathlib.Path,
            repo_root: pathlib.Path,
            run_identity: tuple[int, int],
        ) -> tuple[pathlib.Path, pathlib.Path]:
            current_run_dir.rename(original_dir)
            shutil.copytree(original_dir, current_run_dir)
            for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                (current_run_dir / prompt_name).write_text(
                    sentinel,
                    encoding="utf-8",
                )
            return real_refresh(current_run_dir, repo_root, run_identity)

        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.root / "home-directory-replacement")},
            clear=False,
        ):
            with mock.patch.object(
                module,
                "_refresh_recovery_prompts",
                side_effect=replace_after_preflight,
            ):
                with mock.patch.object(
                    module.sys,
                    "stdin",
                    io.StringIO(json.dumps(self._stop_payload_for(session_id))),
                ):
                    with mock.patch.object(module.sys, "stdout", stdout):
                        with mock.patch.object(module.sys, "stderr", stderr):
                            returncode = module._stop_hook(argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "failed repository/path safety validation",
            stderr.getvalue(),
        )
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            self.assertEqual(
                (run_dir / prompt_name).read_text(encoding="utf-8"),
                sentinel,
            )

    def test_stop_hook_fails_closed_on_run_access_change_after_preflight(
        self,
    ) -> None:
        session_id = "session-access-change"
        run_dir = self._prepare_indexed_run(session_id, "access-change")
        module = self._load_adapter_module()
        real_refresh = module._refresh_recovery_prompts
        sentinel = {
            prompt_name: (run_dir / prompt_name).read_bytes()
            for prompt_name in ("child-prompt.md", "parent-prompt.md")
        }
        stdout = io.StringIO()
        stderr = io.StringIO()

        def change_access_after_preflight(
            current_run_dir: pathlib.Path,
            repo_root: pathlib.Path,
            run_identity,
        ) -> tuple[pathlib.Path, pathlib.Path]:
            current_run_dir.chmod(0o755)
            return real_refresh(current_run_dir, repo_root, run_identity)

        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.root / "home-access-change")},
            clear=False,
        ):
            with mock.patch.object(
                module,
                "_refresh_recovery_prompts",
                side_effect=change_access_after_preflight,
            ):
                with mock.patch.object(
                    module.sys,
                    "stdin",
                    io.StringIO(json.dumps(self._stop_payload_for(session_id))),
                ):
                    with mock.patch.object(module.sys, "stdout", stdout):
                        with mock.patch.object(module.sys, "stderr", stderr):
                            returncode = module._stop_hook(argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "failed repository/path safety validation",
            stderr.getvalue(),
        )
        for prompt_name, original in sentinel.items():
            self.assertEqual((run_dir / prompt_name).read_bytes(), original)

    def test_stop_hook_revalidates_run_identity_after_prompt_refresh(
        self,
    ) -> None:
        for mutation in ("replacement", "access"):
            with self.subTest(mutation=mutation):
                session_id = f"session-post-refresh-{mutation}"
                self._prepare_indexed_run(
                    session_id,
                    f"post-refresh-{mutation}",
                )
                module = self._load_adapter_module()
                real_refresh = module._refresh_recovery_prompts
                original_dir = self.root / f"post-refresh-original-{mutation}"
                stdout = io.StringIO()
                stderr = io.StringIO()

                def mutate_after_refresh(
                    current_run_dir: pathlib.Path,
                    repo_root: pathlib.Path,
                    run_identity,
                ) -> tuple[pathlib.Path, pathlib.Path]:
                    result = real_refresh(
                        current_run_dir,
                        repo_root,
                        run_identity,
                    )
                    if mutation == "replacement":
                        current_run_dir.rename(original_dir)
                        shutil.copytree(original_dir, current_run_dir)
                    else:
                        current_run_dir.chmod(0o755)
                    return result

                with mock.patch.dict(
                    os.environ,
                    {"HOME": str(self.root / f"home-post-refresh-{mutation}")},
                    clear=False,
                ):
                    with mock.patch.object(
                        module,
                        "_refresh_recovery_prompts",
                        side_effect=mutate_after_refresh,
                    ):
                        with mock.patch.object(
                            module.sys,
                            "stdin",
                            io.StringIO(json.dumps(self._stop_payload_for(session_id))),
                        ):
                            with mock.patch.object(module.sys, "stdout", stdout):
                                with mock.patch.object(module.sys, "stderr", stderr):
                                    returncode = module._stop_hook(argparse.Namespace())

                self.assertEqual(returncode, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "failed repository/path safety validation",
                    stderr.getvalue(),
                )

    def test_stop_hook_binds_refreshed_prompt_identity_access_and_content(
        self,
    ) -> None:
        expected_errors = {
            "replacement": "was replaced after prompt refresh",
            "content": "content changed after prompt refresh",
            "access": "access policy changed after prompt refresh",
        }
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            for mutation in (*expected_errors, "timestamps"):
                with self.subTest(prompt=prompt_name, mutation=mutation):
                    session_id = (
                        f"session-prompt-{prompt_name.removesuffix('.md')}-{mutation}"
                    )
                    self._prepare_indexed_run(
                        session_id,
                        f"prompt-{prompt_name.removesuffix('.md')}-{mutation}",
                    )
                    module = self._load_adapter_module()
                    real_refresh = module._refresh_recovery_prompts
                    displaced_prompt = self.root / (
                        f"displaced-{prompt_name}-{mutation}"
                    )
                    fake_home = self.root / (
                        f"home-prompt-{prompt_name.removesuffix('.md')}-{mutation}"
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()

                    def mutate_after_refresh(
                        current_run_dir: pathlib.Path,
                        repo_root: pathlib.Path,
                        run_identity,
                    ):
                        refreshed = real_refresh(
                            current_run_dir,
                            repo_root,
                            run_identity,
                        )
                        prompt_path = current_run_dir / prompt_name
                        original_stat = prompt_path.stat()
                        original_content = prompt_path.read_bytes()
                        if mutation == "replacement":
                            prompt_path.rename(displaced_prompt)
                            prompt_path.write_bytes(original_content)
                            prompt_path.chmod(original_stat.st_mode & 0o7777)
                        elif mutation == "content":
                            replacement = bytearray(original_content)
                            replacement[0] ^= 1
                            prompt_path.write_bytes(replacement)
                        elif mutation == "access":
                            prompt_path.chmod(0o640)
                        else:
                            os.utime(
                                prompt_path,
                                ns=(
                                    original_stat.st_atime_ns,
                                    original_stat.st_mtime_ns + 1_000_000_000,
                                ),
                            )
                        return refreshed

                    with mock.patch.dict(
                        os.environ,
                        {"HOME": str(fake_home)},
                        clear=False,
                    ):
                        with mock.patch.object(
                            module,
                            "_refresh_recovery_prompts",
                            side_effect=mutate_after_refresh,
                        ):
                            with mock.patch.object(
                                module.sys,
                                "stdin",
                                io.StringIO(
                                    json.dumps(self._stop_payload_for(session_id))
                                ),
                            ):
                                with mock.patch.object(module.sys, "stdout", stdout):
                                    with mock.patch.object(
                                        module.sys,
                                        "stderr",
                                        stderr,
                                    ):
                                        returncode = module._stop_hook(
                                            argparse.Namespace()
                                        )

                    self.assertEqual(returncode, 2)
                    self.assertEqual(stdout.getvalue(), "")
                    if mutation == "timestamps":
                        self.assertIn("regenerated", stderr.getvalue())
                        self.assertNotIn(
                            "failed repository/path safety validation",
                            stderr.getvalue(),
                        )
                    else:
                        self.assertIn(
                            "failed repository/path safety validation",
                            stderr.getvalue(),
                        )
                        log_path = (
                            self._home_log_dir(fake_home)
                            / "waited-delivery-hooks.jsonl"
                        )
                        entry = json.loads(
                            log_path.read_text(encoding="utf-8").splitlines()[-1]
                        )
                        self.assertEqual(entry["error_type"], "RunSafetyError")
                        self.assertIn(
                            expected_errors[mutation],
                            entry["error_message"],
                        )

    def test_stop_hook_binds_runner_version_returned_through_bridge(self) -> None:
        mutations = {
            "replacement": ("inode", "was replaced before process start"),
            "access": ("mode", "access policy changed before process start"),
            "content": ("sha256", "content changed before process start"),
        }
        for mutation, (field, expected_error) in mutations.items():
            with self.subTest(mutation=mutation):
                session_id = f"session-runner-{mutation}-mismatch"
                self._prepare_indexed_run(
                    session_id,
                    f"runner-{mutation}-mismatch",
                )
                module = self._load_adapter_module()
                real_run_bridge_json = module._run_refresh_bridge_json
                fake_home = self.root / f"home-runner-{mutation}-mismatch"
                stdout = io.StringIO()
                stderr = io.StringIO()

                def corrupt_runner_version(
                    snapshots,
                    *args: str,
                ) -> dict[str, object]:
                    payload = real_run_bridge_json(snapshots, *args)
                    runner_version = payload["runner_version"]
                    assert isinstance(runner_version, dict)
                    current = runner_version[field]
                    if field == "sha256":
                        runner_version[field] = "0" * 64
                    else:
                        assert isinstance(current, int)
                        runner_version[field] = current ^ 0o040
                    return payload

                with mock.patch.dict(
                    os.environ,
                    {"HOME": str(fake_home)},
                    clear=False,
                ):
                    with mock.patch.object(
                        module,
                        "_run_refresh_bridge_json",
                        side_effect=corrupt_runner_version,
                    ):
                        with mock.patch.object(
                            module.sys,
                            "stdin",
                            io.StringIO(json.dumps(self._stop_payload_for(session_id))),
                        ):
                            with mock.patch.object(module.sys, "stdout", stdout):
                                with mock.patch.object(module.sys, "stderr", stderr):
                                    returncode = module._stop_hook(argparse.Namespace())

                self.assertEqual(returncode, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "failed repository/path safety validation",
                    stderr.getvalue(),
                )
                log_path = self._home_log_dir(fake_home) / "waited-delivery-hooks.jsonl"
                entry = json.loads(
                    log_path.read_text(encoding="utf-8").splitlines()[-1]
                )
                self.assertEqual(entry["error_type"], "RunSafetyError")
                self.assertIn(expected_error, entry["error_message"])

    def test_launch_snapshot_closes_fd_when_execution_path_resolution_fails(
        self,
    ) -> None:
        module = self._load_adapter_module()
        source = module._read_stop_absolute_regular_artifact(
            BRIDGE_PATH,
            max_bytes=module.STATE_MAX_BYTES,
        )
        snapshot_dir = self.root / "snapshot-resolution-failure"
        snapshot_dir.mkdir(mode=0o700)
        snapshot_dir_fd = os.open(snapshot_dir, os.O_RDONLY)
        captured_fds: list[int] = []

        def fail_execution_path(file_fd: int, name: str) -> pathlib.Path:
            captured_fds.append(file_fd)
            raise module.RunSafetyError(
                f"cannot expose descriptor-bound compatibility snapshot: {name}"
            )

        try:
            with mock.patch.object(
                module,
                "_fd_execution_path",
                side_effect=fail_execution_path,
            ):
                with self.assertRaisesRegex(
                    module.RunSafetyError,
                    "cannot expose descriptor-bound compatibility snapshot",
                ):
                    module._write_launch_snapshot(
                        snapshot_dir_fd,
                        "waited_delivery_bridge.py",
                        BRIDGE_PATH,
                        source,
                    )
        finally:
            os.close(snapshot_dir_fd)

        self.assertEqual(len(captured_fds), 1)
        with self.assertRaises(OSError):
            os.fstat(captured_fds[0])
        self.assertFalse((snapshot_dir / "waited_delivery_bridge.py").exists())

    def test_refresh_launch_revalidates_bridge_and_runner_before_process(
        self,
    ) -> None:
        expected_errors = {
            "replacement": "was replaced before process start",
            "content": "content changed before process start",
            "access": "access policy changed before process start",
        }
        for artifact_name in ("bridge", "runner"):
            for mutation in (*expected_errors, "timestamps"):
                with self.subTest(artifact=artifact_name, mutation=mutation):
                    module = self._load_adapter_module()
                    bridge_path, runner_path = self._private_launch_sources(
                        f"{artifact_name}-{mutation}"
                    )
                    source_path = (
                        bridge_path if artifact_name == "bridge" else runner_path
                    )
                    run_dir = self._prepare_indexed_run(
                        f"session-launch-{artifact_name}-{mutation}",
                        f"launch-{artifact_name}-{mutation}",
                    )
                    watched_paths = tuple(
                        run_dir / name
                        for name in (
                            "state.json",
                            "child-prompt.md",
                            "parent-prompt.md",
                        )
                    )
                    before = {
                        path: (path.stat().st_ino, path.read_bytes())
                        for path in watched_paths
                    }
                    run_identity = self._run_identity(module, run_dir)
                    real_revalidate = module._revalidate_refresh_launch_snapshots
                    displaced = self.root / (
                        f"displaced-launch-{artifact_name}-{mutation}.py"
                    )

                    def mutate_before_revalidation(snapshots) -> None:
                        original_stat = source_path.stat()
                        original_content = source_path.read_bytes()
                        if mutation == "replacement":
                            source_path.rename(displaced)
                            source_path.write_bytes(original_content)
                            source_path.chmod(original_stat.st_mode & 0o7777)
                        elif mutation == "content":
                            changed = bytearray(original_content)
                            changed[0] ^= 1
                            source_path.write_bytes(changed)
                        elif mutation == "access":
                            source_path.chmod((original_stat.st_mode & 0o7777) ^ 0o040)
                        else:
                            os.utime(
                                source_path,
                                ns=(
                                    original_stat.st_atime_ns,
                                    original_stat.st_mtime_ns + 1_000_000_000,
                                ),
                            )
                        real_revalidate(snapshots)

                    launch_glob = "waited-delivery-refresh-launch-*"
                    before_launch_dirs = set(self.root.glob(launch_glob))
                    patches = (
                        mock.patch.object(module, "BRIDGE_PATH", bridge_path),
                        mock.patch.object(module, "RUNNER_PATH", runner_path),
                        mock.patch.object(
                            module,
                            "_revalidate_refresh_launch_snapshots",
                            side_effect=mutate_before_revalidation,
                        ),
                        mock.patch.object(module.tempfile, "tempdir", str(self.root)),
                    )
                    with patches[0], patches[1], patches[2], patches[3]:
                        if mutation == "timestamps":
                            refreshed = module._refresh_recovery_prompts(
                                run_dir,
                                self.repo.resolve(),
                                run_identity,
                            )
                            self.assertEqual(
                                refreshed.child_prompt,
                                run_dir / "child-prompt.md",
                            )
                        else:
                            with mock.patch.object(module, "_run") as process_run:
                                with self.assertRaisesRegex(
                                    module.RunSafetyError,
                                    expected_errors[mutation],
                                ):
                                    module._refresh_recovery_prompts(
                                        run_dir,
                                        self.repo.resolve(),
                                        run_identity,
                                    )
                                process_run.assert_not_called()
                            for path, (
                                expected_inode,
                                expected_content,
                            ) in before.items():
                                self.assertEqual(path.stat().st_ino, expected_inode)
                                self.assertEqual(path.read_bytes(), expected_content)
                    self.assertEqual(
                        set(self.root.glob(launch_glob)),
                        before_launch_dirs,
                    )

    def test_refresh_launch_executes_private_snapshots_across_source_aba(
        self,
    ) -> None:
        for artifact_name in ("bridge", "runner"):
            with self.subTest(artifact=artifact_name):
                module = self._load_adapter_module()
                bridge_path, runner_path = self._private_launch_sources(
                    f"aba-{artifact_name}"
                )
                source_path = bridge_path if artifact_name == "bridge" else runner_path
                source_identity = source_path.stat()
                run_dir = self._prepare_indexed_run(
                    f"session-launch-aba-{artifact_name}",
                    f"launch-aba-{artifact_name}",
                )
                for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                    (run_dir / prompt_name).write_text(
                        "legacy launch-window prompt\n",
                        encoding="utf-8",
                    )
                run_identity = self._run_identity(module, run_dir)
                displaced = self.root / f"aba-original-{artifact_name}.py"
                marker = self.root / f"aba-executed-{artifact_name}.txt"
                malicious = (
                    "#!/usr/bin/env python3\n"
                    "import pathlib\n"
                    f"pathlib.Path({str(marker)!r}).write_text("
                    "'unexpected path execution\\n', encoding='utf-8')\n"
                    "raise SystemExit(93)\n"
                )
                real_run = module._run_bounded_refresh_process
                process_commands: list[list[str]] = []
                process_environments: list[dict[str, str] | None] = []

                def run_during_source_aba(
                    cmd: list[str],
                    *,
                    pass_fds: tuple[int, ...],
                    env: dict[str, str],
                    **bounds: object,
                ) -> subprocess.CompletedProcess[str]:
                    process_commands.append(cmd)
                    process_environments.append(env)
                    source_path.rename(displaced)
                    source_path.write_text(malicious, encoding="utf-8")
                    source_path.chmod(source_identity.st_mode & 0o7777)
                    try:
                        return real_run(
                            cmd,
                            pass_fds=pass_fds,
                            env=env,
                            **bounds,
                        )
                    finally:
                        source_path.unlink()
                        displaced.rename(source_path)

                launch_glob = "waited-delivery-refresh-launch-*"
                before_launch_dirs = set(self.root.glob(launch_glob))
                with (
                    mock.patch.object(
                        module,
                        "BRIDGE_PATH",
                        bridge_path,
                    ),
                    mock.patch.object(
                        module,
                        "RUNNER_PATH",
                        runner_path,
                    ),
                    mock.patch.object(
                        module,
                        "_run_bounded_refresh_process",
                        side_effect=run_during_source_aba,
                    ),
                    mock.patch.object(
                        module.tempfile,
                        "tempdir",
                        str(self.root),
                    ),
                ):
                    refreshed = module._refresh_recovery_prompts(
                        run_dir,
                        self.repo.resolve(),
                        run_identity,
                    )

                self.assertEqual(len(process_commands), 1)
                self.assertEqual(
                    process_commands[0][1:4],
                    ["-I", "-B", "-S"],
                )
                self.assertNotEqual(process_commands[0][4], str(source_path))
                self.assertIsNotNone(process_environments[0])
                assert process_environments[0] is not None
                self.assertFalse(
                    any(
                        name.startswith("PYTHON") or name == "__PYVENV_LAUNCHER__"
                        for name in process_environments[0]
                    )
                )
                self.assertFalse(marker.exists())
                self.assertEqual(source_path.stat().st_ino, source_identity.st_ino)
                self.assertEqual(
                    refreshed.parent_prompt,
                    run_dir / "parent-prompt.md",
                )
                for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                    prompt = (run_dir / prompt_name).read_text(encoding="utf-8")
                    self.assertIn(str(runner_path), prompt)
                    self.assertNotIn("legacy launch-window prompt", prompt)
                self.assertEqual(
                    set(self.root.glob(launch_glob)),
                    before_launch_dirs,
                )

    def test_stop_hook_fails_open_when_index_is_invalid(self) -> None:
        fake_home = self.root / "home-stop-invalid"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")

        stop_payload = {
            "session_id": "session-1",
            "transcript_path": "/tmp/transcript-1.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "I am about to stop",
        }
        completed = self._run_adapter(
            "stop-hook",
            input_payload=stop_payload,
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "{}")
        self.assertEqual(completed.stderr.strip(), "")
        log_path = self._home_log_dir(fake_home) / "waited-delivery-hooks.jsonl"
        self.assertTrue(log_path.is_file())
        entries = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(entries[-1]["hook_command"], "stop-hook")
        self.assertEqual(entries[-1]["session_id"], "session-1")
        self.assertEqual(entries[-1]["error_type"], "JSONDecodeError")
        self.assertIsNone(entries[-1]["prompt_preview"])
        self.assertIsNone(entries[-1]["assistant_preview"])
        self.assertNotIn(
            "I am about to stop",
            log_path.read_text(encoding="utf-8"),
        )

    def test_user_prompt_submit_hook_fails_open_when_index_is_invalid(self) -> None:
        fake_home = self.root / "home-submit-invalid"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")

        completed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(),
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "{}")
        self.assertEqual(completed.stderr.strip(), "")
        log_path = self._home_log_dir(fake_home) / "waited-delivery-hooks.jsonl"
        self.assertTrue(log_path.is_file())
        entries = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(entries[-1]["hook_command"], "user-prompt-submit-hook")
        self.assertIsNone(entries[-1]["prompt_preview"])
        self.assertIsNone(entries[-1]["assistant_preview"])
        self.assertNotIn(
            "Please use waited delivery",
            log_path.read_text(encoding="utf-8"),
        )

    def test_stop_hook_debug_env_mirrors_fail_open_error_to_stderr(self) -> None:
        fake_home = self.root / "home-stop-debug"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")

        completed = self._run_adapter(
            "stop-hook",
            input_payload={
                "session_id": "session-debug",
                "transcript_path": "/tmp/transcript-debug.jsonl",
                "cwd": str(self.repo),
                "hook_event_name": "Stop",
                "model": "gpt-5.5",
                "permission_mode": "acceptEdits",
                "stop_hook_active": False,
                "last_assistant_message": "debug me",
            },
            env_overrides={
                "HOME": str(fake_home),
                "WAITED_DELIVERY_HOOK_DEBUG": "1",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("waited-delivery hook fail-open (stop-hook)", completed.stderr)

    def test_fail_open_survives_debug_stderr_and_log_write_failures(self) -> None:
        fake_home = self.root / "home-fail-open-debug"

        class BrokenStderr:
            def write(self, _: str) -> int:
                raise BrokenPipeError("stderr closed")

            def flush(self) -> None:
                return None

        module = self._load_adapter_module()
        stdout = io.StringIO()
        error = RuntimeError("boom")
        setattr(error, "hook_command", "stop-hook")
        setattr(
            error,
            "hook_payload",
            {
                "session_id": "session-debug-broken-stderr",
                "cwd": str(self.repo),
                "transcript_path": "/tmp/transcript-debug-broken-stderr.jsonl",
            },
        )
        with mock.patch.dict(
            os.environ,
            {"HOME": str(fake_home), "WAITED_DELIVERY_HOOK_DEBUG": "1"},
            clear=False,
        ):
            with mock.patch.object(
                module, "_append_hook_log", side_effect=OSError("disk full")
            ):
                with mock.patch.object(module.sys, "stdout", stdout):
                    with mock.patch.object(module.sys, "stderr", BrokenStderr()):
                        returncode = module._fail_open_hook_response(error)

        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.getvalue().strip(), "{}")

    def test_hook_archive_label_is_unique(self) -> None:
        module = self._load_adapter_module()
        path = pathlib.Path("waited-delivery-hooks.2.jsonl")
        with mock.patch.object(
            module.uuid,
            "uuid4",
            side_effect=[
                module.uuid.UUID("11111111-1111-1111-1111-111111111111"),
                module.uuid.UUID("22222222-2222-2222-2222-222222222222"),
            ],
        ):
            first = module._hook_archive_label(path)
            second = module._hook_archive_label(path)
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith("-waited-delivery-hooks.2"))
        self.assertTrue(second.endswith("-waited-delivery-hooks.2"))

    def test_compress_hook_log_falls_back_to_jsonl_when_zstd_missing(self) -> None:
        module = self._load_adapter_module()
        fake_home = self.root / "home-fallback-archive"
        log_dir = self._home_log_dir(fake_home)
        log_dir.mkdir(parents=True, exist_ok=True)
        source = log_dir / "waited-delivery-hooks.2.jsonl"
        source.write_text("fallback\n", encoding="utf-8")

        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
            with mock.patch.object(module.shutil, "which", return_value=None):
                module._compress_hook_log(source)

        self.assertFalse(source.exists())
        archives = sorted(log_dir.glob("waited-delivery-hooks-*.jsonl"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_text(encoding="utf-8"), "fallback\n")
        self.assertEqual(list(log_dir.glob("waited-delivery-hooks-*.jsonl.zst")), [])

    def test_hook_diagnostics_rotate_and_compress_with_zstd(self) -> None:
        zstd = shutil.which("zstd")
        if zstd is None:
            self.skipTest("zstd not available")
        fake_home = self.root / "home-rotation"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        env: Mapping[str, str | None] = {
            "HOME": str(fake_home),
            "WAITED_DELIVERY_HOOK_LOG_MAX_BYTES": "256",
            "WAITED_DELIVERY_HOOK_LOG_UNCOMPRESSED_SLOTS": "3",
        }
        for _ in range(4):
            (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")
            completed = self._run_adapter(
                "stop-hook",
                input_payload={
                    "session_id": "session-rotation",
                    "transcript_path": "/tmp/transcript-rotation.jsonl",
                    "cwd": str(self.repo),
                    "hook_event_name": "Stop",
                    "model": "gpt-5.5",
                    "permission_mode": "acceptEdits",
                    "stop_hook_active": False,
                    "last_assistant_message": "rotate me",
                },
                env_overrides=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        log_dir = self._home_log_dir(fake_home)
        self.assertTrue((log_dir / "waited-delivery-hooks.jsonl").is_file())
        self.assertTrue((log_dir / "waited-delivery-hooks.1.jsonl").is_file())
        self.assertTrue((log_dir / "waited-delivery-hooks.2.jsonl").is_file())
        compressed = list(log_dir.glob("waited-delivery-hooks-*.jsonl.zst"))
        self.assertTrue(compressed)
        self.assertGreater(compressed[0].stat().st_size, 0)
        verify = run([zstd, "-t", str(compressed[0])])
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_hook_log_max_bytes_zero_uses_default_limit(self) -> None:
        fake_home = self.root / "home-max-bytes-zero"
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")
        log_dir = self._home_log_dir(fake_home)
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "waited-delivery-hooks.jsonl").write_text("", encoding="utf-8")

        completed = self._run_adapter(
            "stop-hook",
            input_payload={
                "session_id": "session-max-bytes-zero",
                "transcript_path": "/tmp/transcript-max-bytes-zero.jsonl",
                "cwd": str(self.repo),
                "hook_event_name": "Stop",
                "model": "gpt-5.5",
                "permission_mode": "acceptEdits",
                "stop_hook_active": False,
                "last_assistant_message": "max bytes zero",
            },
            env_overrides={
                "HOME": str(fake_home),
                "WAITED_DELIVERY_HOOK_LOG_MAX_BYTES": "0",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((log_dir / "waited-delivery-hooks.jsonl").is_file())
        self.assertFalse((log_dir / "waited-delivery-hooks.1.jsonl").exists())
        self.assertEqual(list(log_dir.glob("waited-delivery-hooks-*.jsonl*")), [])

    def test_hook_diagnostics_prune_old_archives(self) -> None:
        fake_home = self.root / "home-prune"
        log_dir = self._home_log_dir(fake_home)
        log_dir.mkdir(parents=True, exist_ok=True)
        stale = log_dir / "waited-delivery-hooks-19990101T000000Z-old.jsonl.zst"
        stale.write_bytes(zlib.compress(b"stale"))
        old_ts = 946684800
        os.utime(stale, (old_ts, old_ts))

        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")
        completed = self._run_adapter(
            "stop-hook",
            input_payload={
                "session_id": "session-prune",
                "transcript_path": "/tmp/transcript-prune.jsonl",
                "cwd": str(self.repo),
                "hook_event_name": "Stop",
                "model": "gpt-5.5",
                "permission_mode": "acceptEdits",
                "stop_hook_active": False,
                "last_assistant_message": "prune me",
            },
            env_overrides={
                "HOME": str(fake_home),
                "WAITED_DELIVERY_HOOK_LOG_RETENTION_DAYS": "7",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(stale.exists())

    def test_hook_diagnostics_skip_prune_when_recently_pruned(self) -> None:
        fake_home = self.root / "home-prune-skip"
        log_dir = self._home_log_dir(fake_home)
        log_dir.mkdir(parents=True, exist_ok=True)
        stale = log_dir / "waited-delivery-hooks-19990101T000000Z-old.jsonl.zst"
        stale.write_bytes(zlib.compress(b"stale"))
        old_ts = 946684800
        os.utime(stale, (old_ts, old_ts))
        stamp = log_dir / "waited-delivery-hooks.prune-stamp"
        stamp.touch()

        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "index.json").write_text("{invalid json\n", encoding="utf-8")
        completed = self._run_adapter(
            "stop-hook",
            input_payload={
                "session_id": "session-prune-skip",
                "transcript_path": "/tmp/transcript-prune-skip.jsonl",
                "cwd": str(self.repo),
                "hook_event_name": "Stop",
                "model": "gpt-5.5",
                "permission_mode": "acceptEdits",
                "stop_hook_active": False,
                "last_assistant_message": "skip prune",
            },
            env_overrides={
                "HOME": str(fake_home),
                "WAITED_DELIVERY_HOOK_LOG_RETENTION_DAYS": "7",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(stale.exists())

    def test_reconcile_active_run_clears_index_for_completed_run(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id="session-2"),
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            "--session-id",
            "session-2",
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = json.loads(prepare.stdout)["run_dir"]
        attached = self._run_adapter(
            "attach-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            run_dir,
            "--child-session-id",
            "child-1",
            "--session-id",
            "session-2",
        )
        self.assertEqual(attached.returncode, 0, attached.stderr)
        self._finish_child(run_dir, "session-2", "child-1")
        self._commit_implementation()

        for phase_name in ("tests", "docs_sync", "internal_review", "external_review"):
            completed = self._run_runner(
                "record-phase",
                "--run-dir",
                run_dir,
                "--phase",
                phase_name,
                "--status",
                "passed",
                "--summary",
                f"{phase_name} passed",
                *(
                    ["--evidence", "reviewer terminal artifact"]
                    if phase_name in ("internal_review", "external_review")
                    else []
                ),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        completed = self._run_adapter(
            "reconcile-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            run_dir,
            "--child-status",
            "completed",
            "--child-session-id",
            "child-1",
            "--session-id",
            "session-2",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["overall_status"], "passed")

        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        record = index["sessions"]["session-2"]
        self.assertEqual(record["status"], "completed")
        self.assertIsNone(record["run_dir"])

    def test_finish_child_active_run_rejects_cross_session_run(self) -> None:
        run_dirs: dict[str, str] = {}
        for session_id in ("session-owner-a", "session-owner-b"):
            observed = self._run_adapter(
                "user-prompt-submit-hook",
                input_payload=self._session_payload(session_id=session_id),
            )
            self.assertEqual(observed.returncode, 0, observed.stderr)
            prepared = self._run_adapter(
                "prepare-active-run",
                "--repo",
                str(self.repo),
                "--goal",
                "Verify session ownership",
                "--external-helper",
                str(self.fake_helper),
                "--no-fallback-smoke",
                "--session-id",
                session_id,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            run_dirs[session_id] = json.loads(prepared.stdout)["run_dir"]

        completed = self._run_adapter(
            "finish-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            run_dirs["session-owner-b"],
            "--child-status",
            "completed",
            "--child-session-id",
            "child-owner-b",
            "--session-id",
            "session-owner-a",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not own run_dir", completed.stderr)

        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(
            index["sessions"]["session-owner-a"]["run_dir"],
            run_dirs["session-owner-a"],
        )
        self.assertEqual(
            index["sessions"]["session-owner-b"]["run_dir"],
            run_dirs["session-owner-b"],
        )

    def test_stop_hook_reconcile_prompt_includes_repo(self) -> None:
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id="session-3"),
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            "--session-id",
            "session-3",
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = json.loads(prepare.stdout)["run_dir"]
        self._commit_implementation()

        attach = self._run_adapter(
            "attach-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            run_dir,
            "--child-session-id",
            "child-3",
            "--session-id",
            "session-3",
        )
        self.assertEqual(attach.returncode, 0, attach.stderr)
        self._finish_child(run_dir, "session-3", "child-3")

        for phase_name in ("tests", "docs_sync", "internal_review", "external_review"):
            completed = self._run_runner(
                "record-phase",
                "--run-dir",
                run_dir,
                "--phase",
                phase_name,
                "--status",
                "passed",
                "--summary",
                f"{phase_name} passed",
                *(
                    ["--evidence", "reviewer terminal artifact"]
                    if phase_name in ("internal_review", "external_review")
                    else []
                ),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        state_path = pathlib.Path(run_dir) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["orchestration"]["child_status"] = "completed"
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

        stop_payload = {
            "session_id": "session-3",
            "transcript_path": "/tmp/transcript-3.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "I am about to stop",
        }
        completed = self._run_adapter("stop-hook", input_payload=stop_payload)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("reconcile-active-run", completed.stderr)
        self.assertIn("--repo", completed.stderr)
        self.assertIn(str(self.repo), completed.stderr)
        self.assertIn("--child-session-id child-3", completed.stderr)

    def test_stop_hook_keeps_blocking_when_prompt_render_fails(self) -> None:
        fake_home = self.root / "home-stop-blocking"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-block",
                prompt="Block on active waited delivery",
                transcript_path="/tmp/transcript-block.jsonl",
            ),
            env_overrides={"HOME": str(fake_home)},
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            "session-block",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["orchestration"]["child_status"] = "failed"
        state["orchestration"]["child_session_id"] = "child-terminal-fallback"
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

        stop_payload = {
            "session_id": "session-block",
            "transcript_path": "/tmp/transcript-block.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "keep blocking",
        }

        module = self._load_adapter_module()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
            with mock.patch.object(
                module,
                "_build_stop_continuation_prompt",
                side_effect=RuntimeError("boom"),
            ):
                with mock.patch.object(
                    module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
                ):
                    with mock.patch.object(module.sys, "stderr", stderr):
                        returncode = module._stop_hook(module.argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertIn("Do not finish yet.", stderr.getvalue())
        self.assertIn(str(run_dir / "state.json"), stderr.getvalue())
        log_path = self._home_log_dir(fake_home) / "waited-delivery-hooks.jsonl"
        entries = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(entries[-1]["hook_command"], "stop-hook")
        self.assertEqual(entries[-1]["error_type"], "RuntimeError")
        self.assertEqual(entries[-1]["session_id"], "session-block")

    def test_stop_hook_fallback_prompt_preserves_terminal_child_status(self) -> None:
        for child_status in ("completed", "failed", "interrupted"):
            with self.subTest(child_status=child_status):
                fake_home = self.root / f"home-stop-terminal-fallback-{child_status}"
                session_id = f"session-terminal-fallback-{child_status}"
                transcript_path = (
                    f"/tmp/transcript-terminal-fallback-{child_status}.jsonl"
                )
                self._run_adapter(
                    "user-prompt-submit-hook",
                    input_payload=self._session_payload(
                        session_id=session_id,
                        prompt="Reconcile a waited delivery child",
                        transcript_path=transcript_path,
                    ),
                    env_overrides={"HOME": str(fake_home)},
                )
                prepare = self._run_adapter(
                    "prepare-active-run",
                    "--repo",
                    str(self.repo),
                    "--goal",
                    "Wrap current repo changes",
                    "--session-id",
                    session_id,
                    "--external-helper",
                    str(self.fake_helper),
                    "--no-fallback-smoke",
                    env_overrides={"HOME": str(fake_home)},
                )
                self.assertEqual(prepare.returncode, 0, prepare.stderr)
                run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
                state_path = run_dir / "state.json"
                state = json.loads(state_path.read_text(encoding="utf-8"))
                state["orchestration"]["child_status"] = child_status
                state["orchestration"]["child_session_id"] = "child-terminal-fallback"
                state_path.write_text(
                    json.dumps(state, indent=2, sort_keys=True) + "\n"
                )

                stop_payload = {
                    "session_id": session_id,
                    "transcript_path": transcript_path,
                    "cwd": str(self.repo),
                    "hook_event_name": "Stop",
                    "model": "gpt-5.5",
                    "permission_mode": "acceptEdits",
                    "stop_hook_active": False,
                    "last_assistant_message": f"reconcile {child_status} child",
                }

                module = self._load_adapter_module()
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
                    with mock.patch.object(
                        module,
                        "_build_stop_continuation_prompt",
                        side_effect=RuntimeError("boom"),
                    ):
                        with mock.patch.object(
                            module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
                        ):
                            with mock.patch.object(module.sys, "stderr", stderr):
                                returncode = module._stop_hook(
                                    module.argparse.Namespace()
                                )

                self.assertEqual(returncode, 2)
                self.assertIn(f"--child-status {child_status}", stderr.getvalue())
                self.assertIn(
                    "--child-session-id child-terminal-fallback", stderr.getvalue()
                )

    def test_stop_hook_fallback_prompt_waits_for_active_child(self) -> None:
        fake_home = self.root / "home-stop-active-child-fallback"
        session_id = "session-active-child-fallback"
        transcript_path = "/tmp/transcript-active-child-fallback.jsonl"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="Keep waiting for an active waited delivery child",
                transcript_path=transcript_path,
            ),
            env_overrides={"HOME": str(fake_home)},
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            session_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["orchestration"]["child_status"] = "running"
        state["orchestration"]["child_session_id"] = "child-live"
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

        stop_payload = {
            "session_id": session_id,
            "transcript_path": transcript_path,
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "keep waiting for child",
        }

        module = self._load_adapter_module()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
            with mock.patch.object(
                module,
                "_build_stop_continuation_prompt",
                side_effect=RuntimeError("boom"),
            ):
                with mock.patch.object(
                    module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
                ):
                    with mock.patch.object(module.sys, "stderr", stderr):
                        returncode = module._stop_hook(module.argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertIn("Keep waiting for delivery child `child-live`", stderr.getvalue())

    def test_stop_hook_fallback_prompt_requires_spawn_when_child_missing(self) -> None:
        fake_home = self.root / "home-stop-no-child-fallback"
        session_id = "session-no-child-fallback"
        transcript_path = "/tmp/transcript-no-child-fallback.jsonl"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="Resume waited delivery before a child is attached",
                transcript_path=transcript_path,
            ),
            env_overrides={"HOME": str(fake_home)},
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            session_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        stop_payload = {
            "session_id": session_id,
            "transcript_path": transcript_path,
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "spawn the child next",
        }

        module = self._load_adapter_module()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
            with mock.patch.object(
                module,
                "_build_stop_continuation_prompt",
                side_effect=RuntimeError("boom"),
            ):
                with mock.patch.object(
                    module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
                ):
                    with mock.patch.object(module.sys, "stderr", stderr):
                        returncode = module._stop_hook(module.argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertIn(
            "Continue the required spawn -> attach-child -> wait sequence.",
            stderr.getvalue(),
        )

    def test_stop_hook_keeps_blocking_when_fallback_builder_fails(self) -> None:
        fake_home = self.root / "home-stop-last-resort"
        session_id = "session-last-resort"
        transcript_path = "/tmp/transcript-last-resort.jsonl"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="Use the last-resort waited delivery stop prompt",
                transcript_path=transcript_path,
            ),
            env_overrides={"HOME": str(fake_home)},
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            session_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["orchestration"]["child_status"] = "failed"
        state["orchestration"]["child_session_id"] = "child-last-resort"
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

        stop_payload = {
            "session_id": session_id,
            "transcript_path": transcript_path,
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "last resort prompt",
        }

        module = self._load_adapter_module()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
            with mock.patch.object(
                module,
                "_build_stop_continuation_prompt",
                side_effect=RuntimeError("continuation boom"),
            ):
                with mock.patch.object(
                    module,
                    "_build_stop_fallback_prompt",
                    side_effect=RuntimeError("fallback boom"),
                ):
                    with mock.patch.object(
                        module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
                    ):
                        with mock.patch.object(module.sys, "stderr", stderr):
                            returncode = module._stop_hook(module.argparse.Namespace())

        self.assertEqual(returncode, 2)
        self.assertIn(
            "A waited-delivery run for this session is still active.", stderr.getvalue()
        )
        self.assertIn(str(run_dir / "state.json"), stderr.getvalue())
        self.assertIn("--child-status failed", stderr.getvalue())
        self.assertIn("--child-session-id child-last-resort", stderr.getvalue())

    def test_stop_hook_keeps_blocking_when_last_resort_builder_fails(self) -> None:
        fake_home = self.root / "home-stop-emergency"
        session_id = "session-emergency"
        transcript_path = "/tmp/transcript-emergency.jsonl"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="Use the emergency waited delivery stop prompt",
                transcript_path=transcript_path,
            ),
            env_overrides={"HOME": str(fake_home)},
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            session_id,
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        run_dir = pathlib.Path(json.loads(prepare.stdout)["run_dir"])
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["orchestration"]["child_status"] = "failed"
        state["orchestration"]["child_session_id"] = "child-emergency"
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

        stop_payload = {
            "session_id": session_id,
            "transcript_path": transcript_path,
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "emergency prompt",
        }

        module = self._load_adapter_module()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False):
            with mock.patch.object(
                module,
                "_build_stop_continuation_prompt",
                side_effect=RuntimeError("continuation boom"),
            ):
                with mock.patch.object(
                    module,
                    "_build_stop_fallback_prompt",
                    side_effect=RuntimeError("fallback boom"),
                ):
                    with mock.patch.object(
                        module,
                        "_build_stop_last_resort_prompt",
                        side_effect=RuntimeError("last resort boom"),
                    ):
                        with mock.patch.object(
                            module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
                        ):
                            with mock.patch.object(module.sys, "stderr", stderr):
                                returncode = module._stop_hook(
                                    module.argparse.Namespace()
                                )

        self.assertEqual(returncode, 2)
        self.assertIn("Run this from the repo root:", stderr.getvalue())
        self.assertIn("--child-status failed", stderr.getvalue())
        self.assertIn("--child-session-id child-emergency", stderr.getvalue())

    def test_stop_hook_fails_open_when_prompt_write_fails(self) -> None:
        fake_home = self.root / "home-stop-write-fail"
        self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id="session-write-fail",
                prompt="Block on active waited delivery",
                transcript_path="/tmp/transcript-write-fail.jsonl",
            ),
            env_overrides={"HOME": str(fake_home)},
        )
        prepare = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--session-id",
            "session-write-fail",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env_overrides={"HOME": str(fake_home)},
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        stop_payload = {
            "session_id": "session-write-fail",
            "transcript_path": "/tmp/transcript-write-fail.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "write fails",
        }

        class BrokenStderr:
            def __init__(self) -> None:
                self.calls = 0

            def write(self, _: str) -> int:
                self.calls += 1
                raise BrokenPipeError("stderr closed")

            def flush(self) -> None:
                return None

        module = self._load_adapter_module()
        broken_stderr = BrokenStderr()
        with mock.patch.dict(
            os.environ,
            {"HOME": str(fake_home), "WAITED_DELIVERY_HOOK_DEBUG": "1"},
            clear=False,
        ):
            with mock.patch.object(
                module.sys, "stdin", io.StringIO(json.dumps(stop_payload))
            ):
                with mock.patch.object(module.sys, "stderr", broken_stderr):
                    returncode = module._stop_hook(module.argparse.Namespace())

        self.assertEqual(returncode, 0)
        self.assertGreaterEqual(broken_stderr.calls, 1)
        log_path = self._home_log_dir(fake_home) / "waited-delivery-hooks.jsonl"
        entries = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(entries[-1]["hook_command"], "stop-hook")
        self.assertEqual(entries[-1]["error_type"], "BrokenPipeError")
        self.assertEqual(entries[-1]["session_id"], "session-write-fail")


if __name__ == "__main__":
    unittest.main()
