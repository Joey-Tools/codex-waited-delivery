"""Compatibility tests for the historical waited-delivery hook adapter."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
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
import uuid
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
SCHEMA_V2_CLIENT_PATH = (
    pathlib.Path(__file__).resolve().parent / "fixtures" / "adapter_index_v2_client.py"
)


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    umask: int = -1,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
        umask=umask,
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
        umask: int = -1,
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
            umask=umask,
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

    def _prepare_active_args(
        self,
        module,
        *,
        session_id: str,
        run_id: str,
    ) -> argparse.Namespace:
        return module._build_parser().parse_args(
            [
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
            ]
        )

    def _seed_interrupted_preparation(
        self,
        module,
        *,
        session_id: str,
        run_id: str,
        preparation_id: str,
    ):
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            module._prepare_active_run(args)
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "preparing")
        return module._reservation_from_record(record)

    def _seed_cleanup_pending_without_lease(
        self,
        module,
        *,
        session_id: str,
        run_id: str,
        preparation_id: str,
    ):
        reservation = self._seed_interrupted_preparation(
            module,
            session_id=session_id,
            run_id=run_id,
            preparation_id=preparation_id,
        )
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        pending = module._cas_preparation_cleanup_pending(
            self.repo.resolve(),
            reservation,
            expected_record=record,
            reason="test cleanup pending before lease unlink",
        )
        lease_fd = module._acquire_preparation_lease(
            self.repo.resolve(),
            reservation,
        )
        try:
            module._remove_preparation_lease(
                self.repo.resolve(),
                reservation,
                lease_fd,
            )
        finally:
            os.close(lease_fd)
        self.assertFalse(pathlib.Path(reservation.lease_path).exists())
        return reservation, pending

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

    def test_schema_v2_client_fails_closed_on_schema_v3_cleanup_pending(
        self,
    ) -> None:
        module = self._load_adapter_module()
        session_id = "session-v2-client-fail-closed"
        preparation_id = "d1" * 16
        reservation = self._seed_interrupted_preparation(
            module,
            session_id=session_id,
            run_id="v2-client-fail-closed",
            preparation_id=preparation_id,
        )
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        module._cas_preparation_cleanup_pending(
            self.repo.resolve(),
            reservation,
            expected_record=record,
            reason="schema-v3 compatibility fixture",
        )
        before = self._index_path().read_bytes()

        completed = run(
            [
                sys.executable,
                str(SCHEMA_V2_CLIENT_PATH),
                "observe",
                "--index",
                str(self._index_path()),
                "--session-id",
                session_id,
                "--cwd",
                str(self.repo),
                "--started-at",
                "2026-07-30T00:00:00+00:00",
                "--prompt",
                "must not rewrite cleanup_pending as active",
            ]
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported adapter index schema", completed.stderr)
        self.assertEqual(self._index_path().read_bytes(), before)
        durable = json.loads(before)["sessions"][session_id]
        self.assertEqual(durable["status"], module.CLEANUP_PENDING_STATUS)
        self.assertEqual(durable["run_dir"], reservation.run_dir)
        self.assertEqual(durable["preparation_id"], preparation_id)

    def test_schema_v3_reader_recovers_frozen_schema_v2_preparation(
        self,
    ) -> None:
        module = self._load_adapter_module()
        session_id = "session-v2-preparation"
        preparation_id = "d2" * 16
        run_id = "v2-preparation"
        run_dir = self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id
        lease_path = module._preparation_lease_path(
            self.repo.resolve(),
            preparation_id,
        )
        started_at = "2026-07-30T00:00:00+00:00"
        seeded = run(
            [
                sys.executable,
                str(SCHEMA_V2_CLIENT_PATH),
                "seed-preparing",
                "--index",
                str(self._index_path()),
                "--session-id",
                session_id,
                "--cwd",
                str(self.repo),
                "--started-at",
                started_at,
                "--run-dir",
                str(run_dir),
                "--run-id",
                run_id,
                "--preparation-id",
                preparation_id,
                "--lease-path",
                str(lease_path),
            ]
        )
        self.assertEqual(seeded.returncode, 0, seeded.stderr)
        legacy = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(legacy["schema_version"], 2)
        reservation = module.PreparationReservation(
            session_id=session_id,
            preparation_id=preparation_id,
            run_id=run_id,
            run_dir=str(run_dir),
            lease_path=str(lease_path),
            started_at=started_at,
        )
        lease_fd = module._create_preparation_lease(
            self.repo.resolve(),
            reservation,
        )
        os.close(lease_fd)
        clear_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
                "--action",
                "clear-absent",
            ]
        )

        with mock.patch.object(module.sys, "stdout", io.StringIO()):
            self.assertEqual(module._recover_active_run(clear_args), 0)

        migrated = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertEqual(migrated["schema_version"], module.INDEX_SCHEMA_VERSION)
        record = migrated["sessions"][session_id]
        self.assertEqual(record["status"], module.CLEANUP_COMPLETE_STATUS)
        self.assertEqual(record["preparation_id"], preparation_id)
        self.assertEqual(record["run_dir"], str(run_dir))
        self.assertFalse(lease_path.exists())

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

    def test_prepare_active_run_accepts_exact_prospective_index_limit(self) -> None:
        session_id = "session-prepare-exact-limit"
        run_id = "prepare-exact-limit"
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        fixed_now = "2026-07-30T04:05:06+00:00"
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        preparation_id = "1" * 32
        prospective_run_dir = (
            self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id
        )
        prospective_index = json.loads(self._index_path().read_text(encoding="utf-8"))
        record = prospective_index["sessions"][session_id]
        record["run_dir"] = str(prospective_run_dir)
        record["status"] = "preparing"
        record["updated_at"] = fixed_now
        record["preparation_id"] = preparation_id
        record["preparation_run_id"] = run_id
        record["preparation_lease_path"] = str(
            module._preparation_lease_path(self.repo.resolve(), preparation_id)
        )
        record["preparation_started_at"] = fixed_now
        record["preparation_reason"] = None
        prospective_index["latest_session_id"] = session_id
        prospective_content = module._serialize_index_for_commit(
            prospective_index,
            transaction_time=fixed_now,
            context="test prospective index",
        )
        recovery_projection = copy.deepcopy(prospective_index)
        recovery_record = recovery_projection["sessions"][session_id]
        recovery_record["status"] = "recovery_required"
        recovery_record["preparation_reason"] = (
            "x" * module.PREPARATION_REASON_MAX_CHARS
        )
        recovery_projection["updated_at"] = fixed_now
        projected_content = (
            json.dumps(
                recovery_projection,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self.assertLess(len(prospective_content), len(projected_content))
        captured_stdout = io.StringIO()
        real_bridge = module._run_bridge_json_with_lease
        saw_durable_reservation = False

        def inspect_then_create(
            lease_fd: int,
            *bridge_args: str,
        ) -> dict[str, object]:
            nonlocal saw_durable_reservation
            run_id_index = bridge_args.index("--run-id") + 1
            self.assertEqual(bridge_args[run_id_index], run_id)
            preparation_index = bridge_args.index("--preparation-id") + 1
            self.assertEqual(bridge_args[preparation_index], preparation_id)
            durable = json.loads(self._index_path().read_text(encoding="utf-8"))
            durable_record = durable["sessions"][session_id]
            self.assertEqual(durable_record["status"], "preparing")
            self.assertEqual(durable_record["preparation_id"], preparation_id)
            self.assertEqual(durable_record["run_dir"], str(prospective_run_dir))
            saw_durable_reservation = True
            return real_bridge(lease_fd, *bridge_args)

        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "INDEX_MAX_BYTES",
                len(projected_content),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=inspect_then_create,
            ),
            mock.patch.object(module.sys, "stdout", captured_stdout),
        ):
            self.assertEqual(module._prepare_active_run(args), 0)

        self.assertTrue(saw_durable_reservation)
        self.assertTrue(prospective_run_dir.is_dir())
        committed = json.loads(self._index_path().read_text(encoding="utf-8"))
        committed_record = committed["sessions"][session_id]
        self.assertEqual(committed_record["status"], "active")
        self.assertEqual(committed_record["preparation_id"], preparation_id)
        self.assertFalse(
            pathlib.Path(committed_record["preparation_lease_path"]).exists()
        )
        state = json.loads(
            (prospective_run_dir / "state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(state["schema_version"], 5)
        self.assertEqual(state["preparation_id"], preparation_id)
        self.assertEqual(
            json.loads(captured_stdout.getvalue())["run_dir"],
            str(prospective_run_dir),
        )

    def test_prepare_active_run_capacity_preflight_has_no_side_effects(
        self,
    ) -> None:
        session_id = "session-prepare-over-limit"
        run_id = "prepare-over-limit"
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        fixed_now = "2026-07-30T05:06:07+00:00"
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        preparation_id = "2" * 32
        prospective_run_dir = (
            self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id
        )
        prospective_index = json.loads(self._index_path().read_text(encoding="utf-8"))
        record = prospective_index["sessions"][session_id]
        record["run_dir"] = str(prospective_run_dir)
        record["status"] = "preparing"
        record["updated_at"] = fixed_now
        record["preparation_id"] = preparation_id
        record["preparation_run_id"] = run_id
        record["preparation_lease_path"] = str(
            module._preparation_lease_path(self.repo.resolve(), preparation_id)
        )
        record["preparation_started_at"] = fixed_now
        record["preparation_reason"] = None
        prospective_index["latest_session_id"] = session_id
        prospective_content = module._serialize_index_for_commit(
            prospective_index,
            transaction_time=fixed_now,
            context="test prospective index",
        )
        recovery_projection = copy.deepcopy(prospective_index)
        recovery_record = recovery_projection["sessions"][session_id]
        recovery_record["status"] = "recovery_required"
        recovery_record["preparation_reason"] = (
            "x" * module.PREPARATION_REASON_MAX_CHARS
        )
        recovery_projection["updated_at"] = fixed_now
        projected_content = (
            json.dumps(
                recovery_projection,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        original_index = self._index_path().read_bytes()
        self.assertLess(len(original_index), len(prospective_content))
        self.assertLess(len(prospective_content), len(projected_content))
        captured_stdout = io.StringIO()

        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "INDEX_MAX_BYTES",
                len(projected_content) - 1,
            ),
            mock.patch.object(module, "_create_preparation_lease") as lease_mock,
            mock.patch.object(module, "_run_bridge_json_with_lease") as bridge_mock,
            mock.patch.object(module.sys, "stdout", captured_stdout),
            self.assertRaisesRegex(
                module.RunSafetyError,
                "would consume reserved preparation recovery capacity",
            ),
        ):
            module._prepare_active_run(args)

        lease_mock.assert_not_called()
        bridge_mock.assert_not_called()
        self.assertFalse(prospective_run_dir.exists())
        self.assertEqual(captured_stdout.getvalue(), "")
        self.assertEqual(self._index_path().read_bytes(), original_index)

    def test_prepare_active_run_rejects_concurrent_index_drift_without_output(
        self,
    ) -> None:
        session_id = "session-prepare-index-drift"
        run_id = "prepare-index-drift"
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        fixed_now = "2026-07-30T06:07:08+00:00"
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        preparation_id = "3" * 32
        prospective_run_dir = (
            self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id
        )
        replacement_index = json.loads(self._index_path().read_text(encoding="utf-8"))
        replacement_index["sessions"][session_id]["last_prompt"] = (
            "out-of-band concurrent update"
        )
        replacement_index["updated_at"] = "2026-07-30T06:07:09+00:00"
        replacement_content = (
            json.dumps(
                replacement_index,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        captured_stdout = io.StringIO()
        real_bridge = module._run_bridge_json_with_lease

        def create_run_then_drift(
            lease_fd: int,
            *bridge_args: str,
        ) -> dict[str, object]:
            durable = json.loads(self._index_path().read_text(encoding="utf-8"))
            self.assertEqual(
                durable["sessions"][session_id]["status"],
                "preparing",
            )
            replacement_path = self._index_path().with_name(
                ".index.concurrent-replacement"
            )
            replacement_path.write_bytes(replacement_content)
            replacement_path.chmod(0o600)
            os.replace(replacement_path, self._index_path())
            return real_bridge(lease_fd, *bridge_args)

        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=create_run_then_drift,
            ),
            mock.patch.object(module.sys, "stdout", captured_stdout),
            self.assertRaisesRegex(
                module.UserError,
                "recovery fence update also failed",
            ),
        ):
            module._prepare_active_run(args)

        self.assertEqual(captured_stdout.getvalue(), "")
        self.assertEqual(self._index_path().read_bytes(), replacement_content)
        self.assertTrue(prospective_run_dir.is_dir())
        committed = json.loads(self._index_path().read_text(encoding="utf-8"))
        self.assertIsNone(committed["sessions"][session_id]["run_dir"])
        state = json.loads(
            (prospective_run_dir / "state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(state["preparation_id"], preparation_id)
        self.assertTrue(
            module._preparation_lease_path(
                self.repo.resolve(),
                preparation_id,
            ).exists()
        )

    def test_reservation_commit_failures_never_launch_bridge(self) -> None:
        for failure_point in ("before-replace", "after-replace"):
            with self.subTest(failure_point=failure_point):
                session_id = f"session-reservation-{failure_point}"
                run_id = f"reservation-{failure_point}"
                preparation_id = (
                    "a1" * 16 if failure_point == "before-replace" else "b2" * 16
                )
                observed = self._run_adapter(
                    "user-prompt-submit-hook",
                    input_payload=self._session_payload(session_id=session_id),
                )
                self.assertEqual(observed.returncode, 0, observed.stderr)
                module = self._load_adapter_module()
                args = self._prepare_active_args(
                    module,
                    session_id=session_id,
                    run_id=run_id,
                )
                original_index = self._index_path().read_bytes()
                real_save = module._atomic_save_index_at
                save_calls = 0

                def fail_reservation_commit(*save_args, **save_kwargs):
                    nonlocal save_calls
                    save_calls += 1
                    if failure_point == "before-replace":
                        raise module.RunSafetyError(
                            "simulated reservation failure before replacement"
                        )
                    real_save(*save_args, **save_kwargs)
                    raise module.RunSafetyError(
                        "simulated reservation fsync ambiguity after replacement"
                    )

                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        module.uuid,
                        "uuid4",
                        return_value=uuid.UUID(hex=preparation_id),
                    ),
                    mock.patch.object(
                        module,
                        "_atomic_save_index_at",
                        side_effect=fail_reservation_commit,
                    ),
                    mock.patch.object(
                        module,
                        "_run_bridge_json_with_lease",
                    ) as bridge,
                    mock.patch.object(module.sys, "stdout", stdout),
                    self.assertRaises(module.UserError),
                ):
                    module._prepare_active_run(args)
                self.assertEqual(save_calls, 1)
                bridge.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                lease_path = module._preparation_lease_path(
                    self.repo.resolve(),
                    preparation_id,
                )
                if failure_point == "before-replace":
                    self.assertEqual(self._index_path().read_bytes(), original_index)
                    self.assertFalse(lease_path.exists())
                else:
                    record = json.loads(self._index_path().read_text(encoding="utf-8"))[
                        "sessions"
                    ][session_id]
                    self.assertEqual(record["status"], "preparing")
                    self.assertEqual(record["preparation_id"], preparation_id)
                    self.assertTrue(lease_path.is_file())
                self.assertFalse(
                    (self.repo / ".codex-tmp" / "waited-delivery" / run_id).exists()
                )

    def test_prepare_bridge_failure_without_run_clears_exact_reservation(self) -> None:
        session_id = "session-bridge-failure-absent"
        run_id = "bridge-failure-absent"
        preparation_id = "4" * 32
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        stdout = io.StringIO()
        saw_busy_lease = False

        def fail_before_create(
            _lease_fd: int,
            *_bridge_args: str,
        ) -> dict[str, object]:
            nonlocal saw_busy_lease
            doctor = self._run_adapter(
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
                "--action",
                "doctor",
            )
            self.assertEqual(doctor.returncode, 0, doctor.stderr)
            self.assertEqual(json.loads(doctor.stdout)["status"], "in_progress")
            saw_busy_lease = True
            raise module.UserError("simulated bridge failure before creation")

        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=fail_before_create,
            ),
            mock.patch.object(module.sys, "stdout", stdout),
            self.assertRaisesRegex(module.UserError, "cleared safely"),
        ):
            module._prepare_active_run(args)

        self.assertTrue(saw_busy_lease)
        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], module.CLEANUP_COMPLETE_STATUS)
        self.assertEqual(
            record["run_dir"],
            str(self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id),
        )
        self.assertEqual(record["preparation_id"], preparation_id)
        self.assertFalse(
            module._preparation_lease_path(
                self.repo.resolve(),
                preparation_id,
            ).exists()
        )
        self.assertFalse(
            (self.repo / ".codex-tmp" / "waited-delivery" / run_id).exists()
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork semantics")
    def test_bridge_failure_with_inherited_writer_never_clears_reservation(
        self,
    ) -> None:
        session_id = "session-bridge-failure-inherited-writer"
        run_id = "bridge-failure-inherited-writer"
        preparation_id = "e5" * 16
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        run_dir = self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id
        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        child_pid: int | None = None
        stdout = io.StringIO()

        def fail_while_inherited_writer_survives(
            _lease_fd: int,
            *_bridge_args: str,
        ) -> dict[str, object]:
            nonlocal child_pid
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    os.close(ready_read)
                    os.close(release_write)
                    os.write(ready_write, b"1")
                    os.close(ready_write)
                    if os.read(release_read, 1) != b"1":
                        os._exit(96)
                    os.close(release_read)
                    run_dir.mkdir(parents=True, mode=0o700)
                    run_dir.chmod(0o700)
                except BaseException:
                    os._exit(97)
                os._exit(0)
            os.close(ready_write)
            os.close(release_read)
            self.assertEqual(os.read(ready_read, 1), b"1")
            os.close(ready_read)
            raise module.UserError(
                "simulated bridge death before inherited writer creates the run"
            )

        try:
            with (
                mock.patch.object(
                    module.uuid,
                    "uuid4",
                    return_value=uuid.UUID(hex=preparation_id),
                ),
                mock.patch.object(
                    module,
                    "_run_bridge_json_with_lease",
                    side_effect=fail_while_inherited_writer_survives,
                ),
                mock.patch.object(
                    module,
                    "_expected_run_entry_presence",
                ) as presence,
                mock.patch.object(module.sys, "stdout", stdout),
                self.assertRaisesRegex(module.UserError, "remains recorded"),
            ):
                module._prepare_active_run(args)
            presence.assert_not_called()
            self.assertEqual(stdout.getvalue(), "")
            record = json.loads(self._index_path().read_text(encoding="utf-8"))[
                "sessions"
            ][session_id]
            self.assertEqual(record["status"], "recovery_required")
            self.assertEqual(record["preparation_id"], preparation_id)
            self.assertIn(
                "inherited-writer quiescence could not be proved",
                record["preparation_reason"],
            )
            self.assertTrue(pathlib.Path(record["preparation_lease_path"]).is_file())

            os.write(release_write, b"1")
            os.close(release_write)
            release_write = -1
            assert child_pid is not None
            waited_pid, wait_status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertTrue(os.WIFEXITED(wait_status))
            self.assertEqual(os.WEXITSTATUS(wait_status), 0)
            child_pid = None
            self.assertTrue(run_dir.is_dir())
            preserved = json.loads(self._index_path().read_text(encoding="utf-8"))[
                "sessions"
            ][session_id]
            self.assertEqual(preserved["status"], "recovery_required")
            self.assertEqual(preserved["run_dir"], str(run_dir))
        finally:
            for file_descriptor in (
                ready_read,
                ready_write,
                release_read,
                release_write,
            ):
                if file_descriptor >= 0:
                    try:
                        os.close(file_descriptor)
                    except OSError:
                        pass
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child_pid, 0)

    def test_ambiguous_inherited_lease_close_is_never_retried_or_cleared(
        self,
    ) -> None:
        session_id = "session-ambiguous-inherited-close"
        run_id = "ambiguous-inherited-close"
        preparation_id = "f6" * 16
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        real_retire = module._retire_inherited_preparation_lease
        stdout = io.StringIO()

        def close_then_report_ambiguity(lease_fd: int) -> None:
            real_retire(lease_fd)
            raise OSError("simulated ambiguous close result")

        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=module.UserError("simulated bridge failure"),
            ),
            mock.patch.object(
                module,
                "_retire_inherited_preparation_lease",
                side_effect=close_then_report_ambiguity,
            ) as retire,
            mock.patch.object(
                module,
                "_expected_run_entry_presence",
            ) as presence,
            mock.patch.object(module.sys, "stdout", stdout),
            self.assertRaisesRegex(module.UserError, "remains recorded"),
        ):
            module._prepare_active_run(args)

        retire.assert_called_once()
        presence.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "recovery_required")
        self.assertEqual(record["preparation_id"], preparation_id)
        self.assertIn(
            "lease ownership could not be retired exactly once",
            record["preparation_reason"],
        )
        self.assertTrue(pathlib.Path(record["preparation_lease_path"]).is_file())
        self.assertFalse(
            (self.repo / ".codex-tmp" / "waited-delivery" / run_id).exists()
        )

    def test_partial_prepare_fences_stop_and_active_mutations(self) -> None:
        session_id = "session-partial-preparation"
        run_id = "partial-preparation"
        preparation_id = "5" * 32
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        run_dir = self.repo.resolve() / ".codex-tmp" / "waited-delivery" / run_id
        stdout = io.StringIO()

        def create_partial_then_fail(
            _lease_fd: int,
            *_bridge_args: str,
        ) -> dict[str, object]:
            run_dir.mkdir(parents=True, mode=0o700)
            run_dir.chmod(0o700)
            raise module.UserError("simulated failure after mkdir")

        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=create_partial_then_fail,
            ),
            mock.patch.object(module.sys, "stdout", stdout),
            self.assertRaisesRegex(module.UserError, "remains recorded"),
        ):
            module._prepare_active_run(args)

        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "recovery_required")
        self.assertEqual(record["preparation_id"], preparation_id)
        self.assertTrue(pathlib.Path(record["preparation_lease_path"]).is_file())

        stop_stdout = io.StringIO()
        stop_stderr = io.StringIO()
        with (
            mock.patch.object(
                module.sys,
                "stdin",
                io.StringIO(json.dumps(self._stop_payload_for(session_id))),
            ),
            mock.patch.object(module.sys, "stdout", stop_stdout),
            mock.patch.object(module.sys, "stderr", stop_stderr),
            mock.patch.object(module, "_load_stop_run_state") as load_run,
        ):
            self.assertEqual(module._stop_hook(argparse.Namespace()), 2)
        load_run.assert_not_called()
        self.assertEqual(stop_stdout.getvalue(), "")
        self.assertIn("Do not finish.", stop_stderr.getvalue())
        self.assertIn(preparation_id, stop_stderr.getvalue())
        self.assertIn("recover-active-run", stop_stderr.getvalue())

        retry_args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id="partial-preparation-retry",
        )
        with (
            mock.patch.object(module, "_run_bridge_json_with_lease") as bridge,
            self.assertRaisesRegex(module.UserError, "unfinished recovery_required"),
        ):
            module._prepare_active_run(retry_args)
        bridge.assert_not_called()

        attach_args = module._build_parser().parse_args(
            [
                "attach-child-active-run",
                "--repo",
                str(self.repo),
                "--run-dir",
                str(run_dir),
                "--child-session-id",
                "child-partial",
                "--session-id",
                session_id,
            ]
        )
        with (
            mock.patch.object(module, "_run_bridge_passthrough") as bridge,
            self.assertRaisesRegex(module.UserError, "recovery_required"),
        ):
            module._attach_child_active_run(attach_args)
        bridge.assert_not_called()

    def test_prepare_rejects_mismatched_bridge_receipt_without_output(self) -> None:
        session_id = "session-mismatched-receipt"
        run_id = "mismatched-receipt"
        preparation_id = "c3" * 16
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                return_value={
                    "run_dir": str(self.root / "unexpected-run"),
                    "preparation_id": "wrong-preparation",
                    "preparation_lease_inherited": True,
                },
            ),
            mock.patch.object(module.sys, "stdout", stdout),
            self.assertRaisesRegex(module.UserError, "does not match the exact"),
        ):
            module._prepare_active_run(args)
        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "recovery_required")
        self.assertEqual(record["preparation_id"], preparation_id)
        self.assertIn("does not match", record["preparation_reason"])
        self.assertTrue(pathlib.Path(record["preparation_lease_path"]).is_file())

    def test_interrupted_prepare_remains_recoverable_and_clears_only_when_quiescent(
        self,
    ) -> None:
        session_id = "session-interrupted-preparation"
        run_id = "interrupted-preparation"
        preparation_id = "6" * 32
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=KeyboardInterrupt,
            ),
            mock.patch.object(module.sys, "stdout", stdout),
            self.assertRaises(KeyboardInterrupt),
        ):
            module._prepare_active_run(args)
        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "preparing")
        self.assertEqual(record["preparation_id"], preparation_id)
        observed_again = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(
                session_id=session_id,
                prompt="updated while preparation remains fenced",
                transcript_path="/tmp/updated-interrupted.jsonl",
            ),
        )
        self.assertEqual(observed_again.returncode, 0, observed_again.stderr)
        preserved = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(preserved["status"], "preparing")
        self.assertEqual(preserved["preparation_id"], preparation_id)
        self.assertEqual(preserved["run_dir"], record["run_dir"])
        self.assertEqual(
            preserved["transcript_path"],
            "/tmp/updated-interrupted.jsonl",
        )

        doctor_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
            ]
        )
        doctor_stdout = io.StringIO()
        with mock.patch.object(module.sys, "stdout", doctor_stdout):
            self.assertEqual(module._recover_active_run(doctor_args), 0)
        self.assertEqual(json.loads(doctor_stdout.getvalue())["status"], "absent")

        clear_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
                "--action",
                "clear-absent",
            ]
        )
        clear_stdout = io.StringIO()
        with mock.patch.object(module.sys, "stdout", clear_stdout):
            self.assertEqual(module._recover_active_run(clear_args), 0)
        self.assertEqual(json.loads(clear_stdout.getvalue())["status"], "cleared")
        cleared = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(cleared["status"], module.CLEANUP_COMPLETE_STATUS)
        self.assertEqual(cleared["run_dir"], record["run_dir"])
        self.assertEqual(cleared["preparation_id"], preparation_id)
        self.assertFalse(
            module._preparation_lease_path(
                self.repo.resolve(),
                preparation_id,
            ).exists()
        )

    def test_clear_absent_recovers_both_cleanup_pending_crash_points(self) -> None:
        cases = (
            (
                "before-lease-unlink",
                "a8" * 16,
                "cleanup_pending_lease_present",
                True,
            ),
            (
                "before-final-cas",
                "b9" * 16,
                "cleanup_pending_final_cas",
                False,
            ),
        )
        for label, preparation_id, doctor_status, lease_present in cases:
            with self.subTest(case=label):
                module = self._load_adapter_module()
                session_id = f"session-{label}"
                run_id = f"run-{label}"
                reservation = self._seed_interrupted_preparation(
                    module,
                    session_id=session_id,
                    run_id=run_id,
                    preparation_id=preparation_id,
                )
                original_record = json.loads(
                    self._index_path().read_text(encoding="utf-8")
                )["sessions"][session_id]
                clear_args = module._build_parser().parse_args(
                    [
                        "recover-active-run",
                        "--repo",
                        str(self.repo),
                        "--session-id",
                        session_id,
                        "--preparation-id",
                        preparation_id,
                        "--action",
                        "clear-absent",
                    ]
                )
                if label == "before-lease-unlink":
                    patch_target = "_remove_preparation_lease"
                    failure_message = "simulated failure before lease unlink"
                else:
                    patch_target = "_cas_clear_cleanup_pending"
                    failure_message = "simulated failure before final CAS"
                with (
                    mock.patch.object(
                        module,
                        patch_target,
                        side_effect=module.RunSafetyError(failure_message),
                    ),
                    self.assertRaisesRegex(
                        module.RunSafetyError,
                        failure_message,
                    ),
                ):
                    module._recover_active_run(clear_args)

                pending = json.loads(self._index_path().read_text(encoding="utf-8"))[
                    "sessions"
                ][session_id]
                self.assertEqual(
                    pending["status"],
                    module.CLEANUP_PENDING_STATUS,
                )
                for field in (
                    "run_dir",
                    "preparation_id",
                    "preparation_run_id",
                    "preparation_lease_path",
                    "preparation_started_at",
                ):
                    self.assertEqual(pending[field], original_record[field])
                self.assertEqual(
                    pathlib.Path(reservation.lease_path).exists(),
                    lease_present,
                )

                doctor_args = module._build_parser().parse_args(
                    [
                        "recover-active-run",
                        "--repo",
                        str(self.repo),
                        "--session-id",
                        session_id,
                        "--preparation-id",
                        preparation_id,
                    ]
                )
                doctor_stdout = io.StringIO()
                with mock.patch.object(module.sys, "stdout", doctor_stdout):
                    self.assertEqual(module._recover_active_run(doctor_args), 0)
                self.assertEqual(
                    json.loads(doctor_stdout.getvalue())["status"],
                    doctor_status,
                )

                clear_stdout = io.StringIO()
                with mock.patch.object(module.sys, "stdout", clear_stdout):
                    self.assertEqual(module._recover_active_run(clear_args), 0)
                self.assertEqual(
                    json.loads(clear_stdout.getvalue())["status"],
                    "cleared",
                )
                cleared = json.loads(self._index_path().read_text(encoding="utf-8"))[
                    "sessions"
                ][session_id]
                self.assertEqual(
                    cleared["status"],
                    module.CLEANUP_COMPLETE_STATUS,
                )
                self.assertEqual(cleared["run_dir"], reservation.run_dir)
                self.assertEqual(cleared["preparation_id"], preparation_id)
                self.assertFalse(pathlib.Path(reservation.lease_path).exists())

    def test_absent_lease_parent_is_fsynced_before_cleanup_final_cas(self) -> None:
        module = self._load_adapter_module()
        session_id = "session-cleanup-parent-fsync"
        preparation_id = "bf" * 16
        self._seed_interrupted_preparation(
            module,
            session_id=session_id,
            run_id="cleanup-parent-fsync",
            preparation_id=preparation_id,
        )
        clear_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
                "--action",
                "clear-absent",
            ]
        )
        with (
            mock.patch.object(
                module,
                "_cas_clear_cleanup_pending",
                side_effect=module.RunSafetyError(
                    "simulated crash before cleanup final CAS"
                ),
            ),
            self.assertRaisesRegex(
                module.RunSafetyError,
                "simulated crash before cleanup final CAS",
            ),
        ):
            module._recover_active_run(clear_args)

        events: list[str] = []
        real_fsync_absence = module._fsync_preparation_lease_absence
        real_complete = module._mark_preparation_cleanup_complete

        def fsync_absence(*args, **kwargs):
            real_fsync_absence(*args, **kwargs)
            events.append("lease-parent-fsynced")

        def complete_reservation(*args, **kwargs):
            events.append("cleanup-tombstone-committed")
            return real_complete(*args, **kwargs)

        with (
            mock.patch.object(
                module,
                "_fsync_preparation_lease_absence",
                side_effect=fsync_absence,
            ),
            mock.patch.object(
                module,
                "_mark_preparation_cleanup_complete",
                side_effect=complete_reservation,
            ),
            mock.patch.object(module.sys, "stdout", io.StringIO()),
        ):
            self.assertEqual(module._recover_active_run(clear_args), 0)

        self.assertEqual(
            events,
            ["lease-parent-fsynced", "cleanup-tombstone-committed"],
        )

    def test_cleanup_pending_final_cas_rejects_observation_race(self) -> None:
        module = self._load_adapter_module()
        session_id = "session-cleanup-final-cas-race"
        preparation_id = "ca" * 16
        reservation = self._seed_interrupted_preparation(
            module,
            session_id=session_id,
            run_id="cleanup-final-cas-race",
            preparation_id=preparation_id,
        )
        clear_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
                "--action",
                "clear-absent",
            ]
        )
        real_remove = module._remove_preparation_lease

        def remove_then_observe(*args, **kwargs):
            real_remove(*args, **kwargs)
            observed = self._run_adapter(
                "user-prompt-submit-hook",
                input_payload=self._session_payload(
                    session_id=session_id,
                    prompt="observation racing the final cleanup CAS",
                    transcript_path="/tmp/cleanup-final-cas-race.jsonl",
                ),
            )
            self.assertEqual(observed.returncode, 0, observed.stderr)

        with (
            mock.patch.object(
                module,
                "_remove_preparation_lease",
                side_effect=remove_then_observe,
            ),
            self.assertRaisesRegex(
                module.RunSafetyError,
                "changed before final CAS",
            ),
        ):
            module._recover_active_run(clear_args)

        pending = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(pending["status"], module.CLEANUP_PENDING_STATUS)
        self.assertEqual(
            pending["transcript_path"],
            "/tmp/cleanup-final-cas-race.jsonl",
        )
        self.assertEqual(pending["preparation_id"], preparation_id)
        self.assertFalse(pathlib.Path(reservation.lease_path).exists())

        doctor_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                preparation_id,
            ]
        )
        doctor_stdout = io.StringIO()
        with mock.patch.object(module.sys, "stdout", doctor_stdout):
            self.assertEqual(module._recover_active_run(doctor_args), 0)
        self.assertEqual(
            json.loads(doctor_stdout.getvalue())["status"],
            "cleanup_pending_final_cas",
        )

        with mock.patch.object(module.sys, "stdout", io.StringIO()):
            self.assertEqual(module._recover_active_run(clear_args), 0)
        cleared = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(cleared["status"], module.CLEANUP_COMPLETE_STATUS)
        self.assertEqual(cleared["preparation_id"], preparation_id)

    def test_cleanup_tombstone_survives_each_final_commit_uncertainty(
        self,
    ) -> None:
        cases = (
            "after-replace",
            "final-fsync",
            "readback",
            "post-commit-revalidation",
        )
        for case_number, case in enumerate(cases, start=1):
            with self.subTest(case=case):
                module = self._load_adapter_module()
                session_id = f"session-cleanup-uncertain-{case}"
                preparation_id = f"{case_number + 10:02x}" * 16
                reservation, _pending = self._seed_cleanup_pending_without_lease(
                    module,
                    session_id=session_id,
                    run_id=f"cleanup-uncertain-{case}",
                    preparation_id=preparation_id,
                )
                clear_args = module._build_parser().parse_args(
                    [
                        "recover-active-run",
                        "--repo",
                        str(self.repo),
                        "--session-id",
                        session_id,
                        "--preparation-id",
                        preparation_id,
                        "--action",
                        "clear-absent",
                    ]
                )
                if case == "after-replace":
                    real_replace = module.os.replace

                    def fail_after_replace(*replace_args, **replace_kwargs):
                        real_replace(*replace_args, **replace_kwargs)
                        raise OSError("simulated failure after index replacement")

                    patcher = mock.patch.object(
                        module.os,
                        "replace",
                        side_effect=fail_after_replace,
                    )
                elif case == "final-fsync":
                    real_fsync = module.os.fsync
                    raised = False

                    def fail_after_final_fsync(file_descriptor):
                        nonlocal raised
                        real_fsync(file_descriptor)
                        if raised or not self._index_path().exists():
                            return
                        durable = json.loads(
                            self._index_path().read_text(encoding="utf-8")
                        )["sessions"][session_id]
                        if durable["status"] == module.CLEANUP_COMPLETE_STATUS:
                            raised = True
                            raise OSError(
                                "simulated failure after final directory fsync"
                            )

                    patcher = mock.patch.object(
                        module.os,
                        "fsync",
                        side_effect=fail_after_final_fsync,
                    )
                elif case == "readback":
                    real_read = module._read_index_bytes_at

                    def fail_tombstone_readback(adapter_fd):
                        result = real_read(adapter_fd)
                        if result is not None:
                            durable = json.loads(result[0])["sessions"][session_id]
                            if durable["status"] == module.CLEANUP_COMPLETE_STATUS:
                                raise module.RunSafetyError(
                                    "simulated cleanup tombstone readback failure"
                                )
                        return result

                    patcher = mock.patch.object(
                        module,
                        "_read_index_bytes_at",
                        side_effect=fail_tombstone_readback,
                    )
                else:
                    real_revalidate = module._revalidate_index_directories

                    def fail_post_commit_revalidation(*revalidate_args):
                        real_revalidate(*revalidate_args)
                        if not self._index_path().exists():
                            return
                        durable = json.loads(
                            self._index_path().read_text(encoding="utf-8")
                        )["sessions"][session_id]
                        if durable["status"] == module.CLEANUP_COMPLETE_STATUS:
                            raise module.RunSafetyError(
                                "simulated post-commit directory revalidation failure"
                            )

                    patcher = mock.patch.object(
                        module,
                        "_revalidate_index_directories",
                        side_effect=fail_post_commit_revalidation,
                    )

                with (
                    patcher,
                    self.assertRaisesRegex(
                        module.RunSafetyError,
                        "simulated",
                    ),
                ):
                    module._recover_active_run(clear_args)

                durable = json.loads(self._index_path().read_text(encoding="utf-8"))[
                    "sessions"
                ][session_id]
                self.assertEqual(
                    durable["status"],
                    module.CLEANUP_COMPLETE_STATUS,
                )
                self.assertEqual(durable["run_dir"], reservation.run_dir)
                self.assertEqual(durable["preparation_id"], preparation_id)
                self.assertEqual(
                    durable["preparation_lease_path"],
                    reservation.lease_path,
                )
                retry_stdout = io.StringIO()
                with mock.patch.object(module.sys, "stdout", retry_stdout):
                    self.assertEqual(module._recover_active_run(clear_args), 0)
                self.assertEqual(
                    json.loads(retry_stdout.getvalue())["status"],
                    "cleared",
                )
                retried = json.loads(self._index_path().read_text(encoding="utf-8"))[
                    "sessions"
                ][session_id]
                self.assertEqual(
                    retried["status"],
                    module.CLEANUP_COMPLETE_STATUS,
                )
                self.assertEqual(retried["preparation_id"], preparation_id)

    def test_old_cleanup_retry_never_clears_a_new_reservation(self) -> None:
        module = self._load_adapter_module()
        session_id = "session-cleanup-new-reservation"
        old_preparation_id = "e1" * 16
        reservation, _pending = self._seed_cleanup_pending_without_lease(
            module,
            session_id=session_id,
            run_id="cleanup-old-reservation",
            preparation_id=old_preparation_id,
        )
        old_clear_args = module._build_parser().parse_args(
            [
                "recover-active-run",
                "--repo",
                str(self.repo),
                "--session-id",
                session_id,
                "--preparation-id",
                old_preparation_id,
                "--action",
                "clear-absent",
            ]
        )
        real_replace = module.os.replace

        def fail_after_replace(*replace_args, **replace_kwargs):
            real_replace(*replace_args, **replace_kwargs)
            raise OSError("simulated old cleanup replacement ambiguity")

        with (
            mock.patch.object(
                module.os,
                "replace",
                side_effect=fail_after_replace,
            ),
            self.assertRaisesRegex(module.RunSafetyError, "simulated"),
        ):
            module._recover_active_run(old_clear_args)
        tombstone = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(tombstone["status"], module.CLEANUP_COMPLETE_STATUS)
        self.assertEqual(tombstone["run_dir"], reservation.run_dir)

        new_preparation_id = "e2" * 16
        new_args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id="cleanup-new-reservation",
        )
        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=new_preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            module._prepare_active_run(new_args)
        new_record = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(new_record["status"], "preparing")
        self.assertEqual(new_record["preparation_id"], new_preparation_id)

        with self.assertRaisesRegex(
            module.RunSafetyError,
            "requested preparation id does not match",
        ):
            module._recover_active_run(old_clear_args)
        preserved = json.loads(self._index_path().read_text(encoding="utf-8"))[
            "sessions"
        ][session_id]
        self.assertEqual(preserved["status"], "preparing")
        self.assertEqual(preserved["preparation_id"], new_preparation_id)

    def test_bridge_failure_cleanup_orders_pending_unlink_and_final_cas(
        self,
    ) -> None:
        session_id = "session-bridge-cleanup-order"
        run_id = "bridge-cleanup-order"
        preparation_id = "cb" * 16
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        events: list[str] = []
        real_pending = module._cas_preparation_cleanup_pending
        real_remove = module._remove_preparation_lease
        real_clear = module._cas_clear_cleanup_pending

        def record_pending(*pending_args, **pending_kwargs):
            result = real_pending(*pending_args, **pending_kwargs)
            events.append("cleanup_pending")
            return result

        def record_remove(*remove_args, **remove_kwargs):
            record = json.loads(self._index_path().read_text(encoding="utf-8"))[
                "sessions"
            ][session_id]
            self.assertEqual(record["status"], module.CLEANUP_PENDING_STATUS)
            result = real_remove(*remove_args, **remove_kwargs)
            events.append("lease_unlinked_and_parent_fsynced")
            return result

        def record_clear(*clear_args, **clear_kwargs):
            self.assertFalse(
                module._preparation_lease_path(
                    self.repo.resolve(),
                    preparation_id,
                ).exists()
            )
            result = real_clear(*clear_args, **clear_kwargs)
            events.append("final_index_cas")
            return result

        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=module.UserError("simulated bridge failure"),
            ),
            mock.patch.object(
                module,
                "_cas_preparation_cleanup_pending",
                side_effect=record_pending,
            ),
            mock.patch.object(
                module,
                "_remove_preparation_lease",
                side_effect=record_remove,
            ),
            mock.patch.object(
                module,
                "_cas_clear_cleanup_pending",
                side_effect=record_clear,
            ),
            self.assertRaisesRegex(module.UserError, "cleared safely"),
        ):
            module._prepare_active_run(args)

        self.assertEqual(
            events,
            [
                "cleanup_pending",
                "lease_unlinked_and_parent_fsynced",
                "final_index_cas",
            ],
        )
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], module.CLEANUP_COMPLETE_STATUS)
        self.assertEqual(record["preparation_id"], preparation_id)

    def test_complete_failed_bridge_can_be_doctored_and_resumed(self) -> None:
        session_id = "session-complete-failed-bridge"
        run_id = "complete-failed-bridge"
        preparation_id = "7" * 32
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        real_bridge = module._run_bridge_json_with_lease
        stdout = io.StringIO()

        def complete_then_fail(
            lease_fd: int,
            *bridge_args: str,
        ) -> dict[str, object]:
            real_bridge(lease_fd, *bridge_args)
            raise module.UserError("simulated lost bridge receipt")

        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=complete_then_fail,
            ),
            mock.patch.object(module.sys, "stdout", stdout),
            self.assertRaisesRegex(module.UserError, "lost bridge receipt"),
        ):
            module._prepare_active_run(args)
        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "recovery_required")

        doctor = self._run_adapter(
            "recover-active-run",
            "--repo",
            str(self.repo),
            "--session-id",
            session_id,
            "--preparation-id",
            preparation_id,
            "--action",
            "doctor",
        )
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertEqual(
            json.loads(doctor.stdout)["status"],
            "complete_not_activated",
        )
        resumed = self._run_adapter(
            "recover-active-run",
            "--repo",
            str(self.repo),
            "--session-id",
            session_id,
            "--preparation-id",
            preparation_id,
            "--action",
            "resume",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads(resumed.stdout)["status"], "active")
        active = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["preparation_id"], preparation_id)
        self.assertFalse(pathlib.Path(active["preparation_lease_path"]).exists())

    def test_resume_rejects_mismatched_run_transaction_attestation(self) -> None:
        session_id = "session-mismatched-attestation"
        run_id = "mismatched-attestation"
        preparation_id = "d4" * 16
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        module = self._load_adapter_module()
        args = self._prepare_active_args(
            module,
            session_id=session_id,
            run_id=run_id,
        )
        real_bridge = module._run_bridge_json_with_lease

        def complete_then_fail(
            lease_fd: int,
            *bridge_args: str,
        ) -> dict[str, object]:
            real_bridge(lease_fd, *bridge_args)
            raise module.UserError("simulated receipt loss before attestation tamper")

        with (
            mock.patch.object(
                module.uuid,
                "uuid4",
                return_value=uuid.UUID(hex=preparation_id),
            ),
            mock.patch.object(
                module,
                "_run_bridge_json_with_lease",
                side_effect=complete_then_fail,
            ),
            self.assertRaises(module.UserError),
        ):
            module._prepare_active_run(args)
        run_dir = self.repo / ".codex-tmp" / "waited-delivery" / run_id
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["preparation_id"] = "tampered-transaction"
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        resumed = self._run_adapter(
            "recover-active-run",
            "--repo",
            str(self.repo),
            "--session-id",
            session_id,
            "--preparation-id",
            preparation_id,
            "--action",
            "resume",
        )
        self.assertNotEqual(resumed.returncode, 0)
        self.assertEqual(resumed.stdout, "")
        self.assertIn(
            "does not attest the preparation transaction",
            resumed.stderr,
        )
        record = json.loads(self._index_path().read_text(encoding="utf-8"))["sessions"][
            session_id
        ]
        self.assertEqual(record["status"], "recovery_required")
        self.assertEqual(record["preparation_id"], preparation_id)
        self.assertTrue(pathlib.Path(record["preparation_lease_path"]).is_file())

    def test_activation_commit_failures_keep_recoverable_identity_without_output(
        self,
    ) -> None:
        for failure_point in ("before-replace", "after-replace"):
            with self.subTest(failure_point=failure_point):
                session_id = f"session-activation-{failure_point}"
                run_id = f"activation-{failure_point}"
                preparation_id = (
                    "8" * 32 if failure_point == "before-replace" else "9" * 32
                )
                observed = self._run_adapter(
                    "user-prompt-submit-hook",
                    input_payload=self._session_payload(session_id=session_id),
                )
                self.assertEqual(observed.returncode, 0, observed.stderr)
                module = self._load_adapter_module()
                args = self._prepare_active_args(
                    module,
                    session_id=session_id,
                    run_id=run_id,
                )
                real_save = module._atomic_save_index_at
                save_calls = 0

                def fail_activation_commit(*save_args, **save_kwargs):
                    nonlocal save_calls
                    save_calls += 1
                    if save_calls == 2 and failure_point == "before-replace":
                        raise module.RunSafetyError(
                            "simulated activation CAS failure before replacement"
                        )
                    result = real_save(*save_args, **save_kwargs)
                    if save_calls == 2 and failure_point == "after-replace":
                        raise module.RunSafetyError(
                            "simulated activation fsync ambiguity after replacement"
                        )
                    return result

                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        module.uuid,
                        "uuid4",
                        return_value=uuid.UUID(hex=preparation_id),
                    ),
                    mock.patch.object(
                        module,
                        "_atomic_save_index_at",
                        side_effect=fail_activation_commit,
                    ),
                    mock.patch.object(module.sys, "stdout", stdout),
                    self.assertRaisesRegex(
                        module.UserError,
                        "activation could not be verified",
                    ),
                ):
                    module._prepare_active_run(args)
                self.assertEqual(stdout.getvalue(), "")
                record = json.loads(self._index_path().read_text(encoding="utf-8"))[
                    "sessions"
                ][session_id]
                expected_status = (
                    "recovery_required"
                    if failure_point == "before-replace"
                    else "active"
                )
                self.assertEqual(record["status"], expected_status)
                self.assertEqual(record["preparation_id"], preparation_id)
                self.assertTrue(
                    pathlib.Path(record["preparation_lease_path"]).is_file()
                )

                resumed = self._run_adapter(
                    "recover-active-run",
                    "--repo",
                    str(self.repo),
                    "--session-id",
                    session_id,
                    "--preparation-id",
                    preparation_id,
                    "--action",
                    "resume",
                )
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertEqual(json.loads(resumed.stdout)["status"], "active")
                recovered = json.loads(self._index_path().read_text(encoding="utf-8"))[
                    "sessions"
                ][session_id]
                self.assertEqual(recovered["status"], "active")
                self.assertFalse(
                    pathlib.Path(recovered["preparation_lease_path"]).exists()
                )

    def test_prepare_refuses_tampered_terminal_run_before_replacement(self) -> None:
        for case in ("run-dir-symlink", "state-symlink", "repo-mismatch"):
            with self.subTest(case=case):
                session_id = f"session-existing-terminal-{case}"
                run_id = f"existing-terminal-{case}"
                run_dir = self._prepare_indexed_run(session_id, run_id)
                state_path = run_dir / "state.json"
                state = json.loads(state_path.read_text(encoding="utf-8"))
                state["overall_status"] = "blocked"
                state["orchestration"]["child_status"] = "completed"
                state["orchestration"]["child_session_id"] = f"child-{case}"
                for phase in state["phases"].values():
                    phase["status"] = "blocked"
                if case == "repo-mismatch":
                    state["repo_root"] = str(self.root / "other-repo")
                state_path.write_text(
                    json.dumps(state, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

                if case == "run-dir-symlink":
                    external_run = self.root / f"external-{run_id}"
                    run_dir.rename(external_run)
                    run_dir.symlink_to(external_run, target_is_directory=True)
                elif case == "state-symlink":
                    external_state = self.root / f"external-{run_id}.json"
                    state_path.rename(external_state)
                    state_path.symlink_to(external_state)

                original_index = self._index_path().read_bytes()
                module = self._load_adapter_module()
                args = self._prepare_active_args(
                    module,
                    session_id=session_id,
                    run_id=f"replacement-{case}",
                )
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        module,
                        "_create_preparation_lease",
                    ) as lease,
                    mock.patch.object(
                        module,
                        "_run_bridge_json_with_lease",
                    ) as bridge,
                    mock.patch.object(module.sys, "stdout", stdout),
                    self.assertRaisesRegex(
                        module.UserError,
                        "cannot be retired safely",
                    ),
                ):
                    module._prepare_active_run(args)
                lease.assert_not_called()
                bridge.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(self._index_path().read_bytes(), original_index)

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

    def test_refresh_source_frame_avoids_filesystem_snapshots_under_umask(
        self,
    ) -> None:
        probe = textwrap.dedent(
            """\
            import importlib.util
            import pathlib
            import sys

            adapter_path = pathlib.Path(sys.argv[1])
            spec = importlib.util.spec_from_file_location(
                "waited_delivery_refresh_snapshot_umask_probe",
                adapter_path,
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot load hook adapter")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            with module._verified_refresh_launch_sources() as sources:
                frame = module._refresh_source_frame(sources)
                if frame[:8] != module.SOURCE_FRAME_MAGIC:
                    raise RuntimeError("source frame magic mismatch")
                if sources.bridge.content not in frame:
                    raise RuntimeError("bridge source is absent from frame")
                if sources.runner.content not in frame:
                    raise RuntimeError("runner source is absent from frame")
            """
        )
        completed = run(
            [sys.executable, "-c", probe, str(ADAPTER_PATH)],
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            umask=0o777,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")

    def test_refresh_source_input_early_rejection_cleans_process_group(self) -> None:
        module = self._load_adapter_module()
        pid_path = self.root / "early-source-reject.pid"
        script = self.root / "early-source-reject.py"
        script.write_text(
            textwrap.dedent(
                """\
                import pathlib
                import subprocess
                import sys

                pathlib.Path(sys.argv[1]).write_text(
                    str(__import__("os").getpid()),
                    encoding="utf-8",
                )
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    stdin=subprocess.DEVNULL,
                )
                """
            ),
            encoding="utf-8",
        )
        completed = module._run_bounded_refresh_process(
            [sys.executable, str(script), str(pid_path)],
            pass_fds=(),
            env=os.environ.copy(),
            input_bytes=b"x" * (2 * 1024 * 1024),
            timeout=2.0,
            cleanup_timeout=3.0,
            max_capture_bytes=64 * 1024,
        )
        self.assertEqual(completed.returncode, 126, completed.stderr)
        self.assertIn("rejected its source frame", completed.stderr)
        pgid = int(pid_path.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.killpg(pgid, 0)

    def test_refresh_source_frame_binds_lengths_digests_and_bytes(
        self,
    ) -> None:
        module = self._load_adapter_module()
        with module._verified_refresh_launch_sources() as sources:
            frame = module._refresh_source_frame(sources)
        offset = 8
        self.assertEqual(frame[:offset], module.SOURCE_FRAME_MAGIC)
        bridge_size = int.from_bytes(frame[offset : offset + 8], "big")
        offset += 8
        bridge_digest = frame[offset : offset + 32]
        offset += 32
        runner_size = int.from_bytes(frame[offset : offset + 8], "big")
        offset += 8
        runner_digest = frame[offset : offset + 32]
        offset += 32
        self.assertEqual(bridge_size, len(sources.bridge.content))
        self.assertEqual(runner_size, len(sources.runner.content))
        self.assertEqual(
            bridge_digest,
            hashlib.sha256(sources.bridge.content).digest(),
        )
        self.assertEqual(
            runner_digest,
            hashlib.sha256(sources.runner.content).digest(),
        )
        self.assertEqual(
            frame[offset : offset + bridge_size],
            sources.bridge.content,
        )
        offset += bridge_size
        self.assertEqual(frame[offset:], sources.runner.content)

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
                    real_revalidate = module._revalidate_refresh_launch_sources
                    displaced = self.root / (
                        f"displaced-launch-{artifact_name}-{mutation}.py"
                    )

                    def mutate_before_revalidation(sources) -> None:
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
                        real_revalidate(sources)

                    patches = (
                        mock.patch.object(module, "BRIDGE_PATH", bridge_path),
                        mock.patch.object(module, "RUNNER_PATH", runner_path),
                        mock.patch.object(
                            module,
                            "_revalidate_refresh_launch_sources",
                            side_effect=mutate_before_revalidation,
                        ),
                    )
                    with patches[0], patches[1], patches[2]:
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
                            with mock.patch.object(
                                module,
                                "_run_bounded_refresh_process",
                            ) as process_run:
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

    def test_refresh_launch_executes_pipe_bound_sources_across_source_aba(
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
                process_inputs: list[bytes | None] = []
                process_pass_fds: list[tuple[int, ...]] = []

                def run_during_source_aba(
                    cmd: list[str],
                    *,
                    pass_fds: tuple[int, ...],
                    env: dict[str, str],
                    input_bytes: bytes | None = None,
                    **bounds: object,
                ) -> subprocess.CompletedProcess[str]:
                    process_commands.append(cmd)
                    process_environments.append(env)
                    process_inputs.append(input_bytes)
                    process_pass_fds.append(pass_fds)
                    source_path.rename(displaced)
                    source_path.write_text(malicious, encoding="utf-8")
                    source_path.chmod(source_identity.st_mode & 0o7777)
                    try:
                        return real_run(
                            cmd,
                            pass_fds=pass_fds,
                            env=env,
                            input_bytes=input_bytes,
                            **bounds,
                        )
                    finally:
                        source_path.unlink()
                        displaced.rename(source_path)

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
                ):
                    refreshed = module._refresh_recovery_prompts(
                        run_dir,
                        self.repo.resolve(),
                        run_identity,
                    )

                self.assertEqual(len(process_commands), 1)
                self.assertEqual(
                    process_commands[0][1:5],
                    ["-I", "-B", "-S", "-c"],
                )
                self.assertEqual(
                    process_commands[0][5],
                    module.SOURCE_PIPE_BOOTSTRAP,
                )
                self.assertEqual(process_pass_fds, [()])
                self.assertIsNotNone(process_inputs[0])
                assert process_inputs[0] is not None
                self.assertIn(
                    source_path.read_bytes(),
                    process_inputs[0],
                )
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
