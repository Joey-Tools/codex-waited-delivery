from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zlib
from collections.abc import Mapping
from unittest import mock


ADAPTER_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "waited_delivery_hook_adapter.py"
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
        return run(
            [sys.executable, str(ADAPTER_PATH), *args],
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

    def _home_log_dir(self, home: pathlib.Path) -> pathlib.Path:
        return home / ".codex" / "log"

    def _load_adapter_module(self):
        spec = importlib.util.spec_from_file_location(
            "waited_delivery_hook_adapter_test_module", ADAPTER_PATH
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to load waited_delivery_hook_adapter module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

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
        self.assertEqual(entries[-1]["prompt_preview"], "Please use waited delivery")

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
                state["orchestration"]["child_session_id"] = (
                    "child-terminal-fallback"
                )
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
