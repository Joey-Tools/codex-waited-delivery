from __future__ import annotations

import ast
import json
import os
import pathlib
import shlex
import subprocess
import sys
import textwrap
import unittest
import zlib
from collections.abc import Mapping
from unittest import mock

import required_ci_candidate as candidate_support
from required_ci_candidate import (
    candidate_fixture_directory,
    candidate_script,
    run_candidate_hook_fault_probe,
    run_candidate_python,
)


ADAPTER_PATH = candidate_script("waited_delivery_hook_adapter.py")
RUNNER_PATH = candidate_script("waited_delivery_runner.py")


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
        timeout=30,
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
        self.tempdir = candidate_fixture_directory("waited-delivery-hook-")
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
        return run_candidate_python(
            ADAPTER_PATH,
            args,
            env=env,
            input_text=input_text,
            writable_roots=(self.root,),
        )

    def _run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run_candidate_python(
            RUNNER_PATH, args, writable_roots=(self.root,)
        )

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

    def _adapter_function(self, name: str) -> tuple[ast.FunctionDef, str]:
        source = ADAPTER_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(ADAPTER_PATH))
        matches = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        self.assertEqual(len(matches), 1, f"expected one candidate function {name}")
        function_source = ast.get_source_segment(source, matches[0])
        self.assertIsNotNone(function_source)
        return matches[0], function_source or ""

    def _adapter_call_names(self, name: str) -> list[str]:
        function, _ = self._adapter_function(name)
        calls: list[str] = []
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                calls.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.append(node.func.attr)
        return calls

    def _run_fail_open_fault_probe(self) -> subprocess.CompletedProcess[str]:
        probe_path = self.root / "fail_open_fault_probe.py"
        probe_path.write_text(
            textwrap.dedent(
                """\
                import importlib.util
                import json
                import pathlib
                import sys

                adapter_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
                spec = importlib.util.spec_from_file_location(
                    "_waited_delivery_fail_open_probe", adapter_path
                )
                if spec is None or spec.loader is None:
                    raise AssertionError("candidate adapter cannot be loaded")
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)

                log_attempts = []
                stderr_attempts = []
                stdout_messages = []

                def fail_log_write(entry):
                    log_attempts.append(entry)
                    raise RuntimeError("injected hook log failure")

                def fail_debug_stderr(message="", *args, file=None, **kwargs):
                    if file is module.sys.stderr:
                        stderr_attempts.append(str(message))
                        raise RuntimeError("injected debug stderr failure")
                    stdout_messages.append(str(message))

                module._append_hook_log = fail_log_write
                module.print = fail_debug_stderr
                error = RuntimeError("injected hook failure")
                error.hook_command = "stop-hook"
                error.hook_payload = {"session_id": "session-fail-open-probe"}
                result = module._fail_open_hook_response(error)
                receipt = {
                    "log_attempt_count": len(log_attempts),
                    "result": result,
                    "stderr_attempts": stderr_attempts,
                    "stdout_messages": stdout_messages,
                }
                sys.stdout.write(json.dumps(receipt, sort_keys=True) + "\\n")
                """
            ),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.pop("CODEX_THREAD_ID", None)
        environment["HOME"] = str(self.root)
        environment["WAITED_DELIVERY_HOOK_DEBUG"] = "1"
        return candidate_support._run_candidate_process(
            ADAPTER_PATH,
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(probe_path),
                str(ADAPTER_PATH),
            ],
            env=environment,
            writable_roots=(self.root,),
        )

    def _run_stop_fault_probe(
        self,
        *faults: str,
        label: str = "prompt-fault",
        attach_child: bool = True,
        child_status: str | None = None,
        env_overrides: Mapping[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
        session_id = f"session-{label}"
        child_session_id = f"child-{label}"
        home = self.root / f"{label}-home"
        home.mkdir()
        environment = os.environ.copy()
        environment.pop("CODEX_THREAD_ID", None)
        environment["HOME"] = str(home)
        if env_overrides:
            environment.update(env_overrides)
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
            env_overrides={"HOME": str(home)},
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        prepared = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Exercise stop-hook fault fallback",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            "--session-id",
            session_id,
            env_overrides={"HOME": str(home)},
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        run_dir = json.loads(prepared.stdout)["run_dir"]
        if attach_child:
            attached = self._run_adapter(
                "attach-child-active-run",
                "--repo",
                str(self.repo),
                "--run-dir",
                run_dir,
                "--child-session-id",
                child_session_id,
                "--session-id",
                session_id,
                env_overrides={"HOME": str(home)},
            )
            self.assertEqual(attached.returncode, 0, attached.stderr)
        if child_status is not None:
            state_path = pathlib.Path(run_dir) / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            orchestration = state["orchestration"]
            self.assertIsInstance(orchestration, dict)
            orchestration["child_status"] = child_status
            state_path.write_text(
                json.dumps(state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        stop_payload = {
            "session_id": session_id,
            "transcript_path": "/tmp/prompt-fault-transcript.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "I am about to stop",
        }
        completed = run_candidate_hook_fault_probe(
            ADAPTER_PATH,
            faults,
            env=environment,
            input_text=json.dumps(stop_payload),
            writable_roots=(self.root,),
        )
        trusted_probe = pathlib.Path(
            run_candidate_hook_fault_probe.__code__.co_filename
        ).resolve(strict=True)
        isolated_probe = pathlib.Path(completed.args[3])
        isolated_adapter = pathlib.Path(completed.args[5])
        expected_interpreter = (
            str(pathlib.Path(sys.executable).resolve(strict=True))
            if os.environ.get("REQUIRED_CI_ISOLATION_MODE")
            == "sudo-setpriv-v1"
            else sys.executable
        )
        self.assertEqual(
            completed.args[:3], [expected_interpreter, "-I", "-B"]
        )
        self.assertEqual(completed.args[4], "--hook-fault-probe")
        self.assertEqual(completed.args[6], ",".join(faults))
        self.assertTrue(isolated_probe.is_absolute())
        self.assertEqual(isolated_probe.name, trusted_probe.name)
        self.assertNotEqual(isolated_probe, trusted_probe)
        self.assertTrue(isolated_adapter.is_absolute())
        self.assertEqual(isolated_adapter.name, ADAPTER_PATH.name)
        self.assertNotEqual(isolated_adapter, ADAPTER_PATH)
        log_path = self._home_log_dir(home) / "waited-delivery-hooks.jsonl"
        events = []
        if log_path.is_file():
            events = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
            ]
        return completed, events

    def _run_terminal_stop_prompt_probe(
        self,
        *,
        label: str,
        child_session_id: str | None,
        faults: tuple[str, ...],
    ) -> tuple[
        subprocess.CompletedProcess[str],
        list[dict[str, object]],
        str,
        str,
    ]:
        session_id = f"session-{label}"
        attached_child_session_id = f"child-{label}"
        home = self.root / f"{label}-home"
        home.mkdir()
        environment = os.environ.copy()
        environment.pop("CODEX_THREAD_ID", None)
        environment["HOME"] = str(home)
        observed = self._run_adapter(
            "user-prompt-submit-hook",
            input_payload=self._session_payload(session_id=session_id),
            env_overrides={"HOME": str(home)},
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        prepared = self._run_adapter(
            "prepare-active-run",
            "--repo",
            str(self.repo),
            "--goal",
            "Exercise terminal child prompt identity guard",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            "--session-id",
            session_id,
            env_overrides={"HOME": str(home)},
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        run_dir = json.loads(prepared.stdout)["run_dir"]
        attached = self._run_adapter(
            "attach-child-active-run",
            "--repo",
            str(self.repo),
            "--run-dir",
            run_dir,
            "--child-session-id",
            attached_child_session_id,
            "--session-id",
            session_id,
            env_overrides={"HOME": str(home)},
        )
        self.assertEqual(attached.returncode, 0, attached.stderr)

        state_path = pathlib.Path(run_dir) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["overall_status"] = "passed"
        orchestration = state["orchestration"]
        self.assertIsInstance(orchestration, dict)
        orchestration["child_status"] = "completed"
        if child_session_id is None:
            orchestration.pop("child_session_id", None)
        else:
            orchestration["child_session_id"] = child_session_id
        phases = state["phases"]
        self.assertIsInstance(phases, dict)
        for phase in phases.values():
            self.assertIsInstance(phase, dict)
            phase["status"] = "passed"
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        stop_payload = {
            "session_id": session_id,
            "transcript_path": f"/tmp/{label}-transcript.jsonl",
            "cwd": str(self.repo),
            "hook_event_name": "Stop",
            "model": "gpt-5.5",
            "permission_mode": "acceptEdits",
            "stop_hook_active": False,
            "last_assistant_message": "I am about to stop",
        }
        if faults:
            completed = run_candidate_hook_fault_probe(
                ADAPTER_PATH,
                faults,
                env=environment,
                input_text=json.dumps(stop_payload),
                writable_roots=(self.root,),
            )
        else:
            completed = self._run_adapter(
                "stop-hook",
                input_payload=stop_payload,
                env_overrides={"HOME": str(home)},
            )
        log_path = self._home_log_dir(home) / "waited-delivery-hooks.jsonl"
        events = []
        if log_path.is_file():
            events = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
            ]
        return completed, events, run_dir, session_id

    def test_terminal_stop_prompts_refuse_missing_child_identity(self) -> None:
        builders = (
            ("continuation", (), "without a nonblank child_session_id"),
            (
                "fallback",
                ("continuation",),
                "could not render the full continuation prompt",
            ),
            (
                "last-resort",
                ("continuation", "fallback"),
                "State is inconsistent",
            ),
            (
                "emergency",
                ("continuation", "fallback", "last-resort"),
                "State is inconsistent",
            ),
        )
        identities = (("missing", None), ("blank", " \t "))
        for identity_label, child_session_id in identities:
            for builder_label, faults, prompt_marker in builders:
                label = f"{identity_label}-{builder_label}"
                with self.subTest(identity=identity_label, builder=builder_label):
                    completed, events, run_dir, session_id = (
                        self._run_terminal_stop_prompt_probe(
                            label=label,
                            child_session_id=child_session_id,
                            faults=faults,
                        )
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(prompt_marker, completed.stderr)
                    self.assertIn("child_session_id", completed.stderr)
                    self.assertNotIn("reconcile-active-run", completed.stderr)
                    self.assertEqual(
                        [event["error_message"] for event in events],
                        [
                            f"required-ci injected {fault} failure"
                            for fault in faults
                        ],
                    )
                    index = json.loads(
                        self._index_path().read_text(encoding="utf-8")
                    )
                    record = index["sessions"][session_id]
                    self.assertEqual(record["status"], "active")
                    self.assertEqual(record["run_dir"], run_dir)

    def test_run_is_terminal_accepts_complete_state_with_attached_child(self) -> None:
        completed, events, run_dir, session_id = (
            self._run_terminal_stop_prompt_probe(
                label="terminal-positive-control",
                child_session_id="child-terminal-positive-control",
                faults=(),
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "{}\n")
        self.assertEqual(completed.stderr, "")
        self.assertEqual(events, [])
        index = json.loads(self._index_path().read_text(encoding="utf-8"))
        record = index["sessions"][session_id]
        self.assertEqual(record["status"], "completed")
        self.assertIsNone(record["run_dir"])
        self.assertTrue(pathlib.Path(run_dir, "state.json").is_file())

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
        completed = self._run_fail_open_fault_probe()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        receipt = json.loads(completed.stdout)
        self.assertEqual(
            receipt,
            {
                "log_attempt_count": 1,
                "result": 0,
                "stderr_attempts": [
                    "waited-delivery hook diagnostics write failed: "
                    "injected hook log failure",
                    "waited-delivery hook fail-open (stop-hook): "
                    "injected hook failure",
                ],
                "stdout_messages": ["{}"],
            },
        )

    def test_hook_archive_label_is_unique(self) -> None:
        no_zstd_path = self.root / "archive-label-no-zstd"
        no_zstd_path.mkdir()
        git_wrapper = no_zstd_path / "git"
        git_wrapper.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(candidate_support.TRUSTED_GIT_EXECUTABLE)
            + ' "$@"\n',
            encoding="utf-8",
        )
        git_wrapper.chmod(0o755)
        candidate_environment_keys = candidate_support._CANDIDATE_ENV_KEYS | {"PATH"}
        same_second_entries: list[dict[str, object]] | None = None
        same_second_archives: list[pathlib.Path] | None = None
        with mock.patch.object(
            candidate_support,
            "_CANDIDATE_ENV_KEYS",
            candidate_environment_keys,
        ):
            for attempt in range(3):
                label = f"archive-label-{attempt}"
                completed, _ = self._run_stop_fault_probe(
                    "continuation",
                    "fallback",
                    "last-resort",
                    label=label,
                    env_overrides={
                        "PATH": str(no_zstd_path),
                        "WAITED_DELIVERY_HOOK_LOG_MAX_BYTES": "1",
                        "WAITED_DELIVERY_HOOK_LOG_UNCOMPRESSED_SLOTS": "1",
                    },
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                log_dir = self._home_log_dir(self.root / f"{label}-home")
                archives = sorted(
                    log_dir.glob("waited-delivery-hooks-*.jsonl")
                )
                log_paths = [*archives, log_dir / "waited-delivery-hooks.jsonl"]
                entries = [
                    json.loads(line)
                    for path in log_paths
                    if path.is_file()
                    for line in path.read_text(encoding="utf-8").splitlines()
                ]
                archive_prefix = "waited-delivery-hooks-"
                archive_timestamps = {
                    path.name[len(archive_prefix) : len(archive_prefix) + 16]
                    for path in archives
                }
                if (
                    len(entries) == 3
                    and len({entry["ts"] for entry in entries}) == 1
                    and len(archives) == 2
                    and len(archive_timestamps) == 1
                ):
                    same_second_entries = entries
                    same_second_archives = archives
                    break
        self.assertIsNotNone(
            same_second_entries,
            "could not observe all three diagnostic events in one second",
        )
        self.assertIsNotNone(same_second_archives)
        self.assertEqual(len(same_second_archives or []), 2)
        self.assertEqual(
            sorted(
                str(entry["error_message"])
                for entry in (same_second_entries or [])
            ),
            sorted(
                [
                    "required-ci injected continuation failure",
                    "required-ci injected fallback failure",
                    "required-ci injected last-resort failure",
                ]
            ),
        )

    def test_hook_diagnostics_rotate_to_jsonl_when_zstd_missing(self) -> None:
        fake_home = self.root / "home-rotation-no-zstd"
        no_zstd_path = self.root / "no-zstd-bin"
        no_zstd_path.mkdir()
        adapter_dir = self.repo / ".codex-tmp" / "waited-delivery-hook-adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        env: Mapping[str, str | None] = {
            "HOME": str(fake_home),
            "PATH": str(no_zstd_path),
            "WAITED_DELIVERY_HOOK_LOG_MAX_BYTES": "256",
            "WAITED_DELIVERY_HOOK_LOG_UNCOMPRESSED_SLOTS": "3",
        }
        candidate_environment_keys = candidate_support._CANDIDATE_ENV_KEYS | {"PATH"}
        with mock.patch.object(
            candidate_support,
            "_CANDIDATE_ENV_KEYS",
            candidate_environment_keys,
        ):
            for _ in range(4):
                (adapter_dir / "index.json").write_text(
                    "{invalid json\n", encoding="utf-8"
                )
                completed = self._run_adapter(
                    "stop-hook",
                    input_payload={
                        "session_id": "session-rotation-no-zstd",
                        "transcript_path": "/tmp/transcript-rotation-no-zstd.jsonl",
                        "cwd": str(self.repo),
                        "hook_event_name": "Stop",
                        "model": "gpt-5.5",
                        "permission_mode": "acceptEdits",
                        "stop_hook_active": False,
                        "last_assistant_message": "rotate without zstd",
                    },
                    env_overrides=env,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

        log_dir = self._home_log_dir(fake_home)
        for name in (
            "waited-delivery-hooks.jsonl",
            "waited-delivery-hooks.1.jsonl",
            "waited-delivery-hooks.2.jsonl",
        ):
            path = log_dir / name
            self.assertTrue(path.is_file(), name)
            self.assertTrue(path.read_text(encoding="utf-8").strip(), name)
        archives = list(log_dir.glob("waited-delivery-hooks-*.jsonl"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(list(log_dir.glob("waited-delivery-hooks-*.jsonl.zst")), [])
        entries = [
            json.loads(line)
            for line in archives[0].read_text(encoding="utf-8").splitlines()
        ]
        self.assertTrue(entries)
        self.assertEqual(entries[-1]["hook_command"], "stop-hook")

    def test_hook_diagnostics_rotate_and_compress_with_zstd(self) -> None:
        zstd = next(
            (
                str(path)
                for path in (pathlib.Path("/usr/bin/zstd"), pathlib.Path("/bin/zstd"))
                if path.is_file() and os.access(path, os.X_OK)
            ),
            None,
        )
        if zstd is None:
            self.skipTest("zstd not available in the closed candidate PATH")
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
        completed, events = self._run_stop_fault_probe("continuation")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Do not finish yet", completed.stderr)
        self.assertIn("child-prompt-fault", completed.stderr)
        self.assertEqual(
            [event["error_message"] for event in events],
            ["required-ci injected continuation failure"],
        )
        self.assertEqual(events[0]["hook_command"], "stop-hook")
        self.assertEqual(events[0]["session_id"], "session-prompt-fault")

    def test_stop_hook_fallback_prompt_preserves_terminal_child_status(self) -> None:
        for child_status in ("completed", "failed", "interrupted"):
            label = f"terminal-fallback-{child_status}"
            with self.subTest(child_status=child_status):
                completed, events = self._run_stop_fault_probe(
                    "continuation",
                    label=label,
                    child_status=child_status,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertIn(
                    "could not render the full continuation prompt",
                    completed.stderr,
                )
                self.assertIn(
                    f"--child-status {child_status}", completed.stderr
                )
                self.assertIn(
                    f"--child-session-id child-{label}", completed.stderr
                )
                self.assertIn("reconcile-active-run", completed.stderr)
                self.assertEqual(
                    [event["error_message"] for event in events],
                    ["required-ci injected continuation failure"],
                )

    def test_stop_hook_last_resort_prompt_preserves_terminal_child_status(
        self,
    ) -> None:
        for child_status in ("completed", "failed", "interrupted"):
            label = f"terminal-last-resort-{child_status}"
            with self.subTest(child_status=child_status):
                completed, events = self._run_stop_fault_probe(
                    "continuation",
                    "fallback",
                    label=label,
                    child_status=child_status,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertIn(
                    "Then reconcile the active run before replying.",
                    completed.stderr,
                )
                expected_command_prefix = shlex.join(
                    [
                        completed.args[0],
                        completed.args[5],
                        "reconcile-active-run",
                    ]
                )
                self.assertIn(
                    f"Run:\n{expected_command_prefix} ", completed.stderr
                )
                self.assertNotIn(
                    "Run this from the repo root:", completed.stderr
                )
                self.assertIn(
                    f"--child-status {child_status}", completed.stderr
                )
                self.assertIn(
                    f"--child-session-id child-{label}", completed.stderr
                )
                self.assertIn("reconcile-active-run", completed.stderr)
                self.assertEqual(
                    [event["error_message"] for event in events],
                    [
                        "required-ci injected continuation failure",
                        "required-ci injected fallback failure",
                    ],
                )

    def test_stop_hook_fallback_prompt_waits_for_active_child(self) -> None:
        completed, events = self._run_stop_fault_probe(
            "continuation", label="active-child-fallback"
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "Keep waiting for delivery child `child-active-child-fallback`",
            completed.stderr,
        )
        self.assertIn(
            "unless the user explicitly interrupts the run.", completed.stderr
        )
        self.assertEqual(
            [event["error_message"] for event in events],
            ["required-ci injected continuation failure"],
        )

    def test_stop_hook_fallback_prompt_requires_spawn_when_child_missing(self) -> None:
        completed, events = self._run_stop_fault_probe(
            "continuation",
            label="missing-child-fallback",
            attach_child=False,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "Continue the required spawn -> attach-child -> wait sequence.",
            completed.stderr,
        )
        self.assertNotIn("Keep waiting for delivery child", completed.stderr)
        self.assertEqual(
            [event["error_message"] for event in events],
            ["required-ci injected continuation failure"],
        )

    def test_stop_hook_keeps_blocking_when_fallback_builder_fails(self) -> None:
        completed, events = self._run_stop_fault_probe(
            "continuation", "fallback"
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Do not finish yet", completed.stderr)
        self.assertIn("child-prompt-fault", completed.stderr)
        self.assertEqual(
            [event["error_message"] for event in events],
            [
                "required-ci injected continuation failure",
                "required-ci injected fallback failure",
            ],
        )
        self.assertEqual(
            [event["hook_command"] for event in events],
            ["stop-hook", "stop-hook"],
        )
        self.assertEqual(
            [event["session_id"] for event in events],
            ["session-prompt-fault", "session-prompt-fault"],
        )

    def test_stop_hook_keeps_blocking_when_last_resort_builder_fails(self) -> None:
        completed, events = self._run_stop_fault_probe(
            "continuation", "fallback", "last-resort"
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Do not finish yet", completed.stderr)
        self.assertIn("child-prompt-fault", completed.stderr)
        self.assertEqual(
            [event["error_message"] for event in events],
            [
                "required-ci injected continuation failure",
                "required-ci injected fallback failure",
                "required-ci injected last-resort failure",
            ],
        )

    def test_stop_hook_keeps_blocking_when_diagnostic_stderr_fails(self) -> None:
        completed, events = self._run_stop_fault_probe(
            "continuation", "diagnostic-log", "diagnostic-stderr"
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Do not finish yet", completed.stderr)
        self.assertIn("child-prompt-fault", completed.stderr)
        self.assertNotIn("diagnostics write failed", completed.stderr)
        self.assertEqual(events, [])

    def test_stop_hook_fails_open_when_prompt_write_fails(self) -> None:
        completed, events = self._run_stop_fault_probe("prompt-stderr")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "{}\n")
        self.assertEqual(completed.stderr, "")
        self.assertEqual(
            [event["error_message"] for event in events],
            ["required-ci injected prompt stderr failure"],
        )
        self.assertEqual(events[0]["hook_command"], "stop-hook")
        self.assertEqual(events[0]["session_id"], "session-prompt-fault")


if __name__ == "__main__":
    unittest.main()
