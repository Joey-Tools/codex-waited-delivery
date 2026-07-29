"""Compatibility tests for the historical waited-delivery runner."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest import mock


SCRIPT_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "waited_delivery_runner.py"
)


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
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


class WaitedDeliveryRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="waited-delivery-test-")
        self.root = pathlib.Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.assertEqual(git(self.repo, "init").returncode, 0)
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        self.assertEqual(git(self.repo, "add", "tracked.txt").returncode, 0)
        git_commit(self.repo, "init")
        (self.repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        (self.repo / "notes.md").write_text("untracked\n", encoding="utf-8")
        (self.repo / ".codex-tmp").mkdir()
        (self.repo / ".codex-tmp" / "artifact.log").write_text(
            "ignore me\n", encoding="utf-8"
        )
        self.fake_helper = self.root / "fake_external_helper.py"
        self.fake_helper.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import pathlib
                import sys

                args = sys.argv[1:]
                prompt_path = pathlib.Path(args[args.index("--prompt-file") + 1])
                prompt = prompt_path.read_text(encoding="utf-8")
                if "__FORCE_BLOCK__" in prompt:
                    print("BLOCKED: helper refused")
                    raise SystemExit(1)
                print("READY")
                raise SystemExit(0)
                """
            ),
            encoding="utf-8",
        )
        self.fake_helper.chmod(0o755)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _prepare(self, *extra_args: str) -> pathlib.Path:
        completed = self._run_runner(
            "prepare",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            *extra_args,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return pathlib.Path(completed.stdout.strip())

    def _run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                *args,
            ]
        )
        return completed

    def _load_runner_module(self):
        spec = importlib.util.spec_from_file_location(
            "waited_delivery_runner_test_module",
            SCRIPT_PATH,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to load waited_delivery_runner module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _commit_implementation(self) -> None:
        self.assertEqual(git(self.repo, "add", "tracked.txt", "notes.md").returncode, 0)
        git_commit(self.repo, "freeze implementation")

    def _attach_child(self, run_dir: pathlib.Path, child_session_id: str) -> None:
        completed = self._run_runner(
            "attach-child",
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            child_session_id,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def _finish_child(self, run_dir: pathlib.Path, child_session_id: str) -> None:
        completed = self._run_runner(
            "finish-child",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            child_session_id,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_prepare_writes_state_contract_prompt_and_smoke_command(self) -> None:
        run_dir = self._prepare(
            "--parent-session-id",
            "parent-1",
            "--parent-turn-id",
            "turn-1",
            "--parent-transcript-path",
            "/tmp/transcript.jsonl",
            "--permission-mode",
            "plan",
        )
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))

        self.assertEqual(state["schema_version"], 3)
        self.assertEqual(state["goal"], "Wrap current repo changes")
        self.assertEqual(state["overall_status"], "pending")
        self.assertEqual(state["changed_files"], ["tracked.txt", "notes.md"])
        self.assertEqual(state["orchestration"]["parent_session_id"], "parent-1")
        self.assertEqual(state["orchestration"]["parent_turn_id"], "turn-1")
        self.assertEqual(
            state["orchestration"]["parent_transcript_path"], "/tmp/transcript.jsonl"
        )
        self.assertEqual(state["orchestration"]["permission_mode"], "plan")
        self.assertEqual(state["orchestration"]["child_status"], "pending")
        self.assertTrue(
            all(not path.startswith(".codex-tmp/") for path in state["changed_files"])
        )
        self.assertEqual(
            state["fallback_readiness_smoke"]["command"][-1],
            "{prompt_text}",
        )
        contract = (run_dir / "child-contract.md").read_text(encoding="utf-8")
        self.assertIn("Waited Delivery Child Contract", contract)
        self.assertIn("tracked.txt", contract)
        self.assertIn("the main session completes implementation", contract)
        self.assertIn("the child owns tests, docs sync, and verification", contract)
        self.assertIn(
            "must not mark `internal_review` or `external_review` as passed", contract
        )
        self.assertIn("the parent must form an authorized, committed", contract)
        self.assertIn("Dirty or untracked implementation state cannot count", contract)
        self.assertIn("rejects a review `passed` result", contract)
        self.assertIn("before the child is terminal", contract)
        self.assertIn("terminal review evidence is missing", contract)
        self.assertIn(
            "the parent directly launches exactly one fresh/clear-context Codex "
            "`reviewer` agent",
            contract,
        )
        self.assertIn("load `$review-orchestration-playbook`", contract)
        self.assertIn(
            "discover the fixed diff and necessary nearby context with tools", contract
        )
        self.assertIn("do not precompute or paste the full diff", contract)
        self.assertIn("low-level compatibility/diagnostic tooling only", contract)
        self.assertIn(
            "cannot start, satisfy, substitute for, or count as the named internal "
            "single review",
            contract,
        )
        self.assertIn("never adds or replaces an internal reviewer", contract)
        child_prompt = (run_dir / "child-prompt.md").read_text(encoding="utf-8")
        self.assertIn("Waited Delivery Child Prompt", child_prompt)
        self.assertIn("begin-phase", child_prompt)
        self.assertIn("record-phase", child_prompt)
        parent_prompt = (run_dir / "parent-prompt.md").read_text(encoding="utf-8")
        self.assertIn("Waited Delivery Parent Prompt", parent_prompt)
        self.assertIn("attach-child", parent_prompt)
        self.assertIn("finish-child", parent_prompt)
        self.assertIn("Do not claim review coverage", parent_prompt)
        self.assertIn("committed clean/frozen", parent_prompt)
        self.assertIn(
            "exactly one fresh/clear-context Codex `reviewer` agent", parent_prompt
        )
        self.assertIn("load `$review-orchestration-playbook`", parent_prompt)
        self.assertIn("Do not precompute or paste a full diff", parent_prompt)
        self.assertIn("discovers the fixed diff", parent_prompt)
        self.assertIn("low-level compatibility/diagnostic tooling", parent_prompt)
        self.assertIn(
            "cannot start, satisfy, substitute for, or count as the named internal "
            "single review",
            parent_prompt,
        )
        self.assertIn("lifecycle does not add a reviewer", parent_prompt)
        self.assertIn("only as `internal_review`", parent_prompt)
        self.assertIn("Run `external_review` separately", parent_prompt)
        self.assertIn("never review coverage", parent_prompt)
        self.assertIn("reconcile-parent", parent_prompt)
        self.assertTrue((run_dir / "fallback-smoke.command.txt").is_file())

    def test_prepare_requires_internal_review_phase(self) -> None:
        run_id = "missing-internal-review"
        completed = self._run_runner(
            "prepare",
            "--repo",
            str(self.repo),
            "--goal",
            "Reject a review-free phase override",
            "--run-id",
            run_id,
            "--phase",
            "tests",
            "--external-helper",
            str(self.fake_helper),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("required internal_review phase", completed.stderr)
        run_dir = self.repo / ".codex-tmp" / "waited-delivery" / run_id
        self.assertFalse(run_dir.exists())

    def test_prepare_json_emits_artifact_paths(self) -> None:
        completed = self._run_runner(
            "prepare",
            "--repo",
            str(self.repo),
            "--goal",
            "Wrap current repo changes",
            "--external-helper",
            str(self.fake_helper),
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        run_dir = pathlib.Path(payload["run_dir"])
        self.assertTrue(run_dir.is_dir())
        self.assertEqual(payload["parent_prompt"], str(run_dir / "parent-prompt.md"))
        self.assertEqual(payload["child_prompt"], str(run_dir / "child-prompt.md"))

    def test_refresh_prompts_replaces_legacy_runner_commands(self) -> None:
        run_dir = self._prepare("--no-fallback-smoke")
        legacy_runner = (
            self.root
            / "skills"
            / "waited-delivery"
            / "scripts"
            / "waited_delivery_runner.py"
        )
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (run_dir / prompt_name).write_text(
                f"legacy sentinel\n`{sys.executable} {legacy_runner}`\n",
                encoding="utf-8",
            )
        before_inodes = {
            name: (run_dir / name).stat().st_ino
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        }

        completed = self._run_runner(
            "refresh-prompts",
            "--run-dir",
            str(run_dir),
            "--json",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["runner_path"], str(SCRIPT_PATH))
        self.assertEqual(payload["child_prompt"], str(run_dir / "child-prompt.md"))
        self.assertEqual(payload["parent_prompt"], str(run_dir / "parent-prompt.md"))
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(
            state["artifacts"]["child_prompt"],
            str(run_dir / "child-prompt.md"),
        )
        self.assertEqual(
            state["artifacts"]["parent_prompt"],
            str(run_dir / "parent-prompt.md"),
        )
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            prompt = (run_dir / prompt_name).read_text(encoding="utf-8")
            self.assertIn(str(SCRIPT_PATH), prompt)
            self.assertNotIn(str(legacy_runner), prompt)
            self.assertNotIn("legacy sentinel", prompt)
        for name, old_inode in before_inodes.items():
            self.assertNotEqual((run_dir / name).stat().st_ino, old_inode)

    def test_refresh_prompts_rejects_symlinked_state_or_prompt_artifacts(self) -> None:
        for target_name in ("state.json", "child-prompt.md", "parent-prompt.md"):
            with self.subTest(target=target_name):
                run_dir = self._prepare("--no-fallback-smoke")
                artifact = run_dir / target_name
                external_target = self.root / (
                    f"external-{run_dir.name}-{target_name.replace('.', '-')}"
                )
                artifact.rename(external_target)
                artifact.symlink_to(external_target)
                sentinel = external_target.read_bytes()

                completed = self._run_runner(
                    "refresh-prompts",
                    "--run-dir",
                    str(run_dir),
                    "--expected-repo-root",
                    str(self.repo),
                    "--json",
                )

                self.assertEqual(completed.returncode, 1)
                self.assertEqual(external_target.read_bytes(), sentinel)

    def test_refresh_prompts_rejects_replaced_run_directory_identity(self) -> None:
        run_dir = self._prepare("--no-fallback-smoke")
        original = run_dir.stat()
        original_dir = self.root / "original-run-directory"
        run_dir.rename(original_dir)
        shutil.copytree(original_dir, run_dir)
        sentinel = "replacement prompt must remain unchanged\n"
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (run_dir / prompt_name).write_text(sentinel, encoding="utf-8")

        completed = self._run_runner(
            "refresh-prompts",
            "--run-dir",
            str(run_dir),
            "--expected-repo-root",
            str(self.repo.resolve()),
            "--expected-run-dev",
            str(original.st_dev),
            "--expected-run-ino",
            str(original.st_ino),
            "--expected-run-uid",
            str(original.st_uid),
            "--expected-run-gid",
            str(original.st_gid),
            "--expected-run-mode",
            str(original.st_mode & 0o7777),
            "--json",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("expected bridge identity", completed.stderr)
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            self.assertEqual(
                (run_dir / prompt_name).read_text(encoding="utf-8"),
                sentinel,
            )

    def test_state_save_uses_loaded_identity_and_digest_version(self) -> None:
        mutations = {
            "missing": "is missing before update",
            "replaced": "was replaced before update",
            "content-changed": "content changed before update",
            "unreadable": "is unreadable before update",
        }
        for mutation, expected_error in mutations.items():
            with self.subTest(mutation=mutation):
                module = self._load_runner_module()
                run_dir = self._prepare("--no-fallback-smoke")
                opened_run_dir, repo_root, run_fd = module._open_run_directory(run_dir)
                try:
                    state, state_version = module._load_state_from_fd(
                        opened_run_dir,
                        repo_root,
                        run_fd,
                    )
                    state_path = run_dir / "state.json"
                    original_content = state_path.read_bytes()
                    original_stat = state_path.stat()
                    self.assertEqual(state_version.device, original_stat.st_dev)
                    self.assertEqual(state_version.inode, original_stat.st_ino)
                    self.assertEqual(state_version.size, len(original_content))
                    self.assertEqual(
                        state_version.sha256,
                        hashlib.sha256(original_content).hexdigest(),
                    )

                    if mutation == "missing":
                        state_path.unlink()
                    elif mutation == "replaced":
                        replacement = run_dir / "replacement-state.json"
                        replacement.write_bytes(original_content)
                        replacement.replace(state_path)
                    elif mutation == "content-changed":
                        with state_path.open("r+b") as state_file:
                            state_file.write(
                                b"[" if original_content[:1] != b"[" else b"{"
                            )
                            state_file.flush()
                    else:
                        state_path.unlink()
                        state_path.mkdir()

                    with self.assertRaisesRegex(
                        module.UserError,
                        expected_error,
                    ):
                        module._save_state(
                            opened_run_dir,
                            repo_root,
                            run_fd,
                            state,
                            state_version,
                        )
                finally:
                    module.os.close(run_fd)

    def test_atomic_write_binds_published_temp_file_identity(self) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        opened_run_dir, _repo_root, run_fd = module._open_run_directory(run_dir)
        artifact_name = "child-prompt.md"
        attacker_name = "attacker-prompt.md"
        (opened_run_dir / attacker_name).write_text(
            "attacker replacement\n",
            encoding="utf-8",
        )
        expected_version = module._expected_artifact_version(
            run_fd,
            artifact_name,
            required=True,
        )
        self.assertIsNotNone(expected_version)
        real_replace = module.os.replace

        def replace_then_substitute(
            source: str,
            destination: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
        ) -> None:
            real_replace(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )
            real_replace(
                attacker_name,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        try:
            with mock.patch.object(
                module.os,
                "replace",
                side_effect=replace_then_substitute,
            ):
                with self.assertRaisesRegex(
                    module.UserError,
                    "publication identity mismatch",
                ):
                    module._atomic_write_regular(
                        run_fd,
                        artifact_name,
                        "intended publication\n",
                        expected_version=expected_version,
                    )
        finally:
            module.os.close(run_fd)

    def test_refresh_prompts_serializes_state_rmw_with_phase_and_child_updates(
        self,
    ) -> None:
        for mutation in ("record-phase", "finish-child"):
            with self.subTest(mutation=mutation):
                module = self._load_runner_module()
                run_dir = self._prepare("--no-fallback-smoke")
                if mutation == "finish-child":
                    self._attach_child(run_dir, "child-race")
                for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                    (run_dir / prompt_name).write_text(
                        "legacy prompt\n",
                        encoding="utf-8",
                    )

                refresh_holds_lock = threading.Event()
                release_refresh = threading.Event()
                mutation_attempted_lock = threading.Event()
                failures: list[BaseException] = []
                real_write_prompts = module._write_current_prompts
                real_flock = fcntl.flock

                def instrumented_flock(fd: int, operation: int) -> None:
                    if (
                        threading.current_thread().name == mutation
                        and operation == fcntl.LOCK_EX
                    ):
                        mutation_attempted_lock.set()
                    real_flock(fd, operation)

                def blocking_write_prompts(*args, **kwargs):
                    if threading.current_thread().name == "refresh-prompts":
                        refresh_holds_lock.set()
                        if not release_refresh.wait(5):
                            raise RuntimeError("timed out waiting to release refresh")
                    return real_write_prompts(*args, **kwargs)

                def run_refresh() -> None:
                    try:
                        module._refresh_prompts(
                            argparse.Namespace(
                                run_dir=str(run_dir),
                                expected_repo_root=None,
                                json=False,
                            )
                        )
                    except BaseException as error:
                        failures.append(error)

                def run_mutation() -> None:
                    try:
                        if mutation == "record-phase":
                            module._record_phase(
                                argparse.Namespace(
                                    run_dir=str(run_dir),
                                    phase="tests",
                                    status="passed",
                                    summary="race preserved",
                                    finding=[],
                                    evidence=["deterministic interleaving"],
                                )
                            )
                        else:
                            module._finish_child(
                                argparse.Namespace(
                                    run_dir=str(run_dir),
                                    child_status="completed",
                                    child_session_id="child-race",
                                )
                            )
                    except BaseException as error:
                        failures.append(error)

                with mock.patch.object(
                    module.fcntl,
                    "flock",
                    side_effect=instrumented_flock,
                ):
                    with mock.patch.object(
                        module,
                        "_write_current_prompts",
                        side_effect=blocking_write_prompts,
                    ):
                        refresh_thread = threading.Thread(
                            target=run_refresh,
                            name="refresh-prompts",
                        )
                        mutation_thread = threading.Thread(
                            target=run_mutation,
                            name=mutation,
                        )
                        refresh_thread.start()
                        self.assertTrue(refresh_holds_lock.wait(5))
                        mutation_thread.start()
                        try:
                            self.assertTrue(mutation_attempted_lock.wait(5))
                        finally:
                            release_refresh.set()
                        refresh_thread.join(5)
                        mutation_thread.join(5)

                self.assertFalse(refresh_thread.is_alive())
                self.assertFalse(mutation_thread.is_alive())
                self.assertEqual(failures, [])
                state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
                if mutation == "record-phase":
                    self.assertEqual(state["phases"]["tests"]["status"], "passed")
                    self.assertEqual(
                        state["phases"]["tests"]["summary"],
                        "race preserved",
                    )
                else:
                    self.assertEqual(
                        state["orchestration"]["child_status"],
                        "completed",
                    )
                    self.assertIsNotNone(state["orchestration"]["child_finished_at"])
                for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                    self.assertIn(
                        str(SCRIPT_PATH),
                        (run_dir / prompt_name).read_text(encoding="utf-8"),
                    )

    def test_run_fallback_smoke_records_ready_sample(self) -> None:
        run_dir = self._prepare()
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "run-fallback-smoke",
                "--run-dir",
                str(run_dir),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "READY")

        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        smoke = state["fallback_readiness_smoke"]
        self.assertEqual(smoke["status"], "passed")
        self.assertEqual(smoke["sample"], "READY")

    def test_run_fallback_smoke_releases_lock_and_merges_other_updates(self) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare()
        self._attach_child(run_dir, "child-smoke-race")
        smoke_started = threading.Event()
        release_smoke = threading.Event()
        phase_finished = threading.Event()
        child_finished = threading.Event()
        failures: list[BaseException] = []
        smoke_run_descriptor_opens: list[int] = []
        smoke_lock_descriptor_opens: list[int] = []
        real_open_run_directory = module._open_run_directory
        real_open_run_lock_descriptor = module._open_run_lock_descriptor

        def blocking_smoke(
            command: list[str],
            *,
            cwd: pathlib.Path,
        ) -> subprocess.CompletedProcess[str]:
            self.assertTrue(command)
            self.assertEqual(cwd, self.repo.resolve())
            smoke_started.set()
            if not release_smoke.wait(5):
                raise RuntimeError("timed out waiting to release smoke")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="READY\n",
                stderr="",
            )

        def tracked_open_run_directory(*args, **kwargs):
            if threading.current_thread().name == "smoke":
                smoke_run_descriptor_opens.append(1)
            return real_open_run_directory(*args, **kwargs)

        def tracked_open_run_lock_descriptor(*args, **kwargs):
            if threading.current_thread().name == "smoke":
                smoke_lock_descriptor_opens.append(1)
            return real_open_run_lock_descriptor(*args, **kwargs)

        def run_smoke() -> None:
            try:
                module._run_fallback_smoke(argparse.Namespace(run_dir=str(run_dir)))
            except BaseException as error:
                failures.append(error)

        def record_phase() -> None:
            try:
                module._record_phase(
                    argparse.Namespace(
                        run_dir=str(run_dir),
                        phase="tests",
                        status="passed",
                        summary="completed while smoke was running",
                        finding=[],
                        evidence=["deterministic lock-free smoke interleaving"],
                    )
                )
            except BaseException as error:
                failures.append(error)
            finally:
                phase_finished.set()

        def finish_child() -> None:
            try:
                module._finish_child(
                    argparse.Namespace(
                        run_dir=str(run_dir),
                        child_status="completed",
                        child_session_id="child-smoke-race",
                    )
                )
            except BaseException as error:
                failures.append(error)
            finally:
                child_finished.set()

        with mock.patch.object(
            module,
            "_run_bounded_smoke_process",
            side_effect=blocking_smoke,
        ):
            with mock.patch.object(
                module,
                "_open_run_directory",
                side_effect=tracked_open_run_directory,
            ):
                with mock.patch.object(
                    module,
                    "_open_run_lock_descriptor",
                    side_effect=tracked_open_run_lock_descriptor,
                ):
                    smoke_thread = threading.Thread(target=run_smoke, name="smoke")
                    phase_thread = threading.Thread(
                        target=record_phase,
                        name="record-phase",
                    )
                    child_thread = threading.Thread(
                        target=finish_child,
                        name="finish-child",
                    )
                    smoke_thread.start()
                    self.assertTrue(smoke_started.wait(5), failures)
                    phase_thread.start()
                    child_thread.start()
                    try:
                        self.assertTrue(phase_finished.wait(5))
                        self.assertTrue(child_finished.wait(5))
                    finally:
                        release_smoke.set()
                    smoke_thread.join(5)
                    phase_thread.join(5)
                    child_thread.join(5)

        self.assertFalse(smoke_thread.is_alive())
        self.assertFalse(phase_thread.is_alive())
        self.assertFalse(child_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(smoke_run_descriptor_opens, [1])
        self.assertEqual(smoke_lock_descriptor_opens, [1])
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phases"]["tests"]["status"], "passed")
        self.assertEqual(
            state["phases"]["tests"]["summary"],
            "completed while smoke was running",
        )
        self.assertEqual(state["orchestration"]["child_status"], "completed")
        self.assertEqual(state["fallback_readiness_smoke"]["status"], "passed")
        self.assertEqual(state["fallback_readiness_smoke"]["sample"], "READY")

    def test_bounded_smoke_kills_timed_out_process_group(self) -> None:
        module = self._load_runner_module()
        helper = self.root / "hanging-smoke.py"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import subprocess
                import sys
                import time

                print(os.getpgrp(), flush=True)
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"]
                )
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )

        completed = module._run_bounded_smoke_process(
            [sys.executable, str(helper)],
            cwd=self.repo,
            timeout=0.75,
            cleanup_timeout=3,
        )

        self.assertEqual(completed.returncode, 124)
        self.assertIn("hard timeout", completed.stderr)
        process_group = int(completed.stdout.strip().splitlines()[0])
        self.assertFalse(module._process_group_exists(process_group))

    def test_bounded_smoke_kills_process_group_at_byte_ceiling(self) -> None:
        module = self._load_runner_module()
        helper = self.root / "noisy-smoke.py"
        process_group_path = self.root / "noisy-smoke-pgid.txt"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import sys
                import time

                pathlib.Path(sys.argv[1]).write_text(
                    str(os.getpgrp()),
                    encoding="utf-8",
                )
                sys.stdout.write("x" * (1024 * 1024))
                sys.stdout.flush()
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )

        completed = module._run_bounded_smoke_process(
            [sys.executable, str(helper), str(process_group_path)],
            cwd=self.repo,
            timeout=5,
            cleanup_timeout=3,
            max_capture_bytes=1024,
        )

        self.assertEqual(completed.returncode, 125)
        self.assertIn("output exceeded 1024 bytes", completed.stderr)
        self.assertLessEqual(
            len(completed.stdout.encode("utf-8"))
            + len(
                completed.stderr.replace(
                    "BLOCKED: smoke output exceeded 1024 bytes\n",
                    "",
                ).encode("utf-8")
            ),
            1024,
        )
        process_group = int(process_group_path.read_text(encoding="utf-8"))
        self.assertFalse(module._process_group_exists(process_group))

    def test_rejects_passed_review_for_dirty_or_unproven_state(self) -> None:
        run_dir = self._prepare()
        self._attach_child(run_dir, "child-guard")
        completed = self._run_runner(
            "record-phase",
            "--run-dir",
            str(run_dir),
            "--phase",
            "internal_review",
            "--status",
            "passed",
            "--summary",
            "review clean",
            "--evidence",
            "reviewer terminal artifact",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("before the child is terminal", completed.stderr)

        self._finish_child(run_dir, "child-guard")
        completed = self._run_runner(
            "record-phase",
            "--run-dir",
            str(run_dir),
            "--phase",
            "internal_review",
            "--status",
            "passed",
            "--summary",
            "review clean",
            "--evidence",
            "reviewer terminal artifact",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("dirty or untracked", completed.stderr)

        self._commit_implementation()
        completed = self._run_runner(
            "record-phase",
            "--run-dir",
            str(run_dir),
            "--phase",
            "internal_review",
            "--status",
            "passed",
            "--summary",
            "review clean",
            "--evidence",
            "   ",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("terminal reviewer evidence", completed.stderr)

    def test_close_open_phases_cannot_pass_review_phases(self) -> None:
        run_dir = self._prepare()
        self._attach_child(run_dir, "child-close-open")
        self._finish_child(run_dir, "child-close-open")
        self._commit_implementation()

        completed = self._run_runner(
            "close-open-phases",
            "--run-dir",
            str(run_dir),
            "--status",
            "passed",
            "--summary",
            "everything passed",
            "--evidence",
            "reviewer terminal artifact",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot mark review phases passed", completed.stderr)

    def test_finish_child_requires_attached_matching_child(self) -> None:
        run_dir = self._prepare()
        completed = self._run_runner(
            "finish-child",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--child-session-id", completed.stderr)

        completed = self._run_runner(
            "finish-child",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-unattached",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("before attach-child", completed.stderr)

        self._attach_child(run_dir, "child-match")
        completed = self._run_runner(
            "finish-child",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "   ",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("nonblank child session id", completed.stderr)

        completed = self._run_runner(
            "finish-child",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-other",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match the attached child", completed.stderr)

        self._finish_child(run_dir, "child-match")
        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--child-session-id", completed.stderr)

        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "   ",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("nonblank child session id", completed.stderr)

        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-other",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match the attached child", completed.stderr)

    def test_attach_child_rejects_blank_session_id_without_mutation(self) -> None:
        run_dir = self._prepare()
        completed = self._run_runner(
            "attach-child",
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            "   ",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("nonblank child session id", completed.stderr)

        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        orchestration = state["orchestration"]
        self.assertIsNone(orchestration["child_session_id"])
        self.assertEqual(orchestration["child_status"], "pending")

        self._attach_child(run_dir, "child-recovered")

    def test_terminal_replay_preserves_child_finished_at(self) -> None:
        run_dir = self._prepare()
        child_session_id = "child-terminal-replay"
        self._attach_child(run_dir, child_session_id)
        self._finish_child(run_dir, child_session_id)
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        original_finished_at = "2000-01-01T00:00:00+00:00"
        state["orchestration"]["child_finished_at"] = original_finished_at
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        self._finish_child(run_dir, child_session_id)
        replayed = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            replayed["orchestration"]["child_finished_at"], original_finished_at
        )

        completed = self._run_runner(
            "close-open-phases",
            "--run-dir",
            str(run_dir),
            "--status",
            "blocked",
            "--summary",
            "terminal replay test",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            child_session_id,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        reconciled = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            reconciled["orchestration"]["child_finished_at"], original_finished_at
        )

    def test_attach_child_begin_phase_and_reconcile_parent(self) -> None:
        run_dir = self._prepare()
        completed = self._run_runner(
            "attach-child",
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            "child-1",
            "--parent-session-id",
            "parent-2",
            "--parent-turn-id",
            "turn-2",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = self._run_runner(
            "begin-phase",
            "--run-dir",
            str(run_dir),
            "--phase",
            "tests",
            "--summary",
            "running tests",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
            "--require-terminal",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "cannot finalize before all phases reach terminal status", completed.stderr
        )

        self._finish_child(run_dir, "child-1")
        self._commit_implementation()

        phase_results = {
            "tests": ("passed", "broad tests passed"),
            "docs_sync": ("passed", "docs synced"),
            "internal_review": ("decision_point", "needs the user decision"),
            "external_review": ("passed", "external review clean"),
        }
        for phase_name, (status, summary) in phase_results.items():
            completed = self._run_runner(
                "record-phase",
                "--run-dir",
                str(run_dir),
                "--phase",
                phase_name,
                "--status",
                status,
                "--summary",
                summary,
                *(
                    ["--evidence", "reviewer terminal artifact"]
                    if phase_name in ("internal_review", "external_review")
                    and status == "passed"
                    else []
                ),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-1",
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        summary_path = pathlib.Path(payload["summary_path"])
        summary_text = summary_path.read_text(encoding="utf-8")
        self.assertIn("Overall status: `decision_point`", summary_text)
        self.assertIn("Child status: `completed`", summary_text)
        self.assertEqual(payload["overall_status"], "decision_point")
        self.assertEqual(payload["child_status"], "completed")
        self.assertEqual(payload["child_session_id"], "child-1")

        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["overall_status"], "decision_point")
        self.assertEqual(state["orchestration"]["child_session_id"], "child-1")
        self.assertEqual(state["orchestration"]["child_status"], "completed")

    def test_finalize_and_reconcile_recheck_clean_after_passed_review(self) -> None:
        run_dir = self._prepare()
        self._attach_child(run_dir, "child-recheck")
        self._finish_child(run_dir, "child-recheck")
        self._commit_implementation()

        phase_results = {
            "tests": ("passed", []),
            "docs_sync": ("passed", []),
            "internal_review": ("passed", ["reviewer terminal artifact"]),
            "external_review": ("unavailable", []),
        }
        for phase_name, (status, evidence) in phase_results.items():
            completed = self._run_runner(
                "record-phase",
                "--run-dir",
                str(run_dir),
                "--phase",
                phase_name,
                "--status",
                status,
                "--summary",
                f"{phase_name} {status}",
                *sum((["--evidence", item] for item in evidence), []),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["orchestration"]["child_status"] = "running"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("before the child is terminal", completed.stderr)

        state["orchestration"]["child_status"] = "completed"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        (self.repo / "tracked.txt").write_text(
            "changed after review\n", encoding="utf-8"
        )
        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("dirty or untracked", completed.stderr)

        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-recheck",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("dirty or untracked", completed.stderr)

    def test_finalize_rejects_legacy_terminal_state_without_child_identity(
        self,
    ) -> None:
        run_dir = self._prepare()
        self._commit_implementation()
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        orchestration = state["orchestration"]
        orchestration["child_status"] = "completed"
        orchestration["child_session_id"] = "   "
        for phase in state["phases"].values():
            phase["status"] = "blocked"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        completed = self._run_runner(
            "record-phase",
            "--run-dir",
            str(run_dir),
            "--phase",
            "internal_review",
            "--status",
            "passed",
            "--summary",
            "legacy review",
            "--evidence",
            "reviewer terminal artifact",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("nonblank attached child session id", completed.stderr)

        state["phases"]["internal_review"]["status"] = "passed"
        state["phases"]["internal_review"]["evidence"] = ["reviewer terminal artifact"]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("nonblank attached child session id", completed.stderr)

        state["phases"]["internal_review"]["status"] = "blocked"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("terminal run without a nonblank", completed.stderr)

        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
            "--require-terminal",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("terminal run without a nonblank", completed.stderr)

    def test_finalize_rejects_legacy_state_without_internal_review(self) -> None:
        run_dir = self._prepare()
        self._attach_child(run_dir, "child-missing-review")
        self._finish_child(run_dir, "child-missing-review")
        self._commit_implementation()
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["phases_order"].remove("internal_review")
        del state["phases"]["internal_review"]
        for phase in state["phases"].values():
            phase["status"] = "blocked"
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        completed = self._run_runner(
            "finalize",
            "--run-dir",
            str(run_dir),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing the required internal_review phase", completed.stderr)

        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-missing-review",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing the required internal_review phase", completed.stderr)

    def test_reconcile_parent_tolerates_legacy_state_missing_optional_metadata(
        self,
    ) -> None:
        run_dir = self._prepare()
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        del state["orchestration"]["parent_transcript_path"]
        del state["orchestration"]["permission_mode"]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        self._attach_child(run_dir, "child-legacy")
        self._finish_child(run_dir, "child-legacy")
        self._commit_implementation()

        for phase_name in ("tests", "docs_sync", "internal_review", "external_review"):
            completed = self._run_runner(
                "record-phase",
                "--run-dir",
                str(run_dir),
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

        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-legacy",
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["overall_status"], "passed")
        summary_text = pathlib.Path(payload["summary_path"]).read_text(encoding="utf-8")
        self.assertIn("Parent transcript: `unknown`", summary_text)
        self.assertIn("Permission mode: `unknown`", summary_text)

    def test_close_open_phases_allows_early_stop_reconciliation(self) -> None:
        run_dir = self._prepare()
        completed = self._run_runner(
            "attach-child",
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            "child-2",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = self._run_runner(
            "record-phase",
            "--run-dir",
            str(run_dir),
            "--phase",
            "tests",
            "--status",
            "failed",
            "--summary",
            "tests failed decisively",
            "--evidence",
            "pytest -q failed",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = self._run_runner(
            "close-open-phases",
            "--run-dir",
            str(run_dir),
            "--status",
            "blocked",
            "--summary",
            "not run because tests already failed",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = self._run_runner(
            "reconcile-parent",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "failed",
            "--child-session-id",
            "child-2",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["overall_status"], "failed")
        self.assertEqual(state["phases"]["tests"]["status"], "failed")
        self.assertEqual(state["phases"]["docs_sync"]["status"], "blocked")
        self.assertEqual(state["orchestration"]["child_status"], "failed")


if __name__ == "__main__":
    unittest.main()
