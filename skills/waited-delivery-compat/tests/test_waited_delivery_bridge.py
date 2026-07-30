"""Compatibility tests for the historical waited-delivery bridge."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest


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
ADAPTER_PATH = BRIDGE_PATH.with_name("waited_delivery_hook_adapter.py")


def load_adapter_module():
    spec = importlib.util.spec_from_file_location(
        "waited_delivery_bridge_adapter_test_module",
        ADAPTER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load waited-delivery hook adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        input=input_bytes,
        capture_output=True,
        check=False,
        pass_fds=pass_fds,
    )
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        stdout=completed.stdout.decode("utf-8", errors="replace"),
        stderr=completed.stderr.decode("utf-8", errors="replace"),
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


class WaitedDeliveryBridgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="waited-delivery-bridge-")
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

    def _assert_file_version_payload(
        self,
        payload: object,
        path: pathlib.Path,
    ) -> None:
        self.assertIsInstance(payload, dict)
        version = payload
        assert isinstance(version, dict)
        file_stat = path.stat()
        content = path.read_bytes()
        self.assertEqual(version["device"], file_stat.st_dev)
        self.assertEqual(version["inode"], file_stat.st_ino)
        self.assertEqual(version["uid"], file_stat.st_uid)
        self.assertEqual(version["gid"], file_stat.st_gid)
        self.assertEqual(version["mode"], file_stat.st_mode & 0o7777)
        self.assertEqual(version["size"], len(content))
        self.assertEqual(
            version["sha256"],
            hashlib.sha256(content).hexdigest(),
        )

    def _run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run([sys.executable, str(RUNNER_PATH), *args])

    def _run_bridge(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        bridge_env = os.environ.copy()
        if env:
            bridge_env.update(env)
        return run([sys.executable, str(BRIDGE_PATH), *args], env=bridge_env)

    def _version_args(
        self,
        prefix: str,
        path: pathlib.Path,
        *,
        sha256: str | None = None,
    ) -> list[str]:
        file_stat = path.stat()
        return [
            f"--expected-{prefix}-dev",
            str(file_stat.st_dev),
            f"--expected-{prefix}-ino",
            str(file_stat.st_ino),
            f"--expected-{prefix}-uid",
            str(file_stat.st_uid),
            f"--expected-{prefix}-gid",
            str(file_stat.st_gid),
            f"--expected-{prefix}-mode",
            str(file_stat.st_mode & 0o7777),
            f"--expected-{prefix}-size",
            str(file_stat.st_size),
            f"--expected-{prefix}-sha256",
            sha256 or hashlib.sha256(path.read_bytes()).hexdigest(),
        ]

    def _run_refresh_bridge(
        self,
        *args: str,
        runner_sha256: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_bound_refresh_bridge(
            BRIDGE_PATH,
            RUNNER_PATH,
            *args,
            runner_sha256=runner_sha256,
            env=env,
        )

    def _source_frame(
        self,
        bridge_source: bytes,
        runner_source: bytes,
    ) -> bytes:
        adapter = load_adapter_module()
        return b"".join(
            (
                adapter.SOURCE_FRAME_MAGIC,
                len(bridge_source).to_bytes(8, "big"),
                hashlib.sha256(bridge_source).digest(),
                len(runner_source).to_bytes(8, "big"),
                hashlib.sha256(runner_source).digest(),
                bridge_source,
                runner_source,
            )
        )

    def _run_bound_refresh_bridge(
        self,
        bridge_path: pathlib.Path,
        runner_path: pathlib.Path,
        *args: str,
        runner_sha256: str | None = None,
        env: dict[str, str] | None = None,
        source_frame: bytes | None = None,
    ) -> subprocess.CompletedProcess[str]:
        bridge_source = bridge_path.read_bytes()
        runner_source = runner_path.read_bytes()
        if source_frame is None:
            source_frame = self._source_frame(bridge_source, runner_source)
        return run(
            self._bound_refresh_command(
                bridge_path,
                runner_path,
                *args,
                runner_sha256=runner_sha256,
            ),
            env=env,
            input_bytes=source_frame,
        )

    def _bound_refresh_command(
        self,
        bridge_path: pathlib.Path,
        runner_path: pathlib.Path,
        *args: str,
        runner_sha256: str | None = None,
    ) -> list[str]:
        adapter = load_adapter_module()
        return [
            sys.executable,
            "-I",
            "-B",
            "-S",
            "-c",
            adapter.SOURCE_PIPE_BOOTSTRAP,
            str(bridge_path),
            str(runner_path),
            "refresh-prompts-live",
            "--published-bridge-path",
            str(bridge_path),
            "--published-runner-path",
            str(runner_path),
            *self._version_args(
                "bridge",
                bridge_path,
            ),
            *self._version_args(
                "runner",
                runner_path,
                sha256=runner_sha256,
            ),
            *args,
        ]

    def _prepare_run_dir(self) -> pathlib.Path:
        completed = self._run_runner(
            "prepare",
            "--repo",
            str(self.repo),
            "--goal",
            "Bridge smoke",
            "--external-helper",
            str(self.fake_helper),
            "--json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        return pathlib.Path(payload["run_dir"])

    def _commit_implementation(self) -> None:
        self.assertEqual(git(self.repo, "add", "tracked.txt").returncode, 0)
        git_commit(self.repo, "freeze implementation")

    def _finish_child(self, run_dir: pathlib.Path, child_session_id: str) -> None:
        attached = self._run_bridge(
            "attach-child-live",
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            child_session_id,
        )
        self.assertEqual(attached.returncode, 0, attached.stderr)
        completed = self._run_bridge(
            "finish-child-live",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            child_session_id,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["child_status"], "completed")

    def test_terminal_commands_require_child_session_id(self) -> None:
        for command in ("finish-child-live", "reconcile-live"):
            with self.subTest(command=command):
                completed = self._run_bridge(
                    command,
                    "--run-dir",
                    "/tmp/waited-delivery-run",
                    "--child-status",
                    "completed",
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("--child-session-id", completed.stderr)

    def test_prepare_live_uses_env_parent_metadata(self) -> None:
        completed = self._run_bridge(
            "prepare-live",
            "--repo",
            str(self.repo),
            "--goal",
            "Bridge live prepare",
            "--external-helper",
            str(self.fake_helper),
            "--no-fallback-smoke",
            env={
                "WAITED_DELIVERY_PARENT_SESSION_ID": "parent-env-1",
                "WAITED_DELIVERY_PARENT_TURN_ID": "turn-env-1",
                "WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH": "/tmp/parent-env-1.jsonl",
                "WAITED_DELIVERY_PERMISSION_MODE": "acceptEdits",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        state = json.loads(
            (pathlib.Path(payload["run_dir"]) / "state.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(state["orchestration"]["parent_session_id"], "parent-env-1")
        self.assertEqual(state["orchestration"]["parent_turn_id"], "turn-env-1")
        self.assertEqual(
            state["orchestration"]["parent_transcript_path"],
            "/tmp/parent-env-1.jsonl",
        )
        self.assertEqual(state["orchestration"]["permission_mode"], "acceptEdits")

    def test_bind_parent_live_updates_existing_run(self) -> None:
        run_dir = self._prepare_run_dir()
        completed = self._run_bridge(
            "bind-parent-live",
            "--run-dir",
            str(run_dir),
            env={
                "WAITED_DELIVERY_PARENT_SESSION_ID": "parent-env-2",
                "WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH": "/tmp/parent-env-2.jsonl",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["parent_session_id"], "parent-env-2")
        self.assertEqual(
            state["orchestration"]["parent_transcript_path"],
            "/tmp/parent-env-2.jsonl",
        )

    def test_refresh_prompts_live_uses_loaded_compatibility_runner(self) -> None:
        run_dir = self._prepare_run_dir()
        legacy_runner = pathlib.Path(
            "/legacy/skills/waited-delivery/scripts/waited_delivery_runner.py"
        )
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            (run_dir / prompt_name).write_text(
                f"`{sys.executable} {legacy_runner}`\n",
                encoding="utf-8",
            )
        run_identity = run_dir.stat()

        completed = self._run_refresh_bridge(
            "--run-dir",
            str(run_dir),
            "--expected-run-dev",
            str(run_identity.st_dev),
            "--expected-run-ino",
            str(run_identity.st_ino),
            "--expected-run-uid",
            str(run_identity.st_uid),
            "--expected-run-gid",
            str(run_identity.st_gid),
            "--expected-run-mode",
            str(run_identity.st_mode & 0o7777),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["refresh_schema_version"], 3)
        self.assertIs(payload["python_isolated"], True)
        self.assertEqual(
            payload["bridge_source_transport"],
            "anonymous-pipe-memory",
        )
        self.assertEqual(
            payload["runner_source_transport"],
            "anonymous-pipe-memory",
        )
        self.assertIs(payload["bridge_source_reopenable"], False)
        self.assertIs(payload["runner_source_reopenable"], False)
        self.assertEqual(payload["runner_path"], str(RUNNER_PATH))
        self.assertEqual(payload["compiled_bridge_path"], str(BRIDGE_PATH))
        self.assertEqual(payload["compiled_runner_path"], str(RUNNER_PATH))
        self._assert_file_version_payload(payload["bridge_version"], BRIDGE_PATH)
        self._assert_file_version_payload(payload["runner_version"], RUNNER_PATH)
        self._assert_file_version_payload(
            payload["child_prompt_version"],
            run_dir / "child-prompt.md",
        )
        self._assert_file_version_payload(
            payload["parent_prompt_version"],
            run_dir / "parent-prompt.md",
        )
        self.assertEqual(payload["run_dev"], run_identity.st_dev)
        self.assertEqual(payload["run_ino"], run_identity.st_ino)
        self.assertEqual(payload["run_uid"], run_identity.st_uid)
        self.assertEqual(payload["run_gid"], run_identity.st_gid)
        self.assertEqual(payload["run_mode"], run_identity.st_mode & 0o7777)
        for prompt_name in ("child-prompt.md", "parent-prompt.md"):
            prompt = (run_dir / prompt_name).read_text(encoding="utf-8")
            self.assertIn(str(RUNNER_PATH), prompt)
            self.assertNotIn(str(legacy_runner), prompt)

    def test_refresh_prompts_live_rejects_runner_mismatch_before_writes(self) -> None:
        run_dir = self._prepare_run_dir()
        watched_paths = tuple(
            run_dir / name
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        )
        before = {
            path: (path.stat().st_ino, path.read_bytes()) for path in watched_paths
        }
        completed = self._run_refresh_bridge(
            "--run-dir",
            str(run_dir),
            runner_sha256="0" * 64,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "bound compatibility runner source content changed", completed.stderr
        )
        for path, (expected_inode, expected_content) in before.items():
            self.assertEqual(path.stat().st_ino, expected_inode)
            self.assertEqual(path.read_bytes(), expected_content)

    def test_refresh_prompts_live_rejects_source_path_bridge_launch_before_writes(
        self,
    ) -> None:
        run_dir = self._prepare_run_dir()
        watched_paths = tuple(
            run_dir / name
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        )
        before = {
            path: (path.stat().st_ino, path.read_bytes()) for path in watched_paths
        }
        completed = run(
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(BRIDGE_PATH),
                "refresh-prompts-live",
                "--run-dir",
                str(run_dir),
                "--published-bridge-path",
                str(BRIDGE_PATH),
                "--published-runner-path",
                str(RUNNER_PATH),
                *self._version_args("bridge", BRIDGE_PATH),
                *self._version_args("runner", RUNNER_PATH),
            ],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "requires anonymous-pipe-bound source bytes",
            completed.stderr,
        )
        for path, (expected_inode, expected_content) in before.items():
            self.assertEqual(path.stat().st_ino, expected_inode)
            self.assertEqual(path.read_bytes(), expected_content)

    def test_refresh_prompts_live_rejects_malformed_source_frames_before_writes(
        self,
    ) -> None:
        run_dir = self._prepare_run_dir()
        watched_paths = tuple(
            run_dir / name
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        )
        before = {
            path: (path.stat().st_ino, path.read_bytes()) for path in watched_paths
        }
        adapter = load_adapter_module()
        bridge_source = BRIDGE_PATH.read_bytes()
        runner_source = RUNNER_PATH.read_bytes()
        valid_frame = self._source_frame(bridge_source, runner_source)
        oversized_frame = b"".join(
            (
                adapter.SOURCE_FRAME_MAGIC,
                (adapter.STATE_MAX_BYTES + 1).to_bytes(8, "big"),
                hashlib.sha256(bridge_source).digest(),
                len(runner_source).to_bytes(8, "big"),
                hashlib.sha256(runner_source).digest(),
            )
        )
        digest_mismatch = bytearray(valid_frame)
        digest_mismatch[16] ^= 0xFF
        variants = {
            "truncated": valid_frame[:-1],
            "oversized": oversized_frame,
            "trailing": valid_frame + b"x",
            "digest-mismatch": bytes(digest_mismatch),
        }
        for name, source_frame in variants.items():
            with self.subTest(frame=name):
                completed = self._run_bound_refresh_bridge(
                    BRIDGE_PATH,
                    RUNNER_PATH,
                    "--run-dir",
                    str(run_dir),
                    source_frame=source_frame,
                )
                self.assertNotEqual(completed.returncode, 0)
                for path, (expected_inode, expected_content) in before.items():
                    self.assertEqual(path.stat().st_ino, expected_inode)
                    self.assertEqual(path.read_bytes(), expected_content)

    def test_refresh_prompts_live_blocks_pythonpath_site_injection(self) -> None:
        run_dir = self._prepare_run_dir()
        injection_dir = self.root / "pythonpath-injection"
        injection_dir.mkdir()
        marker = self.root / "unexpected-sitecustomize.txt"
        (injection_dir / "sitecustomize.py").write_text(
            "import pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text("
            "'unexpected site import\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        injected_env = os.environ.copy()
        injected_env["PYTHONPATH"] = str(injection_dir)
        injected_env["PYTHONINSPECT"] = "1"

        completed = self._run_refresh_bridge(
            "--run-dir",
            str(run_dir),
            env=injected_env,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(marker.exists())
        payload = json.loads(completed.stdout)
        self.assertIs(payload["python_isolated"], True)
        self.assertEqual(
            payload["bridge_source_transport"],
            "anonymous-pipe-memory",
        )
        self.assertEqual(
            payload["runner_source_transport"],
            "anonymous-pipe-memory",
        )

    def test_refresh_prompts_live_executes_pipe_bound_bytes_across_source_aba(
        self,
    ) -> None:
        for artifact_name in ("bridge", "runner"):
            with self.subTest(artifact=artifact_name):
                run_dir = self._prepare_run_dir()
                launch_dir = self.root / f"launch-aba-{artifact_name}"
                launch_dir.mkdir()
                bridge_path = launch_dir / BRIDGE_PATH.name
                runner_path = launch_dir / RUNNER_PATH.name
                bridge_path.write_bytes(BRIDGE_PATH.read_bytes())
                runner_path.write_bytes(RUNNER_PATH.read_bytes())
                bridge_path.chmod(BRIDGE_PATH.stat().st_mode & 0o7777)
                runner_path.chmod(RUNNER_PATH.stat().st_mode & 0o7777)
                source_path = bridge_path if artifact_name == "bridge" else runner_path
                source_stat = source_path.stat()
                displaced = launch_dir / f"{artifact_name}-original.py"
                marker = self.root / f"unexpected-{artifact_name}-execution.txt"
                malicious = (
                    "#!/usr/bin/env python3\n"
                    "import pathlib\n"
                    f"pathlib.Path({str(marker)!r}).write_text("
                    "'unexpected path execution\\n', encoding='utf-8')\n"
                    "raise SystemExit(93)\n"
                )
                source_frame = self._source_frame(
                    bridge_path.read_bytes(),
                    runner_path.read_bytes(),
                )
                command = self._bound_refresh_command(
                    bridge_path,
                    runner_path,
                    "--run-dir",
                    str(run_dir),
                )
                source_path.rename(displaced)
                source_path.write_text(malicious, encoding="utf-8")
                source_path.chmod(source_stat.st_mode & 0o7777)
                try:
                    completed = run(
                        command,
                        input_bytes=source_frame,
                    )
                finally:
                    source_path.unlink()
                    displaced.rename(source_path)

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertFalse(marker.exists())
                self.assertEqual(source_path.stat().st_ino, source_stat.st_ino)
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["refresh_schema_version"], 3)
                for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                    self.assertIn(
                        str(runner_path),
                        (run_dir / prompt_name).read_text(encoding="utf-8"),
                    )

    def test_attach_child_live_propagates_env_parent_metadata(self) -> None:
        run_dir = self._prepare_run_dir()
        completed = self._run_bridge(
            "attach-child-live",
            "--run-dir",
            str(run_dir),
            "--child-session-id",
            "child-env-1",
            env={
                "WAITED_DELIVERY_PARENT_SESSION_ID": "parent-env-3",
                "WAITED_DELIVERY_PARENT_TURN_ID": "turn-env-3",
                "WAITED_DELIVERY_PERMISSION_MODE": "dontAsk",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["orchestration"]["child_session_id"], "child-env-1")
        self.assertEqual(state["orchestration"]["parent_session_id"], "parent-env-3")
        self.assertEqual(state["orchestration"]["parent_turn_id"], "turn-env-3")
        self.assertEqual(state["orchestration"]["permission_mode"], "dontAsk")

    def test_reconcile_live_returns_json(self) -> None:
        run_dir = self._prepare_run_dir()
        self._finish_child(run_dir, "child-env-2")
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
        completed = self._run_bridge(
            "reconcile-live",
            "--run-dir",
            str(run_dir),
            "--child-status",
            "completed",
            "--child-session-id",
            "child-env-2",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["overall_status"], "passed")
        self.assertEqual(payload["child_status"], "completed")
        self.assertEqual(payload["child_session_id"], "child-env-2")


if __name__ == "__main__":
    unittest.main()
