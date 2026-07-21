from __future__ import annotations

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

    def _run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run([sys.executable, str(RUNNER_PATH), *args])

    def _run_bridge(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        bridge_env = os.environ.copy()
        if env:
            bridge_env.update(env)
        return run([sys.executable, str(BRIDGE_PATH), *args], env=bridge_env)

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
