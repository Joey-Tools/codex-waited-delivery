from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest


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
        child_prompt = (run_dir / "child-prompt.md").read_text(encoding="utf-8")
        self.assertIn("Waited Delivery Child Prompt", child_prompt)
        self.assertIn("begin-phase", child_prompt)
        self.assertIn("record-phase", child_prompt)
        parent_prompt = (run_dir / "parent-prompt.md").read_text(encoding="utf-8")
        self.assertIn("Waited Delivery Parent Prompt", parent_prompt)
        self.assertIn("attach-child", parent_prompt)
        self.assertIn("reconcile-parent", parent_prompt)
        self.assertTrue((run_dir / "fallback-smoke.command.txt").is_file())

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

    def test_reconcile_parent_tolerates_legacy_state_missing_optional_metadata(
        self,
    ) -> None:
        run_dir = self._prepare()
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        del state["orchestration"]["parent_transcript_path"]
        del state["orchestration"]["permission_mode"]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

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
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["overall_status"], "failed")
        self.assertEqual(state["phases"]["tests"]["status"], "failed")
        self.assertEqual(state["phases"]["docs_sync"]["status"], "blocked")
        self.assertEqual(state["orchestration"]["child_status"], "failed")


if __name__ == "__main__":
    unittest.main()
