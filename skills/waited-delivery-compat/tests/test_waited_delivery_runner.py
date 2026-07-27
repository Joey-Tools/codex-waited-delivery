"""Compatibility tests for the historical waited-delivery runner."""

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
