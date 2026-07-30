"""Compatibility tests for the historical waited-delivery runner."""

from __future__ import annotations

import argparse
import copy
import contextlib
import fcntl
import hashlib
import io
import json
import importlib.util
import os
import pathlib
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock


SCRIPT_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "waited_delivery_runner.py"
)
BRIDGE_PATH = SCRIPT_PATH.with_name("waited_delivery_bridge.py")


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    umask: int = -1,
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
        umask=umask,
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

    def _runner_version(self) -> dict[str, int | str]:
        file_stat = SCRIPT_PATH.stat()
        content = SCRIPT_PATH.read_bytes()
        return {
            "device": file_stat.st_dev,
            "inode": file_stat.st_ino,
            "uid": file_stat.st_uid,
            "gid": file_stat.st_gid,
            "mode": file_stat.st_mode & 0o7777,
            "size": file_stat.st_size,
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def _runner_version_args(
        self,
        *,
        sha256: str | None = None,
    ) -> list[str]:
        version = self._runner_version()
        return [
            "--expected-runner-dev",
            str(version["device"]),
            "--expected-runner-ino",
            str(version["inode"]),
            "--expected-runner-uid",
            str(version["uid"]),
            "--expected-runner-gid",
            str(version["gid"]),
            "--expected-runner-mode",
            str(version["mode"]),
            "--expected-runner-size",
            str(version["size"]),
            "--expected-runner-sha256",
            sha256 or str(version["sha256"]),
        ]

    def _bridge_version_args(self) -> list[str]:
        file_stat = BRIDGE_PATH.stat()
        return [
            "--expected-bridge-dev",
            str(file_stat.st_dev),
            "--expected-bridge-ino",
            str(file_stat.st_ino),
            "--expected-bridge-uid",
            str(file_stat.st_uid),
            "--expected-bridge-gid",
            str(file_stat.st_gid),
            "--expected-bridge-mode",
            str(file_stat.st_mode & 0o7777),
            "--expected-bridge-size",
            str(file_stat.st_size),
            "--expected-bridge-sha256",
            hashlib.sha256(BRIDGE_PATH.read_bytes()).hexdigest(),
        ]

    def _run_refresh_runner(
        self,
        *args: str,
        expected_sha256: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        bridge = self._load_bridge_module()
        runner_source = SCRIPT_PATH.read_bytes()
        source_frame = b"".join(
            (
                bridge.RUNNER_FRAME_MAGIC,
                len(runner_source).to_bytes(8, "big"),
                hashlib.sha256(runner_source).digest(),
                runner_source,
            )
        )
        return run(
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                "-c",
                bridge.RUNNER_PIPE_BOOTSTRAP,
                str(SCRIPT_PATH),
                "refresh-prompts",
                "--compiled-bridge-path",
                str(BRIDGE_PATH),
                "--compiled-runner-path",
                str(SCRIPT_PATH),
                "--published-runner-path",
                str(SCRIPT_PATH),
                *self._bridge_version_args(),
                *self._runner_version_args(
                    sha256=expected_sha256,
                ),
                *args,
            ],
            input_bytes=source_frame,
        )

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

    def _load_bridge_module(self):
        spec = importlib.util.spec_from_file_location(
            "waited_delivery_runner_bridge_test_module",
            BRIDGE_PATH,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to load waited_delivery_bridge module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _direct_refresh_args(
        self,
        module,
        run_dir: pathlib.Path,
    ) -> argparse.Namespace:
        bridge_stat = BRIDGE_PATH.stat()
        runner_stat = SCRIPT_PATH.stat()
        runner_source = SCRIPT_PATH.read_bytes()
        module._WAITED_DELIVERY_BOUND_RUNNER_SOURCE = runner_source
        return argparse.Namespace(
            run_dir=str(run_dir),
            expected_repo_root=None,
            expected_run_dev=None,
            expected_run_ino=None,
            expected_run_uid=None,
            expected_run_gid=None,
            expected_run_mode=None,
            compiled_bridge_path=str(BRIDGE_PATH),
            compiled_runner_path=str(SCRIPT_PATH),
            published_runner_path=str(SCRIPT_PATH),
            expected_bridge_dev=bridge_stat.st_dev,
            expected_bridge_ino=bridge_stat.st_ino,
            expected_bridge_uid=bridge_stat.st_uid,
            expected_bridge_gid=bridge_stat.st_gid,
            expected_bridge_mode=bridge_stat.st_mode & 0o7777,
            expected_bridge_size=bridge_stat.st_size,
            expected_bridge_sha256=hashlib.sha256(BRIDGE_PATH.read_bytes()).hexdigest(),
            expected_runner_dev=runner_stat.st_dev,
            expected_runner_ino=runner_stat.st_ino,
            expected_runner_uid=runner_stat.st_uid,
            expected_runner_gid=runner_stat.st_gid,
            expected_runner_mode=runner_stat.st_mode & 0o7777,
            expected_runner_size=runner_stat.st_size,
            expected_runner_sha256=hashlib.sha256(runner_source).hexdigest(),
            json=True,
        )

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

    def _seed_running_child_with_terminal_phases(
        self,
        run_dir: pathlib.Path,
        child_session_id: str,
        *,
        updated_at: str,
    ) -> dict[str, object]:
        self._attach_child(run_dir, child_session_id)
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        for phase in state["phases"].values():
            phase["status"] = "blocked"
            phase["summary"] = "capacity boundary"
            phase["updated_at"] = updated_at
        orchestration = state["orchestration"]
        orchestration["child_status"] = "running"
        orchestration["child_finished_at"] = None
        orchestration["updated_at"] = updated_at
        state["overall_status"] = "blocked"
        state["updated_at"] = updated_at
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return state

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

        self.assertEqual(state["schema_version"], 4)
        self.assertIsNone(state["preparation_id"])
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

    def test_changed_files_keep_rename_source_when_target_is_ignored(self) -> None:
        module = self._load_runner_module()
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        self.assertEqual(
            git(
                self.repo,
                "mv",
                "tracked.txt",
                ".codex-tmp/tracked.txt",
            ).returncode,
            0,
        )

        changed_files = module._collect_changed_files(self.repo)

        self.assertIn("tracked.txt", changed_files)
        self.assertNotIn(".codex-tmp/tracked.txt", changed_files)

    def test_changed_files_parse_binary_nul_framing_and_dual_paths(self) -> None:
        module = self._load_runner_module()
        path_bytes = [
            b"line\r\nname",
            b"renamed-\xff\r\n",
            b"source-\xfe\n\r",
            b"copy-\x80",
            b"copy-source-\x81\r",
        ]
        status_output = (
            b"?? " + path_bytes[0] + b"\0"
            b"R  " + path_bytes[1] + b"\0" + path_bytes[2] + b"\0"
            b"C  " + path_bytes[3] + b"\0" + path_bytes[4] + b"\0"
            b"?? .codex-tmp/ignored-\xfd\r\n\0"
        )
        completed = subprocess.CompletedProcess(
            args=["git", "status"],
            returncode=0,
            stdout=status_output,
            stderr=b"",
        )

        with mock.patch.object(
            module.subprocess,
            "run",
            return_value=completed,
        ) as run_mock:
            changed_files = module._collect_changed_files(self.repo)

        self.assertEqual(
            [os.fsencode(path) for path in changed_files],
            path_bytes,
        )
        self.assertEqual(
            [module._display_filesystem_path(path) for path in changed_files],
            [
                "line\\r\\nname",
                "renamed-\\xff\\r\\n",
                "source-\\xfe\\n\\r",
                "copy-\\x80",
                "copy-source-\\x81\\r",
            ],
        )
        serialized = json.dumps({"changed_files": changed_files})
        reloaded = json.loads(serialized)["changed_files"]
        self.assertEqual([os.fsencode(path) for path in reloaded], path_bytes)
        run_mock.assert_called_once()
        self.assertIs(run_mock.call_args.kwargs["text"], False)

    def test_filesystem_path_display_escapes_unsafe_text_for_all_consumers(
        self,
    ) -> None:
        module = self._load_runner_module()
        non_utf8_path = os.fsdecode(b"\xff")
        unsafe_path = (
            "plain-"
            "\x1b"
            "\t"
            "\x7f"
            "\u0085"
            "\u2028"
            "\u2029"
            "\u202e"
            "\u2066"
            "\u200d"
            "\ud800"
            "\udc00"
            "`"
            "\\"
            f"{non_utf8_path}"
            "\r"
            "\n"
            "-end"
        )
        expected_display = (
            "plain-"
            "\\x1b"
            "\\t"
            "\\x7f"
            "\\u0085"
            "\\u2028"
            "\\u2029"
            "\\u202e"
            "\\u2066"
            "\\u200d"
            "\\ud800"
            "\\udc00"
            "\\x60"
            "\\\\"
            "\\xff"
            "\\r"
            "\\n"
            "-end"
        )

        displayed = module._display_filesystem_path(unsafe_path)

        self.assertEqual(displayed, expected_display)
        self.assertNotIn("`", displayed)
        self.assertTrue(
            all(
                module.unicodedata.category(character)
                not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                for character in displayed
            )
        )

        run_dir = self._prepare("--no-fallback-smoke")
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        state["changed_files"] = [unsafe_path]
        contract = module._build_child_contract(state)
        self.assertIn(f"- `{expected_display}`", contract)

        state["orchestration"]["child_status"] = "completed"
        state["orchestration"]["child_session_id"] = "child-display"
        with mock.patch.object(
            module,
            "_collect_changed_files",
            return_value=[unsafe_path],
        ):
            with self.assertRaises(module.UserError) as raised:
                module._validate_review_pass(state, ["terminal review evidence"])
        self.assertEqual(
            str(raised.exception),
            "cannot record a passed review while implementation state is "
            f"dirty or untracked: {expected_display}",
        )

    def test_filesystem_path_display_is_readable_unambiguous_and_bounded(
        self,
    ) -> None:
        module = self._load_runner_module()
        self.assertEqual(
            module._display_filesystem_path("src/文档/example file.py"),
            "src/文档/example file.py",
        )
        self.assertEqual(
            module._display_filesystem_path(" leading and trailing "),
            "\\x20leading and trailing\\x20",
        )
        self.assertEqual(
            module._display_filesystem_path(r"\x1b\T{bytes=1}"),
            r"\\x1b\\T{bytes=1}",
        )
        literal_marker = "⟦truncated;identity=filesystem-bytes;bytes=1;sha256=literal⟧"
        escaped_marker = module._display_filesystem_path(literal_marker)
        self.assertEqual(
            escaped_marker,
            "\\u27e6truncated;identity=filesystem-bytes;bytes=1;sha256=literal\\u27e7",
        )
        self.assertNotIn("⟦", escaped_marker)
        self.assertNotIn("⟧", escaped_marker)

        long_path = "é" * 600
        raw_path = os.fsencode(long_path)
        displayed = module._display_filesystem_path(long_path)
        expected_suffix = (
            f"⟦truncated;identity=filesystem-bytes;bytes={len(raw_path)};"
            f"sha256={hashlib.sha256(raw_path).hexdigest()}⟧"
        )

        self.assertLessEqual(
            len(displayed.encode("utf-8")),
            module.FILESYSTEM_PATH_DISPLAY_MAX_BYTES,
        )
        self.assertTrue(displayed.endswith(expected_suffix))
        self.assertNotIn("`", displayed)

    def test_filesystem_path_display_uses_explicit_surrogate_fallback_identity(
        self,
    ) -> None:
        module = self._load_runner_module()
        short_path = "bad-\ud800-\udc00-\udc7f"
        self.assertEqual(
            module._display_filesystem_path(short_path),
            "bad-\\ud800-\\udc00-\\udc7f",
        )

        fallback_path = "\ud800\udc00" * 400
        fallback_identity = fallback_path.encode(
            "utf-8",
            errors="surrogatepass",
        )
        fallback_display = module._display_filesystem_path(fallback_path)
        fallback_suffix = (
            "⟦truncated;identity=utf8-surrogatepass;"
            f"bytes={len(fallback_identity)};"
            f"sha256={hashlib.sha256(fallback_identity).hexdigest()}⟧"
        )
        self.assertLessEqual(
            len(fallback_display.encode("utf-8")),
            module.FILESYSTEM_PATH_DISPLAY_MAX_BYTES,
        )
        self.assertTrue(fallback_display.endswith(fallback_suffix))

        raw_path = b"\xff" * 600
        filesystem_path = os.fsdecode(raw_path)
        self.assertEqual(os.fsencode(filesystem_path), raw_path)
        filesystem_display = module._display_filesystem_path(filesystem_path)
        filesystem_suffix = (
            "⟦truncated;identity=filesystem-bytes;"
            f"bytes={len(raw_path)};"
            f"sha256={hashlib.sha256(raw_path).hexdigest()}⟧"
        )
        self.assertLessEqual(
            len(filesystem_display.encode("utf-8")),
            module.FILESYSTEM_PATH_DISPLAY_MAX_BYTES,
        )
        self.assertTrue(filesystem_display.endswith(filesystem_suffix))

    def test_changed_files_reject_incomplete_nul_framing(self) -> None:
        module = self._load_runner_module()
        malformed_outputs = {
            "missing-terminal-nul": b"?? name",
            "missing-rename-source": b"R  renamed\0",
            "missing-copy-source": b"C  copied\0",
        }

        for case, status_output in malformed_outputs.items():
            with self.subTest(case=case):
                with mock.patch.object(
                    module,
                    "_run_bytes",
                    return_value=status_output,
                ):
                    with self.assertRaisesRegex(
                        module.UserError,
                        "incomplete",
                    ):
                        module._collect_changed_files(self.repo)

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
        self.assertIsNone(payload["preparation_id"])

    def test_prepare_preflights_exact_and_plus_one_terminal_capacity_before_creation(
        self,
    ) -> None:
        module = self._load_runner_module()
        fixed_now = "2026-07-30T07:08:09+00:00"
        run_id = "r" * 200
        args = module._build_parser().parse_args(
            [
                "prepare",
                "--repo",
                str(self.repo),
                "--goal",
                "Preflight the complete initial state",
                "--run-id",
                run_id,
                "--external-helper",
                str(self.fake_helper),
                "--no-fallback-smoke",
            ]
        )
        captured_state: dict[str, object] = {}
        real_serialize = module._serialize_state_for_save

        class PlannedCreation(RuntimeError):
            pass

        def capture_serialize(state, **kwargs):
            content = real_serialize(state, **kwargs)
            captured_state["state"] = copy.deepcopy(state)
            return content

        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "_serialize_state_for_save",
                side_effect=capture_serialize,
            ),
            mock.patch.object(
                module,
                "_create_run_directory",
                side_effect=PlannedCreation,
            ),
            self.assertRaises(PlannedCreation),
        ):
            module._prepare(args)

        state = captured_state["state"]
        self.assertIsInstance(state, dict)
        projected = module._terminal_capacity_projection(
            state,
            transaction_time=fixed_now,
        )
        projected_size = len(
            (json.dumps(projected, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
        shutil.rmtree(self.repo / ".codex-tmp")
        exact_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(module, "STATE_MAX_BYTES", projected_size),
            contextlib.redirect_stdout(exact_stdout),
        ):
            self.assertEqual(module._prepare(args), 0)
        run_dir = module._prospective_run_directory(self.repo.resolve(), run_id)
        self.assertEqual(exact_stdout.getvalue(), f"{run_dir}\n")
        self.assertTrue(run_dir.is_dir())
        self.assertEqual(
            {
                ".state.lock",
                "child-contract.md",
                "child-prompt.md",
                "fallback-smoke.command.txt",
                "fallback-smoke.prompt.md",
                "parent-prompt.md",
                "state.json",
            },
            {path.name for path in run_dir.iterdir() if path.is_file()},
        )

        shutil.rmtree(self.repo / ".codex-tmp")
        rejected_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(module, "STATE_MAX_BYTES", projected_size - 1),
            mock.patch.object(module, "_create_run_directory") as creator,
            contextlib.redirect_stdout(rejected_stdout),
            self.assertRaisesRegex(
                module.UserError,
                "initial state would consume reserved terminal capacity",
            ),
        ):
            module._prepare(args)
        creator.assert_not_called()
        self.assertEqual(rejected_stdout.getvalue(), "")
        self.assertFalse((self.repo / ".codex-tmp").exists())

    def test_prepare_auto_id_capacity_preflight_precedes_unavailable_parent(
        self,
    ) -> None:
        module = self._load_runner_module()
        fixed_now = "2026-07-30T08:09:10+00:00"
        generated_run_id = "a" * 200
        args = module._build_parser().parse_args(
            [
                "prepare",
                "--repo",
                str(self.repo),
                "--goal",
                "Preflight an automatic run id",
                "--external-helper",
                str(self.fake_helper),
                "--no-fallback-smoke",
            ]
        )
        captured_state: dict[str, object] = {}
        real_serialize = module._serialize_state_for_save

        class PlannedCreation(RuntimeError):
            pass

        def capture_serialize(state, **kwargs):
            content = real_serialize(state, **kwargs)
            captured_state["state"] = copy.deepcopy(state)
            return content

        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "_generate_run_id",
                return_value=generated_run_id,
            ),
            mock.patch.object(
                module,
                "_serialize_state_for_save",
                side_effect=capture_serialize,
            ),
            mock.patch.object(
                module,
                "_create_run_directory",
                side_effect=PlannedCreation,
            ),
            self.assertRaises(PlannedCreation),
        ):
            module._prepare(args)
        projected = module._terminal_capacity_projection(
            captured_state["state"],
            transaction_time=fixed_now,
        )
        projected_size = len(
            (json.dumps(projected, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )

        shutil.rmtree(self.repo / ".codex-tmp")
        unavailable_parent = self.repo / ".codex-tmp"
        unavailable_parent.write_text("not a directory\n", encoding="utf-8")
        rejected_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "_generate_run_id",
                return_value=generated_run_id,
            ),
            mock.patch.object(module, "STATE_MAX_BYTES", projected_size - 1),
            mock.patch.object(module, "_create_run_directory") as creator,
            contextlib.redirect_stdout(rejected_stdout),
            self.assertRaisesRegex(
                module.UserError,
                "initial state would consume reserved terminal capacity",
            ),
        ):
            module._prepare(args)
        creator.assert_not_called()
        self.assertEqual(rejected_stdout.getvalue(), "")
        self.assertEqual(
            unavailable_parent.read_text(encoding="utf-8"),
            "not a directory\n",
        )

        exact_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "_generate_run_id",
                return_value=generated_run_id,
            ),
            mock.patch.object(module, "STATE_MAX_BYTES", projected_size),
            contextlib.redirect_stdout(exact_stdout),
            self.assertRaises(module.UserError),
        ):
            module._prepare(args)
        self.assertEqual(exact_stdout.getvalue(), "")
        self.assertTrue(unavailable_parent.is_file())

    def test_prepare_rejects_empty_oversized_and_non_utf8_inputs_before_creation(
        self,
    ) -> None:
        module = self._load_runner_module()
        name_max = os.pathconf(self.repo, "PC_NAME_MAX")
        oversized_run_id = "x" * (name_max + 1)
        cases = (
            ("empty-explicit", "", "goal", None),
            ("oversized-explicit", oversized_run_id, "goal", None),
            ("non-utf8-artifact", "non-utf8", "goal-\ud800", None),
            ("oversized-auto", None, "goal", oversized_run_id),
        )
        for label, run_id, goal, generated in cases:
            with self.subTest(case=label):
                shutil.rmtree(self.repo / ".codex-tmp", ignore_errors=True)
                argv = [
                    "prepare",
                    "--repo",
                    str(self.repo),
                    "--goal",
                    goal,
                    "--external-helper",
                    str(self.fake_helper),
                    "--no-fallback-smoke",
                ]
                if run_id is not None:
                    argv.extend(["--run-id", run_id])
                args = module._build_parser().parse_args(argv)
                patches = (
                    mock.patch.object(
                        module,
                        "_generate_run_id",
                        return_value=generated,
                    )
                    if generated is not None
                    else contextlib.nullcontext()
                )
                stdout = io.StringIO()
                with (
                    patches,
                    mock.patch.object(module, "_create_run_directory") as creator,
                    contextlib.redirect_stdout(stdout),
                    self.assertRaises(module.UserError),
                ):
                    module._prepare(args)
                creator.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                self.assertFalse((self.repo / ".codex-tmp").exists())

    def test_prepare_persists_directory_entries_before_artifact_publication(
        self,
    ) -> None:
        module = self._load_runner_module()
        run_id = "directory-durability-failure"
        args = module._build_parser().parse_args(
            [
                "prepare",
                "--repo",
                str(self.repo),
                "--goal",
                "Persist run directory entries",
                "--run-id",
                run_id,
                "--external-helper",
                str(self.fake_helper),
                "--no-fallback-smoke",
            ]
        )
        real_fsync = module.os.fsync
        fsync_calls = 0
        stdout = io.StringIO()

        def fail_run_entry_fsync(file_descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 3:
                raise OSError("simulated run-entry durability failure")
            real_fsync(file_descriptor)

        with (
            mock.patch.object(module.os, "fsync", side_effect=fail_run_entry_fsync),
            mock.patch.object(module, "_atomic_write_regular") as artifact_writer,
            contextlib.redirect_stdout(stdout),
            self.assertRaisesRegex(
                module.UserError,
                "run directory parents are unsafe or unavailable",
            ),
        ):
            module._prepare(args)

        self.assertEqual(fsync_calls, 3)
        artifact_writer.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(
            (self.repo / ".codex-tmp" / module.RUNS_DIR_NAME / run_id).is_dir()
        )

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

        completed = self._run_refresh_runner(
            "--run-dir",
            str(run_dir),
            "--json",
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
        self.assertEqual(payload["runner_path"], str(SCRIPT_PATH))
        self.assertEqual(payload["compiled_bridge_path"], str(BRIDGE_PATH))
        self.assertEqual(payload["compiled_runner_path"], str(SCRIPT_PATH))
        self.assertEqual(payload["child_prompt"], str(run_dir / "child-prompt.md"))
        self.assertEqual(payload["parent_prompt"], str(run_dir / "parent-prompt.md"))
        self._assert_file_version_payload(payload["bridge_version"], BRIDGE_PATH)
        self._assert_file_version_payload(payload["runner_version"], SCRIPT_PATH)
        self._assert_file_version_payload(
            payload["child_prompt_version"],
            run_dir / "child-prompt.md",
        )
        self._assert_file_version_payload(
            payload["parent_prompt_version"],
            run_dir / "parent-prompt.md",
        )
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

    def test_refresh_prompts_preflights_state_before_prompt_publication(
        self,
    ) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        args = self._direct_refresh_args(module, run_dir)
        fixed_now = "2026-07-30T07:08:09+00:00"
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        for phase in state["phases"].values():
            phase["status"] = "blocked"
            phase["updated_at"] = fixed_now
        orchestration = state["orchestration"]
        orchestration["child_session_id"] = "child-prompt-capacity"
        orchestration["child_status"] = "completed"
        orchestration["child_finished_at"] = fixed_now
        orchestration["updated_at"] = fixed_now
        state["overall_status"] = "blocked"
        state["updated_at"] = ""
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        original_state = state_path.read_bytes()
        sentinel = "prompt must not change before state preflight\n"
        prompt_paths = tuple(
            run_dir / name for name in ("child-prompt.md", "parent-prompt.md")
        )
        for prompt_path in prompt_paths:
            prompt_path.write_text(sentinel, encoding="utf-8")

        candidate = copy.deepcopy(state)
        candidate["artifacts"]["child_prompt"] = str(run_dir / "child-prompt.md")
        candidate["artifacts"]["parent_prompt"] = str(run_dir / "parent-prompt.md")
        candidate["updated_at"] = fixed_now
        candidate_content = (
            json.dumps(candidate, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertLess(len(original_state), len(candidate_content))
        captured_stdout = io.StringIO()

        with (
            mock.patch.object(module, "_require_isolated_python"),
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "STATE_MAX_BYTES",
                len(candidate_content) - 1,
            ),
            mock.patch.object(module.sys, "stdout", captured_stdout),
            self.assertRaisesRegex(
                module.UserError,
                "prompt refresh state exceeds the state byte limit",
            ),
        ):
            module._refresh_prompts(args)

        self.assertEqual(captured_stdout.getvalue(), "")
        self.assertEqual(state_path.read_bytes(), original_state)
        for prompt_path in prompt_paths:
            self.assertEqual(prompt_path.read_text(encoding="utf-8"), sentinel)

        captured_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_require_isolated_python"),
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "STATE_MAX_BYTES",
                len(candidate_content),
            ),
            mock.patch.object(module.sys, "stdout", captured_stdout),
        ):
            self.assertEqual(module._refresh_prompts(args), 0)

        self.assertEqual(state_path.read_bytes(), candidate_content)
        for prompt_path in prompt_paths:
            prompt = prompt_path.read_text(encoding="utf-8")
            self.assertNotEqual(prompt, sentinel)
            self.assertIn(str(SCRIPT_PATH), prompt)
        payload = json.loads(captured_stdout.getvalue())
        self.assertEqual(payload["child_prompt"], str(prompt_paths[0]))
        self.assertEqual(payload["parent_prompt"], str(prompt_paths[1]))

    def test_refresh_prompts_rejects_runner_mismatch_before_writes(self) -> None:
        run_dir = self._prepare("--no-fallback-smoke")
        watched_paths = tuple(
            run_dir / name
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        )
        before = {
            path: (path.stat().st_ino, path.read_bytes()) for path in watched_paths
        }
        completed = self._run_refresh_runner(
            "--run-dir",
            str(run_dir),
            "--json",
            expected_sha256="0" * 64,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "bound compatibility runner source content changed", completed.stderr
        )
        for path, (expected_inode, expected_content) in before.items():
            self.assertEqual(path.stat().st_ino, expected_inode)
            self.assertEqual(path.read_bytes(), expected_content)

    def test_refresh_prompts_rejects_source_path_launch_before_writes(self) -> None:
        run_dir = self._prepare("--no-fallback-smoke")
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
                str(SCRIPT_PATH),
                "refresh-prompts",
                "--run-dir",
                str(run_dir),
                "--compiled-bridge-path",
                str(BRIDGE_PATH),
                "--compiled-runner-path",
                str(SCRIPT_PATH),
                "--published-runner-path",
                str(SCRIPT_PATH),
                *self._bridge_version_args(),
                *self._runner_version_args(),
                "--json",
            ],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "requires anonymous-pipe-bound runner source",
            completed.stderr,
        )
        for path, (expected_inode, expected_content) in before.items():
            self.assertEqual(path.stat().st_ino, expected_inode)
            self.assertEqual(path.read_bytes(), expected_content)

    def test_refresh_prompts_rejects_malformed_runner_frames_before_writes(
        self,
    ) -> None:
        run_dir = self._prepare("--no-fallback-smoke")
        watched_paths = tuple(
            run_dir / name
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        )
        before = {
            path: (path.stat().st_ino, path.read_bytes()) for path in watched_paths
        }
        bridge = self._load_bridge_module()
        runner_source = SCRIPT_PATH.read_bytes()
        valid_frame = b"".join(
            (
                bridge.RUNNER_FRAME_MAGIC,
                len(runner_source).to_bytes(8, "big"),
                hashlib.sha256(runner_source).digest(),
                runner_source,
            )
        )
        oversized = b"".join(
            (
                bridge.RUNNER_FRAME_MAGIC,
                (4 * 1024 * 1024 + 1).to_bytes(8, "big"),
                hashlib.sha256(runner_source).digest(),
            )
        )
        digest_mismatch = bytearray(valid_frame)
        digest_mismatch[16] ^= 0xFF
        command = [
            sys.executable,
            "-I",
            "-B",
            "-S",
            "-c",
            bridge.RUNNER_PIPE_BOOTSTRAP,
            str(SCRIPT_PATH),
            "refresh-prompts",
            "--run-dir",
            str(run_dir),
            "--compiled-bridge-path",
            str(BRIDGE_PATH),
            "--compiled-runner-path",
            str(SCRIPT_PATH),
            "--published-runner-path",
            str(SCRIPT_PATH),
            *self._bridge_version_args(),
            *self._runner_version_args(),
            "--json",
        ]
        variants = {
            "truncated": valid_frame[:-1],
            "oversized": oversized,
            "trailing": valid_frame + b"x",
            "digest-mismatch": bytes(digest_mismatch),
        }
        for name, source_frame in variants.items():
            with self.subTest(frame=name):
                completed = run(command, input_bytes=source_frame)
                self.assertNotEqual(completed.returncode, 0)
                for path, (expected_inode, expected_content) in before.items():
                    self.assertEqual(path.stat().st_ino, expected_inode)
                    self.assertEqual(path.read_bytes(), expected_content)

    def test_refresh_prompts_revalidates_bound_runner_memory_before_writes(
        self,
    ) -> None:
        run_dir = self._prepare("--no-fallback-smoke")
        watched_paths = tuple(
            run_dir / name
            for name in ("state.json", "child-prompt.md", "parent-prompt.md")
        )
        before = {
            path: (path.stat().st_ino, path.read_bytes()) for path in watched_paths
        }
        module = self._load_runner_module()
        bridge_stat = BRIDGE_PATH.stat()
        runner_stat = SCRIPT_PATH.stat()
        runner_source = SCRIPT_PATH.read_bytes()
        module._WAITED_DELIVERY_BOUND_RUNNER_SOURCE = runner_source
        args = argparse.Namespace(
            run_dir=str(run_dir),
            expected_repo_root=None,
            expected_run_dev=None,
            expected_run_ino=None,
            expected_run_uid=None,
            expected_run_gid=None,
            expected_run_mode=None,
            compiled_bridge_path=str(BRIDGE_PATH),
            compiled_runner_path=str(SCRIPT_PATH),
            published_runner_path=str(SCRIPT_PATH),
            expected_bridge_dev=bridge_stat.st_dev,
            expected_bridge_ino=bridge_stat.st_ino,
            expected_bridge_uid=bridge_stat.st_uid,
            expected_bridge_gid=bridge_stat.st_gid,
            expected_bridge_mode=bridge_stat.st_mode & 0o7777,
            expected_bridge_size=bridge_stat.st_size,
            expected_bridge_sha256=hashlib.sha256(BRIDGE_PATH.read_bytes()).hexdigest(),
            expected_runner_dev=runner_stat.st_dev,
            expected_runner_ino=runner_stat.st_ino,
            expected_runner_uid=runner_stat.st_uid,
            expected_runner_gid=runner_stat.st_gid,
            expected_runner_mode=runner_stat.st_mode & 0o7777,
            expected_runner_size=runner_stat.st_size,
            expected_runner_sha256=hashlib.sha256(runner_source).hexdigest(),
            json=True,
        )
        real_sha256 = module.hashlib.sha256
        runner_hashes = 0

        class DriftedDigest:
            def hexdigest(self) -> str:
                return "0" * 64

        def drift_on_final_hash(content=b""):
            nonlocal runner_hashes
            if content is runner_source:
                runner_hashes += 1
                if runner_hashes == 2:
                    return DriftedDigest()
            return real_sha256(content)

        with (
            mock.patch.object(module, "_require_isolated_python"),
            mock.patch.object(
                module.hashlib,
                "sha256",
                side_effect=drift_on_final_hash,
            ),
            self.assertRaisesRegex(
                module.UserError,
                "bound compatibility runner source content changed before writes",
            ),
        ):
            module._refresh_prompts(args)

        self.assertEqual(runner_hashes, 2)
        for path, (expected_inode, expected_content) in before.items():
            self.assertEqual(path.stat().st_ino, expected_inode)
            self.assertEqual(path.read_bytes(), expected_content)

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

                completed = self._run_refresh_runner(
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

        completed = self._run_refresh_runner(
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
            "access-changed": "access changed before update",
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
                    elif mutation == "access-changed":
                        state_path.chmod(0o640)
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

    def test_state_size_boundary_and_crossing_preserve_recoverable_state(
        self,
    ) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        opened_run_dir, repo_root, run_fd = module._open_run_directory(run_dir)
        state_path = run_dir / "state.json"
        fixed_now = "2026-07-30T00:00:00+00:00"
        try:
            state, state_version = module._load_state_from_fd(
                opened_run_dir,
                repo_root,
                run_fd,
            )
            state["orchestration"]["child_session_id"] = "child-size-boundary"
            state["orchestration"]["child_status"] = "completed"
            state["orchestration"]["child_finished_at"] = fixed_now
            state["orchestration"]["updated_at"] = fixed_now
            for phase in state["phases"].values():
                phase["status"] = "blocked"
                phase["updated_at"] = fixed_now
            state["overall_status"] = module._overall_status(state["phases"])
            state["updated_at"] = fixed_now
            exact_content = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )

            with (
                mock.patch.object(module, "_utc_now", return_value=fixed_now),
                mock.patch.object(
                    module,
                    "STATE_MAX_BYTES",
                    len(exact_content),
                ),
            ):
                state_version = module._save_state(
                    opened_run_dir,
                    repo_root,
                    run_fd,
                    state,
                    state_version,
                )

            self.assertEqual(state_path.read_bytes(), exact_content)

            state["known_blockers"].append("cross the state-size boundary")
            oversized_content = (
                json.dumps(state, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            before_failure = state_path.read_bytes()
            entries_before_failure = sorted(path.name for path in run_dir.iterdir())

            with (
                mock.patch.object(module, "_utc_now", return_value=fixed_now),
                mock.patch.object(
                    module,
                    "STATE_MAX_BYTES",
                    len(oversized_content) - 1,
                ),
                mock.patch.object(module.uuid, "uuid4") as uuid_mock,
                mock.patch.object(module.os, "replace") as replace_mock,
            ):
                with self.assertRaisesRegex(
                    module.UserError,
                    rf"{len(oversized_content)} > "
                    rf"{len(oversized_content) - 1} bytes",
                ):
                    module._save_state(
                        opened_run_dir,
                        repo_root,
                        run_fd,
                        state,
                        state_version,
                    )
                uuid_mock.assert_not_called()
                replace_mock.assert_not_called()

            self.assertEqual(state_path.read_bytes(), before_failure)
            self.assertEqual(
                sorted(path.name for path in run_dir.iterdir()),
                entries_before_failure,
            )
            recovered, recovered_version = module._load_state_from_fd(
                opened_run_dir,
                repo_root,
                run_fd,
            )
            self.assertEqual(recovered["known_blockers"], [])
            self.assertEqual(
                recovered_version.sha256,
                hashlib.sha256(before_failure).hexdigest(),
            )
        finally:
            module.os.close(run_fd)

    def test_nonterminal_save_reserves_exact_terminal_capacity(self) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        fixed_now = "2026-07-30T01:02:03+00:00"
        state = self._seed_running_child_with_terminal_phases(
            run_dir,
            "child-reserved-capacity",
            updated_at=fixed_now,
        )
        state_path = run_dir / "state.json"
        original_content = state_path.read_bytes()
        projected = module._terminal_capacity_projection(
            state,
            transaction_time=fixed_now,
        )
        projected_content = (
            json.dumps(projected, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertLess(len(original_content), len(projected_content))

        opened_run_dir, repo_root, run_fd = module._open_run_directory(run_dir)
        try:
            loaded, state_version = module._load_state_from_fd(
                opened_run_dir,
                repo_root,
                run_fd,
            )
            with (
                mock.patch.object(module, "_utc_now", return_value=fixed_now),
                mock.patch.object(
                    module,
                    "STATE_MAX_BYTES",
                    len(projected_content) - 1,
                ),
                mock.patch.object(module.uuid, "uuid4") as uuid_mock,
                mock.patch.object(module.os, "replace") as replace_mock,
            ):
                with self.assertRaisesRegex(
                    module.UserError,
                    "would consume reserved terminal capacity",
                ):
                    module._save_state(
                        opened_run_dir,
                        repo_root,
                        run_fd,
                        loaded,
                        state_version,
                    )
                uuid_mock.assert_not_called()
                replace_mock.assert_not_called()
            self.assertEqual(state_path.read_bytes(), original_content)

            with (
                mock.patch.object(module, "_utc_now", return_value=fixed_now),
                mock.patch.object(
                    module,
                    "STATE_MAX_BYTES",
                    len(projected_content),
                ),
            ):
                module._save_state(
                    opened_run_dir,
                    repo_root,
                    run_fd,
                    loaded,
                    state_version,
                )
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8"))["orchestration"][
                    "child_status"
                ],
                "running",
            )
        finally:
            module.os.close(run_fd)

    def test_finish_child_preflights_terminal_state_and_retries_at_exact_limit(
        self,
    ) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        child_session_id = "child-finish-capacity"
        fixed_now = "2026-07-30T02:03:04+00:00"
        state = self._seed_running_child_with_terminal_phases(
            run_dir,
            child_session_id,
            updated_at=fixed_now,
        )
        state_path = run_dir / "state.json"
        summary_path = run_dir / "summary.md"
        sentinel_summary = "existing summary must survive\n"
        summary_path.write_text(sentinel_summary, encoding="utf-8")
        original_content = state_path.read_bytes()

        candidate = copy.deepcopy(state)
        module._transition_child_terminal(
            candidate,
            child_status="completed",
            child_session_id=child_session_id,
            transaction_time=fixed_now,
        )
        candidate["updated_at"] = fixed_now
        candidate_content = (
            json.dumps(candidate, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertLess(len(original_content), len(candidate_content))
        args = argparse.Namespace(
            run_dir=str(run_dir),
            child_status="completed",
            child_session_id=child_session_id,
        )

        captured_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "STATE_MAX_BYTES",
                len(candidate_content) - 1,
            ),
            contextlib.redirect_stdout(captured_stdout),
        ):
            with self.assertRaisesRegex(
                module.UserError,
                "child terminal transition exceeds the state byte limit",
            ):
                module._finish_child(args)
        self.assertEqual(captured_stdout.getvalue(), "")
        self.assertEqual(state_path.read_bytes(), original_content)
        self.assertEqual(summary_path.read_text(encoding="utf-8"), sentinel_summary)
        recovered = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(recovered["orchestration"]["child_status"], "running")
        self.assertIsNone(recovered["orchestration"]["child_finished_at"])

        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "STATE_MAX_BYTES",
                len(candidate_content),
            ),
        ):
            self.assertEqual(module._finish_child(args), 0)
        self.assertEqual(state_path.read_bytes(), candidate_content)
        self.assertEqual(summary_path.read_text(encoding="utf-8"), sentinel_summary)
        finished = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            finished["orchestration"]["child_finished_at"],
            fixed_now,
        )
        self.assertEqual(finished["orchestration"]["updated_at"], fixed_now)
        self.assertEqual(finished["updated_at"], fixed_now)

    def test_reconcile_preflights_before_summary_and_retries_at_exact_limit(
        self,
    ) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        child_session_id = "child-reconcile-capacity"
        fixed_now = "2026-07-30T03:04:05+00:00"
        state = self._seed_running_child_with_terminal_phases(
            run_dir,
            child_session_id,
            updated_at=fixed_now,
        )
        state_path = run_dir / "state.json"
        summary_path = run_dir / "summary.md"
        sentinel_summary = "preexisting summary must not drift\n"
        summary_path.write_text(sentinel_summary, encoding="utf-8")
        original_content = state_path.read_bytes()

        candidate = copy.deepcopy(state)
        module._transition_child_terminal(
            candidate,
            child_status="completed",
            child_session_id=child_session_id,
            transaction_time=fixed_now,
        )
        expected_summary = module._build_summary(candidate, require_terminal=True)
        candidate["updated_at"] = fixed_now
        candidate_content = (
            json.dumps(candidate, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertLess(len(original_content), len(candidate_content))
        args = argparse.Namespace(
            run_dir=str(run_dir),
            child_status="completed",
            child_session_id=child_session_id,
            json=True,
        )

        captured_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "STATE_MAX_BYTES",
                len(candidate_content) - 1,
            ),
            contextlib.redirect_stdout(captured_stdout),
        ):
            with self.assertRaisesRegex(
                module.UserError,
                "terminal reconciliation exceeds the state byte limit",
            ):
                module._reconcile_parent(args)
        self.assertEqual(captured_stdout.getvalue(), "")
        self.assertEqual(state_path.read_bytes(), original_content)
        self.assertEqual(summary_path.read_text(encoding="utf-8"), sentinel_summary)
        recovered = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(recovered["orchestration"]["child_status"], "running")
        self.assertIsNone(recovered["orchestration"]["child_finished_at"])

        captured_stdout = io.StringIO()
        with (
            mock.patch.object(module, "_utc_now", return_value=fixed_now),
            mock.patch.object(
                module,
                "STATE_MAX_BYTES",
                len(candidate_content),
            ),
            contextlib.redirect_stdout(captured_stdout),
        ):
            self.assertEqual(module._reconcile_parent(args), 0)
        self.assertEqual(state_path.read_bytes(), candidate_content)
        self.assertEqual(summary_path.read_text(encoding="utf-8"), expected_summary)
        payload = json.loads(captured_stdout.getvalue())
        self.assertEqual(payload["overall_status"], "blocked")
        self.assertEqual(payload["child_status"], "completed")
        self.assertEqual(payload["child_session_id"], child_session_id)

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

    def test_atomic_write_binds_published_temp_file_access_policy(self) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare("--no-fallback-smoke")
        opened_run_dir, _repo_root, run_fd = module._open_run_directory(run_dir)
        artifact_name = "child-prompt.md"
        artifact_path = opened_run_dir / artifact_name
        expected_version = module._expected_artifact_version(
            run_fd,
            artifact_name,
            required=True,
        )
        self.assertIsNotNone(expected_version)
        real_regular_file_stat = module._regular_file_stat
        access_changed = False

        def stat_then_change_access(*args, **kwargs):
            nonlocal access_changed
            published_stat = real_regular_file_stat(*args, **kwargs)
            if not access_changed:
                access_changed = True
                artifact_path.chmod(0o640)
            return published_stat

        try:
            with mock.patch.object(
                module,
                "_regular_file_stat",
                side_effect=stat_then_change_access,
            ):
                with self.assertRaisesRegex(
                    module.UserError,
                    "publication identity or content mismatch",
                ):
                    module._atomic_write_regular(
                        run_fd,
                        artifact_name,
                        "intended publication\n",
                        expected_version=expected_version,
                    )
        finally:
            module.os.close(run_fd)

        self.assertTrue(access_changed)
        self.assertEqual(artifact_path.stat().st_mode & 0o7777, 0o640)

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
                bridge_stat = BRIDGE_PATH.stat()
                runner_version = self._runner_version()
                module._WAITED_DELIVERY_BOUND_RUNNER_SOURCE = SCRIPT_PATH.read_bytes()
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
                                compiled_bridge_path=str(BRIDGE_PATH),
                                compiled_runner_path=str(SCRIPT_PATH),
                                published_runner_path=str(SCRIPT_PATH),
                                expected_bridge_dev=bridge_stat.st_dev,
                                expected_bridge_ino=bridge_stat.st_ino,
                                expected_bridge_uid=bridge_stat.st_uid,
                                expected_bridge_gid=bridge_stat.st_gid,
                                expected_bridge_mode=bridge_stat.st_mode & 0o7777,
                                expected_bridge_size=bridge_stat.st_size,
                                expected_bridge_sha256=hashlib.sha256(
                                    BRIDGE_PATH.read_bytes()
                                ).hexdigest(),
                                expected_runner_dev=runner_version["device"],
                                expected_runner_ino=runner_version["inode"],
                                expected_runner_uid=runner_version["uid"],
                                expected_runner_gid=runner_version["gid"],
                                expected_runner_mode=runner_version["mode"],
                                expected_runner_size=runner_version["size"],
                                expected_runner_sha256=runner_version["sha256"],
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

                with (
                    mock.patch.object(module, "_require_isolated_python"),
                    mock.patch.object(
                        module.fcntl,
                        "flock",
                        side_effect=instrumented_flock,
                    ),
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

    def test_fallback_prompt_uses_anonymous_pipe_under_restrictive_umask(
        self,
    ) -> None:
        probe = textwrap.dedent(
            """\
            import fcntl
            import importlib.util
            import os
            import pathlib
            import stat
            import sys

            runner_path = pathlib.Path(sys.argv[1])
            spec = importlib.util.spec_from_file_location(
                "waited_delivery_fallback_snapshot_umask_probe",
                runner_path,
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot load compatibility runner")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            content = b"fallback prompt\\n"
            with module._anonymous_smoke_prompt_pipe() as (
                execution_path,
                read_stream,
                write_stream,
            ):
                read_fd = read_stream.fileno()
                write_fd = write_stream.fileno()
                if not stat.S_ISFIFO(os.fstat(read_fd).st_mode):
                    raise RuntimeError("read descriptor is not an anonymous pipe")
                if not stat.S_ISFIFO(os.fstat(write_fd).st_mode):
                    raise RuntimeError("write descriptor is not an anonymous pipe")
                if (
                    fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_ACCMODE
                ) != os.O_RDONLY:
                    raise RuntimeError("read descriptor access mismatch")
                if (
                    fcntl.fcntl(write_fd, fcntl.F_GETFL) & os.O_ACCMODE
                ) != os.O_WRONLY:
                    raise RuntimeError("write descriptor access mismatch")
                write_stream.write(content)
                write_stream.close()
                replacement_fd = os.open(os.devnull, os.O_RDONLY)
                if replacement_fd != write_fd:
                    raise RuntimeError("closed writer descriptor was not reused")
                if execution_path.read_bytes() != content:
                    raise RuntimeError("pipe content mismatch")
            try:
                os.fstat(replacement_fd)
            finally:
                os.close(replacement_fd)
            """
        )
        completed = run(
            [sys.executable, "-c", probe, str(SCRIPT_PATH)],
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            umask=0o777,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")

    def test_smoke_prompt_pipe_rejection_cleans_process_group(self) -> None:
        module = self._load_runner_module()
        helper = self.root / "reject-smoke-prompt.py"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import subprocess
                import sys
                import time

                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    stdin=subprocess.DEVNULL,
                )
                print(os.getpgrp(), flush=True)
                os.close(int(sys.argv[1]))
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )

        with module._anonymous_smoke_prompt_pipe() as (
            _execution_path,
            read_stream,
            write_stream,
        ):
            read_fd = read_stream.fileno()
            completed = module._run_bounded_smoke_process(
                [sys.executable, str(helper), str(read_fd)],
                cwd=self.repo,
                child_read_streams=(read_stream,),
                input_stream=write_stream,
                input_bytes=b"x" * module.STATE_MAX_BYTES,
                timeout=5,
                cleanup_timeout=3,
            )

        self.assertTrue(read_stream.closed)
        self.assertTrue(write_stream.closed)
        self.assertEqual(completed.returncode, 126, completed.stderr)
        self.assertIn(
            "rejected its prompt stream before complete delivery",
            completed.stderr,
        )
        process_group = int(completed.stdout.strip().splitlines()[0])
        self.assertFalse(module._process_group_exists(process_group))

    def test_smoke_small_prompt_reader_rejection_fails_closed(self) -> None:
        module = self._load_runner_module()
        helper = self.root / "ignore-small-smoke-prompt.py"
        process_group_path = self.root / "ignore-small-smoke-prompt-pgid.txt"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import subprocess
                import sys
                import time

                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    stdin=subprocess.DEVNULL,
                )
                prompt_path = pathlib.Path(sys.argv[1])
                os.close(int(prompt_path.name))
                pathlib.Path(sys.argv[2]).write_text(
                    str(os.getpgrp()),
                    encoding="utf-8",
                )
                print("READY", flush=True)
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )
        prompt = module.FALLBACK_SMOKE_PROMPT.encode("utf-8")
        self.assertLess(len(prompt), 4096)
        real_popen = module.subprocess.Popen

        def wait_for_reader_close(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    if process_group_path.read_text(encoding="utf-8").strip():
                        return process
                except FileNotFoundError:
                    pass
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            process.kill()
            process.communicate(timeout=5)
            self.fail("smoke helper did not close its prompt reader")

        with module._anonymous_smoke_prompt_pipe() as (
            execution_path,
            read_stream,
            write_stream,
        ):
            with mock.patch.object(
                module.subprocess,
                "Popen",
                side_effect=wait_for_reader_close,
            ):
                completed = module._run_bounded_smoke_process(
                    [
                        sys.executable,
                        str(helper),
                        str(execution_path),
                        str(process_group_path),
                    ],
                    cwd=self.repo,
                    child_read_streams=(read_stream,),
                    input_stream=write_stream,
                    input_bytes=prompt,
                    timeout=5,
                    cleanup_timeout=3,
                )

        self.assertTrue(read_stream.closed)
        self.assertTrue(write_stream.closed)
        self.assertEqual(completed.returncode, 126, completed.stderr)
        self.assertIn("READY", completed.stdout)
        self.assertIn(
            "rejected its prompt stream before complete delivery",
            completed.stderr,
        )
        status, sample = module._classify_smoke(
            completed.stdout,
            completed.stderr,
            completed.returncode,
        )
        self.assertEqual(status, "blocked")
        self.assertNotEqual(sample, "READY")
        process_group = int(process_group_path.read_text(encoding="utf-8"))
        self.assertFalse(module._process_group_exists(process_group))

    def test_run_fallback_smoke_binds_prompt_pipe_under_lock(self) -> None:
        module = self._load_runner_module()
        run_dir = self._prepare()
        prompt_path = run_dir / module.FALLBACK_SMOKE_PROMPT_NAME
        original_prompt = prompt_path.read_bytes()
        malicious_prompt = self.root / "malicious-smoke-prompt.md"
        malicious_prompt.write_text("__FORCE_BLOCK__\n", encoding="utf-8")
        real_acquired_run_lock = module._acquired_run_lock
        real_read_regular_artifact = module._read_regular_artifact
        lock_depth = 0
        lock_acquisitions = 0
        prompt_read_under_lock = False
        captured_pipe_fds: list[int] = []

        @contextlib.contextmanager
        def tracked_acquired_run_lock(*args, **kwargs):
            nonlocal lock_acquisitions, lock_depth
            with real_acquired_run_lock(*args, **kwargs):
                lock_acquisitions += 1
                if lock_acquisitions == 2:
                    self.assertEqual(len(captured_pipe_fds), 2)
                    for file_fd in captured_pipe_fds:
                        with self.assertRaises(OSError):
                            os.fstat(file_fd)
                lock_depth += 1
                try:
                    yield
                finally:
                    lock_depth -= 1

        def tracked_read_regular_artifact(*args, **kwargs):
            nonlocal prompt_read_under_lock
            artifact = real_read_regular_artifact(*args, **kwargs)
            if args[1] == module.FALLBACK_SMOKE_PROMPT_NAME:
                self.assertGreater(lock_depth, 0)
                prompt_read_under_lock = True
            return artifact

        def replacing_smoke(
            command: list[str],
            *,
            cwd: pathlib.Path,
            child_read_streams: tuple,
            input_stream,
            input_bytes: bytes,
        ) -> subprocess.CompletedProcess[str]:
            self.assertEqual(cwd, self.repo.resolve())
            self.assertEqual(len(child_read_streams), 1)
            read_fd = child_read_streams[0].fileno()
            input_fd = input_stream.fileno()
            captured_pipe_fds.extend((read_fd, input_fd))
            prompt_index = command.index("--prompt-file") + 1
            pipe_path = pathlib.Path(command[prompt_index])
            self.assertNotEqual(pipe_path, prompt_path)
            prompt_path.unlink()
            prompt_path.symlink_to(malicious_prompt)
            self.assertEqual(input_bytes, original_prompt)
            input_stream.write(input_bytes)
            input_stream.close()
            self.assertEqual(pipe_path.read_bytes(), original_prompt)
            self.assertEqual(
                fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_ACCMODE,
                os.O_RDONLY,
            )
            self.assertTrue(stat.S_ISFIFO(os.fstat(read_fd).st_mode))
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="READY\n",
                stderr="",
            )

        with (
            mock.patch.object(
                module,
                "_acquired_run_lock",
                side_effect=tracked_acquired_run_lock,
            ),
            mock.patch.object(
                module,
                "_read_regular_artifact",
                side_effect=tracked_read_regular_artifact,
            ),
            mock.patch.object(
                module,
                "_run_bounded_smoke_process",
                side_effect=replacing_smoke,
            ),
        ):
            result = module._run_fallback_smoke(
                argparse.Namespace(run_dir=str(run_dir))
            )

        self.assertEqual(result, 0)
        self.assertTrue(prompt_read_under_lock)
        self.assertEqual(lock_acquisitions, 2)
        self.assertEqual(len(captured_pipe_fds), 2)
        for file_fd in captured_pipe_fds:
            with self.assertRaises(OSError):
                os.fstat(file_fd)
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["fallback_readiness_smoke"]["status"], "passed")
        self.assertEqual(state["fallback_readiness_smoke"]["sample"], "READY")

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
            child_read_streams: tuple,
            input_stream,
            input_bytes: bytes,
        ) -> subprocess.CompletedProcess[str]:
            self.assertTrue(command)
            self.assertEqual(cwd, self.repo.resolve())
            self.assertEqual(len(child_read_streams), 1)
            read_fd = child_read_streams[0].fileno()
            self.assertGreater(len(input_bytes), 0)
            input_fd = input_stream.fileno()
            self.assertNotEqual(input_fd, read_fd)
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

    def test_zombie_only_group_remains_addressable_for_cleanup(self) -> None:
        module = self._load_runner_module()
        proc_root = self.root / "proc"
        process_dir = proc_root / "201"
        process_dir.mkdir(parents=True)
        (process_dir / "stat").write_bytes(b"201 (fixture) Z 1 77 1 0\n")

        with mock.patch.object(module.os, "killpg", return_value=None) as killpg:
            self.assertFalse(
                module._process_group_exists(
                    77,
                    proc_root=proc_root,
                    platform="linux",
                )
            )
            self.assertTrue(module._process_group_is_addressable(77))

        self.assertEqual(killpg.call_args_list, [mock.call(77, 0), mock.call(77, 0)])

    def test_linux_process_group_scan_handles_non_utf8_same_and_unrelated_members(
        self,
    ) -> None:
        module = self._load_runner_module()
        proc_root = self.root / "proc-non-utf8"
        same_zombie = proc_root / "201"
        unrelated_live = proc_root / "202"
        same_zombie.mkdir(parents=True)
        unrelated_live.mkdir(parents=True)
        (same_zombie / "stat").write_bytes(b"201 (same \xff zombie) Z 1 77 1 0\n")
        (unrelated_live / "stat").write_bytes(b"202 (unrelated \xfe live) S 1 88 1 0\n")

        self.assertEqual(
            module._linux_process_group_state(77, proc_root=proc_root),
            "zombie-only",
        )
        with mock.patch.object(module.os, "killpg", return_value=None):
            self.assertFalse(
                module._process_group_exists(
                    77,
                    proc_root=proc_root,
                    platform="linux",
                )
            )

        same_live = proc_root / "203"
        same_live.mkdir()
        (same_live / "stat").write_bytes(b"203 (same \xfd live) S 1 77 1 0\n")
        self.assertEqual(
            module._linux_process_group_state(77, proc_root=proc_root),
            "live",
        )

    def test_linux_process_group_no_members_rechecks_addressability(self) -> None:
        module = self._load_runner_module()
        proc_root = self.root / "proc-no-members"
        unrelated_live = proc_root / "204"
        unrelated_live.mkdir(parents=True)
        (unrelated_live / "stat").write_bytes(b"204 (unrelated \xff live) S 1 88 1 0\n")

        self.assertEqual(
            module._linux_process_group_state(77, proc_root=proc_root),
            "no-members",
        )
        with mock.patch.object(
            module.os,
            "killpg",
            side_effect=[None, ProcessLookupError()],
        ) as killpg:
            self.assertFalse(
                module._process_group_exists(
                    77,
                    proc_root=proc_root,
                    platform="linux",
                )
            )
        self.assertEqual(killpg.call_args_list, [mock.call(77, 0), mock.call(77, 0)])

        with mock.patch.object(module.os, "killpg", return_value=None) as killpg:
            self.assertTrue(
                module._process_group_exists(
                    77,
                    proc_root=proc_root,
                    platform="linux",
                )
            )
        self.assertEqual(killpg.call_args_list, [mock.call(77, 0), mock.call(77, 0)])

    def test_linux_process_group_scan_ambiguity_fails_closed(self) -> None:
        module = self._load_runner_module()
        proc_root = self.root / "proc-ambiguous"
        process_dir = proc_root / "301"
        process_dir.mkdir(parents=True)
        stat_path = process_dir / "stat"
        stat_path.write_bytes(b"301 (fixture) Z 1 91 1 0\n")

        self.assertEqual(
            module._linux_process_group_state(
                91,
                proc_root=proc_root,
                deadline=time.monotonic() - 1,
            ),
            "unknown",
        )

        stat_path.write_bytes(b"ambiguous\n")
        self.assertEqual(
            module._linux_process_group_state(91, proc_root=proc_root),
            "unknown",
        )

        stat_path.unlink()
        stat_path.mkdir()
        self.assertEqual(
            module._linux_process_group_state(91, proc_root=proc_root),
            "unknown",
        )
        stat_path.rmdir()
        stat_path.write_bytes(b"301 (fixture) \xff 1 91 1 0\n")
        with mock.patch.object(module.os, "killpg", return_value=None):
            self.assertTrue(
                module._process_group_exists(
                    91,
                    proc_root=proc_root,
                    platform="linux",
                )
            )

    def test_linux_process_group_scan_iteration_error_fails_closed(self) -> None:
        module = self._load_runner_module()

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
            self.assertEqual(module._linux_process_group_state(101), "unknown")
            with mock.patch.object(module.os, "killpg", return_value=None):
                self.assertTrue(
                    module._process_group_exists(
                        101,
                        platform="linux",
                    )
                )

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

    def test_bounded_smoke_selector_failure_precedes_process_launch(self) -> None:
        module = self._load_runner_module()
        launch_marker = self.root / "selector-failure-launched.txt"
        helper = self.root / "selector-failure-smoke.py"
        helper.write_text(
            textwrap.dedent(
                """\
                import pathlib
                import sys

                pathlib.Path(sys.argv[1]).write_text("launched", encoding="utf-8")
                """
            ),
            encoding="utf-8",
        )

        with mock.patch.object(
            module.selectors,
            "DefaultSelector",
            side_effect=OSError("selector unavailable"),
        ):
            with mock.patch.object(
                module.subprocess,
                "Popen",
                wraps=module.subprocess.Popen,
            ) as popen:
                with self.assertRaisesRegex(
                    module.UserError,
                    "cannot initialize fallback readiness smoke selector",
                ):
                    module._run_bounded_smoke_process(
                        [sys.executable, str(helper), str(launch_marker)],
                        cwd=self.repo,
                    )

        popen.assert_not_called()
        self.assertFalse(launch_marker.exists())

    def test_smoke_nonzero_status_overrides_ready_output(self) -> None:
        module = self._load_runner_module()
        for returncode in (1, 7, 124, 125, 126, -signal.SIGKILL):
            for stdout, stderr in (
                ("READY\n", ""),
                ("", "READY\n"),
                ("READY\n", "READY\n"),
            ):
                with self.subTest(
                    returncode=returncode,
                    ready_streams=(bool(stdout), bool(stderr)),
                ):
                    status, sample = module._classify_smoke(
                        stdout,
                        stderr,
                        returncode,
                    )
                    self.assertEqual(status, "blocked")
                    self.assertIsNotNone(sample)
                    assert sample is not None
                    self.assertTrue(sample.startswith("BLOCKED:"))
                    self.assertNotEqual(sample, "READY")

    def test_ready_output_does_not_override_bounded_process_failures(self) -> None:
        module = self._load_runner_module()
        helper = self.root / "ready-then-failure.py"
        process_group_path = self.root / "ready-then-failure-pgid.txt"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import subprocess
                import sys
                import time

                mode = sys.argv[1]
                pathlib.Path(sys.argv[2]).write_text(
                    str(os.getpgrp()),
                    encoding="utf-8",
                )
                print("READY", flush=True)
                time.sleep(0.1)
                if mode == "output":
                    sys.stdout.write("x" * (1024 * 1024))
                    sys.stdout.flush()
                    time.sleep(60)
                elif mode == "residual":
                    subprocess.Popen(
                        [sys.executable, "-c", "import time; time.sleep(60)"]
                    )
                else:
                    time.sleep(60)
                """
            ),
            encoding="utf-8",
        )
        scenarios = {
            "timeout": {
                "returncode": 124,
                "timeout": 0.4,
                "max_capture_bytes": 4096,
            },
            "output": {
                "returncode": 125,
                "timeout": 5,
                "max_capture_bytes": 1024,
            },
            "residual": {
                "returncode": 126,
                "timeout": 5,
                "max_capture_bytes": 4096,
            },
        }

        for mode, expected in scenarios.items():
            with self.subTest(mode=mode):
                process_group_path.unlink(missing_ok=True)
                completed = module._run_bounded_smoke_process(
                    [
                        sys.executable,
                        str(helper),
                        mode,
                        str(process_group_path),
                    ],
                    cwd=self.repo,
                    timeout=expected["timeout"],
                    cleanup_timeout=3,
                    max_capture_bytes=expected["max_capture_bytes"],
                )
                self.assertEqual(
                    completed.returncode,
                    expected["returncode"],
                    completed.stderr,
                )
                self.assertIn("READY", completed.stdout)
                status, sample = module._classify_smoke(
                    completed.stdout,
                    completed.stderr,
                    completed.returncode,
                )
                self.assertEqual(status, "blocked")
                self.assertNotEqual(sample, "READY")
                process_group = int(process_group_path.read_text(encoding="utf-8"))
                self.assertFalse(module._process_group_exists(process_group))

    def test_smoke_defers_terminal_signals_until_process_group_cleanup(
        self,
    ) -> None:
        module = self._load_runner_module()
        helper = self.root / "signal-resistant-smoke.py"
        harness = self.root / "smoke-signal-harness.py"
        process_group_path = self.root / "signal-resistant-smoke-pgid.txt"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import signal
                import subprocess
                import sys
                import time

                for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT):
                    signal.signal(signum, signal.SIG_IGN)
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import signal,time;"
                            "signal.signal(signal.SIGHUP,signal.SIG_IGN);"
                            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                            "signal.signal(signal.SIGQUIT,signal.SIG_IGN);"
                            "time.sleep(60)"
                        ),
                    ]
                )
                pathlib.Path(sys.argv[1]).write_text(
                    str(os.getpgrp()),
                    encoding="utf-8",
                )
                print("READY", flush=True)
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )
        harness.write_text(
            textwrap.dedent(
                f"""\
                import importlib.util
                import pathlib
                import sys

                spec = importlib.util.spec_from_file_location(
                    "waited_delivery_runner_signal_harness",
                    {str(SCRIPT_PATH)!r},
                )
                if spec is None or spec.loader is None:
                    raise RuntimeError("cannot load waited-delivery runner")
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                module._run_bounded_smoke_process(
                    [
                        sys.executable,
                        {str(helper)!r},
                        sys.argv[1],
                    ],
                    cwd=pathlib.Path({str(self.repo)!r}),
                    timeout=60,
                    cleanup_timeout=3,
                )
                """
            ),
            encoding="utf-8",
        )

        for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT):
            with self.subTest(signum=signal.Signals(signum).name):
                process_group_path.unlink(missing_ok=True)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(harness),
                        str(process_group_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                process_group: int | None = None
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if process_group_path.is_file():
                            process_group = int(
                                process_group_path.read_text(encoding="utf-8")
                            )
                            break
                        if process.poll() is not None:
                            break
                        time.sleep(0.02)
                    self.assertIsNotNone(
                        process_group,
                        "smoke helper did not publish its process group",
                    )
                    os.kill(process.pid, signum)
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertEqual(
                        process.returncode,
                        -signum,
                        f"stdout={stdout!r}\nstderr={stderr!r}",
                    )
                    assert process_group is not None
                    self.assertFalse(
                        module._process_group_exists(process_group),
                        f"process group {process_group} survived "
                        f"{signal.Signals(signum).name}",
                    )
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)
                    if process_group is not None and module._process_group_exists(
                        process_group
                    ):
                        os.killpg(process_group, signal.SIGKILL)

    def test_smoke_redelivers_to_returning_handler_after_group_cleanup(
        self,
    ) -> None:
        module = self._load_runner_module()
        helper = self.root / "custom-handler-signal-resistant-smoke.py"
        harness = self.root / "custom-handler-smoke-signal-harness.py"
        process_group_path = self.root / "custom-handler-smoke-pgid.txt"
        handler_result_path = self.root / "custom-handler-result.txt"
        completed_result_path = self.root / "custom-handler-completed.txt"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                import pathlib
                import signal
                import subprocess
                import sys
                import time

                for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT):
                    signal.signal(signum, signal.SIG_IGN)
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import signal,time;"
                            "signal.signal(signal.SIGHUP,signal.SIG_IGN);"
                            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                            "signal.signal(signal.SIGQUIT,signal.SIG_IGN);"
                            "time.sleep(60)"
                        ),
                    ]
                )
                pathlib.Path(sys.argv[1]).write_text(
                    str(os.getpgrp()),
                    encoding="utf-8",
                )
                print("READY", flush=True)
                time.sleep(60)
                """
            ),
            encoding="utf-8",
        )
        harness.write_text(
            textwrap.dedent(
                f"""\
                import importlib.util
                import os
                import pathlib
                import signal
                import sys

                process_group_path = pathlib.Path(sys.argv[1])
                handler_result_path = pathlib.Path(sys.argv[2])
                completed_result_path = pathlib.Path(sys.argv[3])

                def returning_handler(signum, _frame):
                    process_group = int(
                        process_group_path.read_text(encoding="utf-8")
                    )
                    try:
                        os.killpg(process_group, 0)
                    except ProcessLookupError:
                        group_state = "gone"
                    except PermissionError:
                        group_state = "live"
                    else:
                        group_state = "live"
                    handler_result_path.write_text(
                        f"{{signum}}:{{group_state}}",
                        encoding="utf-8",
                    )

                for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT):
                    signal.signal(signum, returning_handler)

                spec = importlib.util.spec_from_file_location(
                    "waited_delivery_runner_custom_signal_harness",
                    {str(SCRIPT_PATH)!r},
                )
                if spec is None or spec.loader is None:
                    raise RuntimeError("cannot load waited-delivery runner")
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                completed = module._run_bounded_smoke_process(
                    [
                        sys.executable,
                        {str(helper)!r},
                        str(process_group_path),
                    ],
                    cwd=pathlib.Path({str(self.repo)!r}),
                    timeout=60,
                    cleanup_timeout=3,
                )
                completed_result_path.write_text(
                    str(completed.returncode),
                    encoding="utf-8",
                )
                """
            ),
            encoding="utf-8",
        )

        for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT):
            with self.subTest(signum=signal.Signals(signum).name):
                process_group_path.unlink(missing_ok=True)
                handler_result_path.unlink(missing_ok=True)
                completed_result_path.unlink(missing_ok=True)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(harness),
                        str(process_group_path),
                        str(handler_result_path),
                        str(completed_result_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                process_group: int | None = None
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if process_group_path.is_file():
                            process_group = int(
                                process_group_path.read_text(encoding="utf-8")
                            )
                            break
                        if process.poll() is not None:
                            break
                        time.sleep(0.02)
                    self.assertIsNotNone(
                        process_group,
                        "smoke helper did not publish its process group",
                    )
                    os.kill(process.pid, signum)
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertEqual(
                        process.returncode,
                        0,
                        f"stdout={stdout!r}\nstderr={stderr!r}",
                    )
                    self.assertEqual(
                        handler_result_path.read_text(encoding="utf-8"),
                        f"{signum}:gone",
                    )
                    self.assertEqual(
                        completed_result_path.read_text(encoding="utf-8"),
                        str(128 + signum),
                    )
                    assert process_group is not None
                    self.assertFalse(module._process_group_exists(process_group))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)
                    if process_group is not None and module._process_group_exists(
                        process_group
                    ):
                        os.killpg(process_group, signal.SIGKILL)

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
