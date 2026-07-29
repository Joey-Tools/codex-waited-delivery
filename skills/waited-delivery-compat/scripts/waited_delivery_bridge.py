#!/usr/bin/env python3

"""Compatibility bridge for historical waited-delivery runs."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import NamedTuple, cast


PARENT_SESSION_ENV = "WAITED_DELIVERY_PARENT_SESSION_ID"
PARENT_TURN_ENV = "WAITED_DELIVERY_PARENT_TURN_ID"
TRANSCRIPT_PATH_ENV = "WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH"
PERMISSION_MODE_ENV = "WAITED_DELIVERY_PERMISSION_MODE"
RUNNER_PATH = pathlib.Path(__file__).resolve().with_name("waited_delivery_runner.py")
STATE_MAX_BYTES = 4 * 1024 * 1024
PROMPT_REFRESH_SCHEMA_VERSION = 2


class UserError(RuntimeError):
    pass


class FileVersion(NamedTuple):
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    sha256: str


class ArtifactRead(NamedTuple):
    content: bytes
    version: FileVersion


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _read_inherited_regular_artifact(
    file_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> ArtifactRead:
    def read_bounded() -> bytes:
        chunks: list[bytes] = []
        offset = 0
        while True:
            chunk = os.pread(
                file_fd,
                min(65536, max_bytes + 1 - offset),
                offset,
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            if offset > max_bytes:
                raise UserError(
                    f"descriptor-bound compatibility artifact exceeds byte "
                    f"limit: {name}"
                )
        return b"".join(chunks)

    try:
        access_mode = fcntl.fcntl(file_fd, fcntl.F_GETFL) & os.O_ACCMODE
        if access_mode != os.O_RDONLY:
            raise UserError(
                f"descriptor-bound compatibility artifact must be opened "
                f"read-only: {name}"
            )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise UserError(
                f"descriptor-bound compatibility artifact must be a regular "
                f"file: {name}"
            )
        if before.st_size > max_bytes:
            raise UserError(
                f"descriptor-bound compatibility artifact exceeds byte limit: {name}"
            )
        expected_access = (
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
        first_content = read_bounded()
        middle = os.fstat(file_fd)
        second_content = read_bounded()
        after = os.fstat(file_fd)
        stable_stats = (before, middle, after)
        if (
            any(not stat.S_ISREG(value.st_mode) for value in stable_stats)
            or any(not _same_object(before, value) for value in stable_stats[1:])
            or any(value.st_size != before.st_size for value in stable_stats[1:])
            or any(
                (
                    value.st_uid,
                    value.st_gid,
                    stat.S_IMODE(value.st_mode),
                )
                != expected_access
                for value in stable_stats[1:]
            )
            or len(first_content) != before.st_size
            or len(second_content) != before.st_size
            or first_content != second_content
        ):
            raise UserError(
                f"descriptor-bound compatibility artifact identity, access, size, "
                f"or content changed while read: {name}"
            )
        return ArtifactRead(
            content=second_content,
            version=FileVersion(
                device=after.st_dev,
                inode=after.st_ino,
                uid=after.st_uid,
                gid=after.st_gid,
                mode=stat.S_IMODE(after.st_mode),
                size=after.st_size,
                sha256=hashlib.sha256(second_content).hexdigest(),
            ),
        )
    except UserError:
        raise
    except OSError as error:
        raise UserError(
            f"cannot read descriptor-bound compatibility artifact: {name}"
        ) from error


def _fd_execution_path(file_fd: int, name: str) -> pathlib.Path:
    try:
        descriptor_stat = os.fstat(file_fd)
    except OSError as error:
        raise UserError(
            f"cannot inspect descriptor-bound compatibility artifact: {name}"
        ) from error
    for root in (pathlib.Path("/dev/fd"), pathlib.Path("/proc/self/fd")):
        candidate = root / str(file_fd)
        probe_fd: int | None = None
        try:
            probe_fd = os.open(
                candidate,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            candidate_stat = os.fstat(probe_fd)
        except OSError:
            continue
        finally:
            if probe_fd is not None:
                os.close(probe_fd)
        if _same_object(descriptor_stat, candidate_stat):
            return candidate
    raise UserError(f"cannot expose descriptor-bound compatibility artifact: {name}")


def _expected_file_version(
    args: argparse.Namespace,
    prefix: str,
) -> FileVersion:
    values = tuple(
        getattr(args, f"expected_{prefix}_{field}")
        for field in ("dev", "ino", "uid", "gid", "mode", "size", "sha256")
    )
    integer_values = values[:-1]
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in integer_values
    ):
        raise UserError(
            f"expected {prefix} identity fields must be supplied as nonnegative "
            f"integers"
        )
    sha256 = values[-1]
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise UserError(f"expected {prefix} sha256 must be lowercase hexadecimal")
    return FileVersion(
        device=cast(int, integer_values[0]),
        inode=cast(int, integer_values[1]),
        uid=cast(int, integer_values[2]),
        gid=cast(int, integer_values[3]),
        mode=cast(int, integer_values[4]),
        size=cast(int, integer_values[5]),
        sha256=sha256,
    )


def _validate_file_version(
    actual: FileVersion,
    expected: FileVersion,
    *,
    label: str,
) -> None:
    if (actual.device, actual.inode) != (expected.device, expected.inode):
        raise UserError(f"{label} was replaced")
    if (actual.uid, actual.gid, actual.mode) != (
        expected.uid,
        expected.gid,
        expected.mode,
    ):
        raise UserError(f"{label} access policy changed")
    if actual.size != expected.size or actual.sha256 != expected.sha256:
        raise UserError(f"{label} content changed")


def _file_version_from_payload(
    payload: dict[str, object],
    field: str,
) -> FileVersion:
    raw_version = payload.get(field)
    if not isinstance(raw_version, dict):
        raise UserError(f"runner did not return {field}")
    version = cast(dict[str, object], raw_version)
    integer_values = tuple(
        version.get(name) for name in ("device", "inode", "uid", "gid", "mode", "size")
    )
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in integer_values
    ):
        raise UserError(f"runner returned an invalid {field} identity")
    sha256 = version.get("sha256")
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise UserError(f"runner returned an invalid {field} digest")
    return FileVersion(
        device=cast(int, integer_values[0]),
        inode=cast(int, integer_values[1]),
        uid=cast(int, integer_values[2]),
        gid=cast(int, integer_values[3]),
        mode=cast(int, integer_values[4]),
        size=cast(int, integer_values[5]),
        sha256=sha256,
    )


def _validate_loaded_from_descriptor(
    file_fd: int,
    name: str,
) -> pathlib.Path:
    execution_path = _fd_execution_path(file_fd, name)
    loaded_path = pathlib.Path(os.path.abspath(__file__))
    if loaded_path != execution_path:
        raise UserError(
            "compatibility bridge must be launched through its inherited "
            "descriptor path"
        )
    loaded_fd: int | None = None
    try:
        loaded_fd = os.open(
            loaded_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        loaded_stat = os.fstat(loaded_fd)
        descriptor_stat = os.fstat(file_fd)
    except OSError as error:
        raise UserError(
            "cannot bind loaded compatibility bridge to inherited descriptor"
        ) from error
    finally:
        if loaded_fd is not None:
            os.close(loaded_fd)
    if not _same_object(loaded_stat, descriptor_stat):
        raise UserError(
            "loaded compatibility bridge does not match inherited descriptor"
        )
    return execution_path


def _runner_command(*args: str) -> list[str]:
    return [sys.executable, str(RUNNER_PATH), *args]


def _run_runner(*args: str) -> int:
    completed = subprocess.run(
        _runner_command(*args),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.returncode != 0:
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="")
        return completed.returncode
    return 0


def _isolated_python_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PYTHON") and name != "__PYVENV_LAUNCHER__"
    }


def _require_isolated_python() -> None:
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise UserError("refresh-prompts-live requires Python -I -B -S isolation")


def _run_descriptor_runner_json(
    bridge_fd: int,
    runner_fd: int,
    *args: str,
) -> dict[str, object]:
    execution_path = _fd_execution_path(
        runner_fd,
        "waited_delivery_runner.py",
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            str(execution_path),
            *args,
        ],
        text=True,
        capture_output=True,
        check=False,
        pass_fds=(bridge_fd, runner_fd),
        env=_isolated_python_environment(),
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise UserError(stderr)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise UserError(f"runner did not return valid JSON: {error}") from error
    if not isinstance(payload, dict):
        raise UserError("runner JSON output must be an object")
    return cast(dict[str, object], payload)


def _resolved_parent_ids(
    args: argparse.Namespace,
) -> tuple[str | None, str | None, str | None, str | None]:
    parent_session_id = args.parent_session_id or os.environ.get(PARENT_SESSION_ENV)
    parent_turn_id = args.parent_turn_id or os.environ.get(PARENT_TURN_ENV)
    parent_transcript_path = args.parent_transcript_path or os.environ.get(
        TRANSCRIPT_PATH_ENV
    )
    permission_mode = args.permission_mode or os.environ.get(PERMISSION_MODE_ENV)
    return (
        parent_session_id,
        parent_turn_id,
        parent_transcript_path,
        permission_mode,
    )


def _prepare_live(args: argparse.Namespace) -> int:
    (
        parent_session_id,
        parent_turn_id,
        parent_transcript_path,
        permission_mode,
    ) = _resolved_parent_ids(args)
    runner_args = [
        "prepare",
        "--repo",
        args.repo,
        "--goal",
        args.goal,
        "--json",
    ]
    if args.run_id:
        runner_args.extend(["--run-id", args.run_id])
    for phase in args.phase:
        runner_args.extend(["--phase", phase])
    for changed_file in args.changed_file:
        runner_args.extend(["--changed-file", changed_file])
    for blocker in args.known_blocker:
        runner_args.extend(["--known-blocker", blocker])
    runner_args.extend(["--external-lane", args.external_lane])
    runner_args.extend(["--fallback-lane", args.fallback_lane])
    runner_args.extend(["--fallback-entrypoint", args.fallback_entrypoint])
    runner_args.extend(["--external-helper", args.external_helper])
    if args.no_fallback_smoke:
        runner_args.append("--no-fallback-smoke")
    if parent_session_id:
        runner_args.extend(["--parent-session-id", parent_session_id])
    if parent_turn_id:
        runner_args.extend(["--parent-turn-id", parent_turn_id])
    if parent_transcript_path:
        runner_args.extend(["--parent-transcript-path", parent_transcript_path])
    if permission_mode:
        runner_args.extend(["--permission-mode", permission_mode])
    return _run_runner(*runner_args)


def _bind_parent_live(args: argparse.Namespace) -> int:
    (
        parent_session_id,
        parent_turn_id,
        parent_transcript_path,
        permission_mode,
    ) = _resolved_parent_ids(args)
    if (
        not parent_session_id
        and not parent_turn_id
        and not parent_transcript_path
        and not permission_mode
    ):
        raise UserError(
            "bind-parent-live requires parent metadata via args or env contract"
        )
    runner_args = ["bind-parent", "--run-dir", args.run_dir]
    if parent_session_id:
        runner_args.extend(["--parent-session-id", parent_session_id])
    if parent_turn_id:
        runner_args.extend(["--parent-turn-id", parent_turn_id])
    if parent_transcript_path:
        runner_args.extend(["--parent-transcript-path", parent_transcript_path])
    if permission_mode:
        runner_args.extend(["--permission-mode", permission_mode])
    return _run_runner(*runner_args)


def _attach_child_live(args: argparse.Namespace) -> int:
    (
        parent_session_id,
        parent_turn_id,
        parent_transcript_path,
        permission_mode,
    ) = _resolved_parent_ids(args)
    runner_args = [
        "attach-child",
        "--run-dir",
        args.run_dir,
        "--child-session-id",
        args.child_session_id,
    ]
    if parent_session_id:
        runner_args.extend(["--parent-session-id", parent_session_id])
    if parent_turn_id:
        runner_args.extend(["--parent-turn-id", parent_turn_id])
    if parent_transcript_path:
        runner_args.extend(["--parent-transcript-path", parent_transcript_path])
    if permission_mode:
        runner_args.extend(["--permission-mode", permission_mode])
    return _run_runner(*runner_args)


def _refresh_prompts_live(args: argparse.Namespace) -> int:
    _require_isolated_python()
    expected_identity_args = (
        ("--expected-run-dev", args.expected_run_dev),
        ("--expected-run-ino", args.expected_run_ino),
        ("--expected-run-uid", args.expected_run_uid),
        ("--expected-run-gid", args.expected_run_gid),
        ("--expected-run-mode", args.expected_run_mode),
    )
    if any(value is not None for _name, value in expected_identity_args) and not all(
        value is not None for _name, value in expected_identity_args
    ):
        raise UserError(
            "expected run device, inode, uid, gid, and mode must be supplied together"
        )
    expected_bridge = _expected_file_version(args, "bridge")
    expected_runner = _expected_file_version(args, "runner")
    bridge_execution_path = _validate_loaded_from_descriptor(
        args.executed_bridge_fd,
        "waited_delivery_bridge.py",
    )
    bridge_artifact = _read_inherited_regular_artifact(
        args.executed_bridge_fd,
        "waited_delivery_bridge.py",
        max_bytes=STATE_MAX_BYTES,
    )
    _validate_file_version(
        bridge_artifact.version,
        expected_bridge,
        label="descriptor-bound compatibility bridge",
    )
    runner_execution_path = _fd_execution_path(
        args.executed_runner_fd,
        "waited_delivery_runner.py",
    )
    runner_artifact = _read_inherited_regular_artifact(
        args.executed_runner_fd,
        "waited_delivery_runner.py",
        max_bytes=STATE_MAX_BYTES,
    )
    _validate_file_version(
        runner_artifact.version,
        expected_runner,
        label="descriptor-bound compatibility runner",
    )
    published_runner_path = pathlib.Path(args.published_runner_path)
    if (
        not published_runner_path.is_absolute()
        or not published_runner_path.name
        or pathlib.PurePath(published_runner_path.name).name
        != published_runner_path.name
    ):
        raise UserError("published runner path must be an absolute file path")
    runner_args = [
        "refresh-prompts",
        "--run-dir",
        args.run_dir,
        "--json",
        "--executed-bridge-fd",
        str(args.executed_bridge_fd),
        "--executed-runner-fd",
        str(args.executed_runner_fd),
        "--published-runner-path",
        str(published_runner_path),
    ]
    if args.expected_repo_root:
        runner_args.extend(["--expected-repo-root", args.expected_repo_root])
    for name, value in expected_identity_args:
        if value is not None:
            runner_args.extend([name, str(value)])
    runner_args.extend(
        [
            "--expected-bridge-dev",
            str(expected_bridge.device),
            "--expected-bridge-ino",
            str(expected_bridge.inode),
            "--expected-bridge-uid",
            str(expected_bridge.uid),
            "--expected-bridge-gid",
            str(expected_bridge.gid),
            "--expected-bridge-mode",
            str(expected_bridge.mode),
            "--expected-bridge-size",
            str(expected_bridge.size),
            "--expected-bridge-sha256",
            expected_bridge.sha256,
            "--expected-runner-dev",
            str(expected_runner.device),
            "--expected-runner-ino",
            str(expected_runner.inode),
            "--expected-runner-uid",
            str(expected_runner.uid),
            "--expected-runner-gid",
            str(expected_runner.gid),
            "--expected-runner-mode",
            str(expected_runner.mode),
            "--expected-runner-size",
            str(expected_runner.size),
            "--expected-runner-sha256",
            expected_runner.sha256,
        ]
    )
    payload = _run_descriptor_runner_json(
        args.executed_bridge_fd,
        args.executed_runner_fd,
        *runner_args,
    )
    if payload.get("refresh_schema_version") != PROMPT_REFRESH_SCHEMA_VERSION:
        raise UserError("runner returned an unsupported refresh schema")
    if payload.get("python_isolated") is not True:
        raise UserError("runner did not attest isolated Python execution")
    if payload.get("bridge_fd_access") != "read-only":
        raise UserError("runner did not attest read-only bridge descriptor access")
    if payload.get("runner_fd_access") != "read-only":
        raise UserError("runner did not attest read-only runner descriptor access")
    if payload.get("executed_bridge_path") != str(bridge_execution_path):
        raise UserError(
            "runner receipt does not identify the descriptor-bound bridge path"
        )
    if payload.get("executed_runner_path") != str(runner_execution_path):
        raise UserError(
            "runner receipt does not identify the descriptor-bound execution path"
        )
    returned_bridge = _file_version_from_payload(payload, "bridge_version")
    _validate_file_version(
        returned_bridge,
        expected_bridge,
        label="bridge receipt",
    )
    returned_runner = _file_version_from_payload(payload, "runner_version")
    _validate_file_version(
        returned_runner,
        expected_runner,
        label="runner receipt",
    )
    print(json.dumps(payload))
    return 0


def _finish_child_live(args: argparse.Namespace) -> int:
    runner_args = [
        "finish-child",
        "--run-dir",
        args.run_dir,
        "--child-status",
        args.child_status,
        "--child-session-id",
        args.child_session_id,
    ]
    return _run_runner(*runner_args)


def _reconcile_live(args: argparse.Namespace) -> int:
    runner_args = [
        "reconcile-parent",
        "--run-dir",
        args.run_dir,
        "--child-status",
        args.child_status,
        "--child-session-id",
        args.child_session_id,
        "--json",
    ]
    return _run_runner(*runner_args)


def _print_env_contract(_: argparse.Namespace) -> int:
    print(
        "\n".join(
            [
                f"{PARENT_SESSION_ENV}=<parent-session-id>",
                f"{PARENT_TURN_ENV}=<parent-turn-id>",
                f"{TRANSCRIPT_PATH_ENV}=<parent-transcript-path>",
                f"{PERMISSION_MODE_ENV}=<permission-mode>",
            ]
        )
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bridge waited-delivery runner commands for hooks/supervisors.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_live = subparsers.add_parser("prepare-live")
    prepare_live.add_argument("--repo", required=True)
    prepare_live.add_argument("--goal", required=True)
    prepare_live.add_argument("--run-id")
    prepare_live.add_argument("--parent-session-id")
    prepare_live.add_argument("--parent-turn-id")
    prepare_live.add_argument("--parent-transcript-path")
    prepare_live.add_argument("--permission-mode")
    prepare_live.add_argument("--phase", action="append", default=[])
    prepare_live.add_argument("--changed-file", action="append", default=[])
    prepare_live.add_argument("--known-blocker", action="append", default=[])
    prepare_live.add_argument("--external-lane", default="bounded-semantic")
    prepare_live.add_argument("--fallback-lane", default="baseline")
    prepare_live.add_argument("--fallback-entrypoint", default="gh-copilot")
    prepare_live.add_argument(
        "--external-helper",
        default=str(
            pathlib.Path(__file__).resolve().parents[2]
            / "review-orchestration-playbook"
            / "scripts"
            / "isolated_review"
        ),
    )
    prepare_live.add_argument("--no-fallback-smoke", action="store_true")
    prepare_live.set_defaults(func=_prepare_live)

    bind_parent_live = subparsers.add_parser("bind-parent-live")
    bind_parent_live.add_argument("--run-dir", required=True)
    bind_parent_live.add_argument("--parent-session-id")
    bind_parent_live.add_argument("--parent-turn-id")
    bind_parent_live.add_argument("--parent-transcript-path")
    bind_parent_live.add_argument("--permission-mode")
    bind_parent_live.set_defaults(func=_bind_parent_live)

    attach_child_live = subparsers.add_parser("attach-child-live")
    attach_child_live.add_argument("--run-dir", required=True)
    attach_child_live.add_argument("--child-session-id", required=True)
    attach_child_live.add_argument("--parent-session-id")
    attach_child_live.add_argument("--parent-turn-id")
    attach_child_live.add_argument("--parent-transcript-path")
    attach_child_live.add_argument("--permission-mode")
    attach_child_live.set_defaults(func=_attach_child_live)

    refresh_prompts_live = subparsers.add_parser("refresh-prompts-live")
    refresh_prompts_live.add_argument("--run-dir", required=True)
    refresh_prompts_live.add_argument("--expected-repo-root")
    refresh_prompts_live.add_argument(
        "--executed-bridge-fd",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--executed-runner-fd",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--published-runner-path",
        required=True,
    )
    refresh_prompts_live.add_argument("--expected-run-dev", type=int)
    refresh_prompts_live.add_argument("--expected-run-ino", type=int)
    refresh_prompts_live.add_argument("--expected-run-uid", type=int)
    refresh_prompts_live.add_argument("--expected-run-gid", type=int)
    refresh_prompts_live.add_argument("--expected-run-mode", type=int)
    refresh_prompts_live.add_argument(
        "--expected-bridge-dev",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-bridge-ino",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-bridge-uid",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-bridge-gid",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-bridge-mode",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-bridge-size",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument("--expected-bridge-sha256", required=True)
    refresh_prompts_live.add_argument(
        "--expected-runner-dev",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-runner-ino",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-runner-uid",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-runner-gid",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-runner-mode",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument(
        "--expected-runner-size",
        type=int,
        required=True,
    )
    refresh_prompts_live.add_argument("--expected-runner-sha256", required=True)
    refresh_prompts_live.set_defaults(func=_refresh_prompts_live)

    finish_child_live = subparsers.add_parser("finish-child-live")
    finish_child_live.add_argument("--run-dir", required=True)
    finish_child_live.add_argument("--child-status", required=True)
    finish_child_live.add_argument("--child-session-id", required=True)
    finish_child_live.set_defaults(func=_finish_child_live)

    reconcile_live = subparsers.add_parser("reconcile-live")
    reconcile_live.add_argument("--run-dir", required=True)
    reconcile_live.add_argument("--child-status", required=True)
    reconcile_live.add_argument("--child-session-id", required=True)
    reconcile_live.set_defaults(func=_reconcile_live)

    env_contract = subparsers.add_parser("print-env-contract")
    env_contract.set_defaults(func=_print_env_contract)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except UserError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
