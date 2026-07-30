#!/usr/bin/env python3

"""Compatibility bridge for historical waited-delivery runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import NamedTuple, cast


PARENT_SESSION_ENV = "WAITED_DELIVERY_PARENT_SESSION_ID"
PARENT_TURN_ENV = "WAITED_DELIVERY_PARENT_TURN_ID"
TRANSCRIPT_PATH_ENV = "WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH"
PERMISSION_MODE_ENV = "WAITED_DELIVERY_PERMISSION_MODE"
RUNNER_PATH = pathlib.Path(__file__).resolve().with_name("waited_delivery_runner.py")
STATE_MAX_BYTES = 4 * 1024 * 1024
PROMPT_REFRESH_SCHEMA_VERSION = 3
RUNNER_FRAME_MAGIC = b"WDLRUN01"
RUNNER_PIPE_BOOTSTRAP = """\
import hashlib
import sys

MAX_SOURCE_BYTES = 4 * 1024 * 1024

def read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            raise SystemExit("truncated waited-delivery runner frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

stream = sys.stdin.buffer
if read_exact(stream, 8) != b"WDLRUN01":
    raise SystemExit("invalid waited-delivery runner frame")
runner_size = int.from_bytes(read_exact(stream, 8), "big")
runner_sha256 = read_exact(stream, 32).hex()
if runner_size <= 0 or runner_size > MAX_SOURCE_BYTES:
    raise SystemExit("waited-delivery runner frame size is outside the bound")
runner_source = read_exact(stream, runner_size)
if stream.read(1):
    raise SystemExit("waited-delivery runner frame has trailing bytes")
if hashlib.sha256(runner_source).hexdigest() != runner_sha256:
    raise SystemExit("waited-delivery runner source digest mismatch")
runner_path = sys.argv[1]
runner_args = sys.argv[2:]
sys.argv[:] = [runner_path, *runner_args]
runner_globals = {
    "__name__": "__main__",
    "__file__": runner_path,
    "__package__": None,
    "__cached__": None,
    "_WAITED_DELIVERY_BOUND_RUNNER_SOURCE": runner_source,
}
exec(compile(runner_source, runner_path, "exec"), runner_globals)
"""


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


def _runner_source_frame(source: bytes) -> bytes:
    if not source or len(source) > STATE_MAX_BYTES:
        raise UserError("bound compatibility runner is outside the byte bound")
    return b"".join(
        (
            RUNNER_FRAME_MAGIC,
            len(source).to_bytes(8, "big"),
            hashlib.sha256(source).digest(),
            source,
        )
    )


def _run_in_memory_runner_json(
    runner_source: bytes,
    runner_path: pathlib.Path,
    *args: str,
) -> dict[str, object]:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            "-c",
            RUNNER_PIPE_BOOTSTRAP,
            str(runner_path),
            *args,
        ],
        input=_runner_source_frame(runner_source),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=_isolated_python_environment(),
    )
    if completed.returncode != 0:
        stderr = (
            completed.stderr.decode("utf-8", errors="replace").strip()
            or completed.stdout.decode("utf-8", errors="replace").strip()
            or "unknown error"
        )
        raise UserError(stderr)
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
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
    bridge_source = globals().get("_WAITED_DELIVERY_BOUND_BRIDGE_SOURCE")
    runner_source = globals().get("_WAITED_DELIVERY_BOUND_RUNNER_SOURCE")
    runner_source_path = globals().get("_WAITED_DELIVERY_BOUND_RUNNER_PATH")
    if not isinstance(bridge_source, bytes) or not isinstance(runner_source, bytes):
        raise UserError(
            "refresh-prompts-live requires anonymous-pipe-bound source bytes"
        )
    if (
        len(bridge_source) != expected_bridge.size
        or hashlib.sha256(bridge_source).hexdigest() != expected_bridge.sha256
    ):
        raise UserError("bound compatibility bridge source content changed")
    if (
        len(runner_source) != expected_runner.size
        or hashlib.sha256(runner_source).hexdigest() != expected_runner.sha256
    ):
        raise UserError("bound compatibility runner source content changed")
    published_bridge_path = pathlib.Path(args.published_bridge_path)
    published_runner_path = pathlib.Path(args.published_runner_path)
    for label, published_path in (
        ("bridge", published_bridge_path),
        ("runner", published_runner_path),
    ):
        if (
            not published_path.is_absolute()
            or not published_path.name
            or pathlib.PurePath(published_path.name).name != published_path.name
        ):
            raise UserError(f"published {label} path must be an absolute file path")
    if pathlib.Path(os.path.abspath(__file__)) != published_bridge_path:
        raise UserError(
            "compatibility bridge compile filename does not match its published path"
        )
    if (
        not isinstance(runner_source_path, str)
        or pathlib.Path(runner_source_path) != published_runner_path
    ):
        raise UserError(
            "bound compatibility runner compile filename does not match its "
            "published path"
        )
    runner_args = [
        "refresh-prompts",
        "--run-dir",
        args.run_dir,
        "--json",
        "--compiled-bridge-path",
        str(published_bridge_path),
        "--compiled-runner-path",
        str(published_runner_path),
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
    payload = _run_in_memory_runner_json(
        runner_source,
        published_runner_path,
        *runner_args,
    )
    if payload.get("refresh_schema_version") != PROMPT_REFRESH_SCHEMA_VERSION:
        raise UserError("runner returned an unsupported refresh schema")
    if payload.get("python_isolated") is not True:
        raise UserError("runner did not attest isolated Python execution")
    for field in ("bridge_source_transport", "runner_source_transport"):
        if payload.get(field) != "anonymous-pipe-memory":
            raise UserError(
                f"runner did not attest anonymous in-memory source transport: {field}"
            )
    for field in ("bridge_source_reopenable", "runner_source_reopenable"):
        if payload.get(field) is not False:
            raise UserError(f"runner did not attest non-reopenable source: {field}")
    if payload.get("compiled_bridge_path") != str(published_bridge_path):
        raise UserError("runner receipt does not identify the bridge compile filename")
    if payload.get("compiled_runner_path") != str(published_runner_path):
        raise UserError("runner receipt does not identify the runner compile filename")
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
        "--published-bridge-path",
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
