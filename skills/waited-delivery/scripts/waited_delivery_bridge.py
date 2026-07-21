#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys


PARENT_SESSION_ENV = "WAITED_DELIVERY_PARENT_SESSION_ID"
PARENT_TURN_ENV = "WAITED_DELIVERY_PARENT_TURN_ID"
TRANSCRIPT_PATH_ENV = "WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH"
PERMISSION_MODE_ENV = "WAITED_DELIVERY_PERMISSION_MODE"
RUNNER_PATH = pathlib.Path(__file__).resolve().with_name("waited_delivery_runner.py")


class UserError(RuntimeError):
    pass


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
