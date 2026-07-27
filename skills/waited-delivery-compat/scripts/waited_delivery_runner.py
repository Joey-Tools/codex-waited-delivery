#!/usr/bin/env python3

"""Compatibility runner for historical waited-delivery state."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import shlex
import subprocess
import sys
import uuid
from typing import TypedDict, cast


TERMINAL_PHASE_STATUSES = {
    "passed",
    "failed",
    "blocked",
    "unavailable",
    "decision_point",
}
PHASE_STATUSES = TERMINAL_PHASE_STATUSES | {"pending", "running"}
CHILD_TERMINAL_STATUSES = {"completed", "failed", "interrupted"}
CHILD_STATUSES = CHILD_TERMINAL_STATUSES | {"pending", "running"}
DEFAULT_PHASES = [
    "tests",
    "docs_sync",
    "internal_review",
    "external_review",
]
REVIEW_PHASES = {"internal_review", "external_review"}
DEFAULT_EXTERNAL_HELPER = (
    pathlib.Path(__file__).resolve().parents[2]
    / "review-orchestration-playbook"
    / "scripts"
    / "isolated_review"
)
FALLBACK_SMOKE_PROMPT = """You are running a fallback-lane readiness smoke.

Rules:
- Do not perform a full code review.
- Do not inspect extra files unless the runtime requires it to answer.
- Reply with exactly one line.

Output contract:
- If the lane is usable and can answer, reply exactly: READY
- If the lane is blocked or unavailable, reply with a single short line starting with: BLOCKED:
"""


class UserError(RuntimeError):
    pass


class PhaseState(TypedDict):
    status: str
    summary: str
    findings: list[str]
    evidence: list[str]
    updated_at: str | None


class ReviewPolicy(TypedDict):
    external_lane: str
    fallback_lane: str
    fallback_entrypoint: str
    external_helper: str


class FallbackReadinessSmoke(TypedDict):
    enabled: bool
    status: str
    lane: str
    entrypoint: str
    prompt_file: str
    command: list[str]
    sample: str | None
    stdout: str
    stderr: str
    returncode: int | None
    updated_at: str | None


class Artifacts(TypedDict):
    state_json: str
    child_contract: str
    child_prompt: str
    parent_prompt: str
    fallback_smoke_prompt: str
    fallback_smoke_command: str


class OrchestrationState(TypedDict):
    parent_session_id: str | None
    parent_turn_id: str | None
    parent_transcript_path: str | None
    permission_mode: str | None
    child_session_id: str | None
    child_status: str
    child_started_at: str | None
    child_finished_at: str | None
    updated_at: str | None


class WaitedDeliveryState(TypedDict):
    schema_version: int
    run_id: str
    repo_root: str
    goal: str
    created_at: str
    updated_at: str
    known_blockers: list[str]
    changed_files: list[str]
    phases_order: list[str]
    phases: dict[str, PhaseState]
    review_policy: ReviewPolicy
    fallback_readiness_smoke: FallbackReadinessSmoke
    orchestration: OrchestrationState
    artifacts: Artifacts
    overall_status: str


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _run_json(cmd: list[str], *, cwd: pathlib.Path | None = None) -> str:
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or "unknown error"
        raise UserError(f"command failed: {' '.join(cmd)}\n{stderr}")
    return completed.stdout


def _resolve_repo_root(repo_arg: str) -> pathlib.Path:
    repo_path = pathlib.Path(repo_arg).resolve()
    stdout = _run_json(
        ["git", "-C", str(repo_path), "rev-parse", "--show-toplevel"],
    )
    return pathlib.Path(stdout.strip()).resolve()


def _parse_status_path(raw_path: str) -> str:
    if " -> " in raw_path:
        return raw_path.split(" -> ", 1)[1]
    return raw_path


def _collect_changed_files(repo_root: pathlib.Path) -> list[str]:
    stdout = _run_json(
        [
            "git",
            "-C",
            str(repo_root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ]
    )
    changed: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        if len(line) < 4:
            continue
        path = _parse_status_path(line[3:])
        if path == ".codex-tmp" or path.startswith(".codex-tmp/"):
            continue
        if path not in seen:
            changed.append(path)
            seen.add(path)
    return changed


def _ensure_relative_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        candidate = pathlib.Path(path)
        if candidate.is_absolute():
            raise UserError(f"changed-file must be repo-relative: {path}")
        result.append(candidate.as_posix())
    return result


def _write_json(path: pathlib.Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _load_json(path: pathlib.Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _phase_template() -> PhaseState:
    return {
        "status": "pending",
        "summary": "",
        "findings": [],
        "evidence": [],
        "updated_at": None,
    }


def _orchestration_template(
    *,
    parent_session_id: str | None = None,
    parent_turn_id: str | None = None,
    parent_transcript_path: str | None = None,
    permission_mode: str | None = None,
) -> OrchestrationState:
    return {
        "parent_session_id": parent_session_id,
        "parent_turn_id": parent_turn_id,
        "parent_transcript_path": parent_transcript_path,
        "permission_mode": permission_mode,
        "child_session_id": None,
        "child_status": "pending",
        "child_started_at": None,
        "child_finished_at": None,
        "updated_at": None,
    }


def _build_child_contract(state: WaitedDeliveryState) -> str:
    review_policy = state["review_policy"]
    fallback = state["fallback_readiness_smoke"]
    lines = [
        "# Waited Delivery Child Contract",
        "",
        f"- Run ID: `{state['run_id']}`",
        f"- Repo: `{state['repo_root']}`",
        f"- Goal: {state['goal']}",
        "",
        "## Required Phases",
    ]
    for phase in state["phases_order"]:
        lines.append(f"- `{phase}`")

    lines.extend(
        [
            "",
            "## Review Policy",
            "- Implementation boundary: the main session completes implementation before spawning the child.",
            "- Child review boundary: the child owns tests, docs sync, and verification of the already-implemented change; it must not mark `internal_review` or `external_review` as passed.",
            "- Parent review boundary: after the child returns, the parent must form an authorized, committed, clean/frozen `base_sha..head_sha` before starting review.",
            "- Dirty or untracked implementation state cannot count as reviewed.",
            "- Runner enforcement: `record-phase` rejects a review `passed` result before the child is terminal, while implementation state is dirty/untracked, or when nonblank terminal review evidence is missing.",
            "- Named internal single review: the parent directly launches exactly one fresh/clear-context Codex `reviewer` agent.",
            "- Reviewer context: load `$review-orchestration-playbook` plus applicable `AGENTS.md` and repository guidance.",
            "- Reviewer workspace: discover the fixed diff and necessary nearby context with tools inside the clean/frozen workspace.",
            "- Reviewer handoff: do not precompute or paste the full diff into the prompt.",
            "- Helper role: `isolated_review` is low-level compatibility/diagnostic tooling only; it cannot start, satisfy, substitute for, or count as the named internal single review.",
            f"- Primary external-review lane: `{review_policy['external_lane']}`",
            f"- Fallback lane: `{review_policy['fallback_lane']}`",
            f"- Fallback entrypoint: `{review_policy['fallback_entrypoint']}`",
            f"- Fallback readiness smoke enabled: `{str(fallback['enabled']).lower()}`",
        ]
    )

    blockers = state["known_blockers"]
    if blockers:
        lines.extend(["", "## Known Blockers"])
        for blocker in blockers:
            lines.append(f"- {blocker}")

    changed_files = state["changed_files"]
    if changed_files:
        lines.extend(["", "## Changed Files"])
        for path in changed_files:
            lines.append(f"- `{path}`")

    lines.extend(
        [
            "",
            "## Guardrails",
            "- Spawn no additional delivery children for this run.",
            "- Treat fallback readiness smoke as lane-availability evidence only, not as external-review coverage.",
            "- Keep external fallback-readiness smoke separate from the named internal single review; it never adds or replaces an internal reviewer.",
            "- Convert any reviewer stall into a terminal result such as `blocked`, `unavailable`, or `decision_point` after bounded retries.",
            "- Return control as soon as a gate reaches the earliest decisive stopping point.",
        ]
    )

    return "\n".join(lines) + "\n"


def _shell_command(args: list[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in args)


def _runner_command(*args: str) -> str:
    return _shell_command(
        [sys.executable, str(pathlib.Path(__file__).resolve()), *args]
    )


def _smoke_command_argv(state: WaitedDeliveryState) -> list[str]:
    smoke = state["fallback_readiness_smoke"]
    helper = pathlib.Path(state["review_policy"]["external_helper"])
    return [
        str(helper),
        "--repo",
        state["repo_root"],
        "--lane",
        smoke["lane"],
        "--entrypoint",
        smoke["entrypoint"],
        "--prompt-file",
        smoke["prompt_file"],
        "--",
        "{prompt_text}",
    ]


def _build_child_prompt(run_dir: pathlib.Path, state: WaitedDeliveryState) -> str:
    smoke = state["fallback_readiness_smoke"]
    lines = [
        "# Waited Delivery Child Prompt",
        "",
        f"- Run directory: `{run_dir}`",
        f"- Contract: `{state['artifacts']['child_contract']}`",
        f"- State file: `{state['artifacts']['state_json']}`",
        "",
        "Use the runner as the delivery control plane for this run.",
        "",
        "Required sequence:",
        f"1. Read `{state['artifacts']['child_contract']}` before doing finish-line work.",
    ]
    if smoke["enabled"]:
        lines.append(
            "2. If an early fallback-lane readiness probe is useful, run this narrow smoke first:"
        )
        lines.append(
            f"   `{_runner_command('run-fallback-smoke', '--run-dir', str(run_dir))}`"
        )
    else:
        lines.append("2. Fallback readiness smoke is disabled for this run.")
    lines.extend(
        [
            "3. For each child-owned delivery phase, mark it `running` before work begins:",
            f"   `{_runner_command('begin-phase', '--run-dir', str(run_dir), '--phase', '<phase>')}`",
            "4. As soon as a phase reaches a terminal result, persist it with `record-phase`:",
            f"   `{_runner_command('record-phase', '--run-dir', str(run_dir), '--phase', '<phase>', '--status', 'passed', '--summary', '<summary>')}`",
            "5. Do not mark `internal_review` or `external_review` as passed. The parent owns review after you return.",
            "6. If you stop early after a decisive failure or decision point, close untouched downstream phases before returning:",
            f"   `{_runner_command('close-open-phases', '--run-dir', str(run_dir), '--status', 'blocked', '--summary', '<why downstream phases were not run>')}`",
            "7. Do not call `finalize` from the child. The parent owns review and reconciliation after `wait` returns.",
            "8. Return a concise terminal summary for the parent that matches the persisted child-owned phase states.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_parent_prompt(run_dir: pathlib.Path, state: WaitedDeliveryState) -> str:
    lines = [
        "# Waited Delivery Parent Prompt",
        "",
        "You are the main session for a waited-delivery run.",
        "",
        "Required sequence:",
        f"1. Spawn exactly one delivery child for this run and give it `{state['artifacts']['child_prompt']}` as the bounded handoff payload.",
        f"2. As soon as the child session ID is known, persist it with: `{_runner_command('attach-child', '--run-dir', str(run_dir), '--child-session-id', '<child_session_id>')}`",
        "3. Immediately wait for that child. Do not summarize early and do not continue unrelated work while the child is active.",
        "4. When `wait` returns, inspect the child result and persist its terminal status before starting review:",
        f"   `{_runner_command('finish-child', '--run-dir', str(run_dir), '--child-status', '<completed|failed|interrupted>', '--child-session-id', '<child_session_id>')}`",
        "5. Do not claim review coverage while implementation changes remain dirty or untracked. When authorized, form a committed clean/frozen `base_sha..head_sha`; otherwise record `blocked` or `decision_point`.",
        "6. Named internal single review means directly launching exactly one fresh/clear-context Codex `reviewer` agent. Require it to load `$review-orchestration-playbook` plus applicable `AGENTS.md` and repository guidance.",
        "7. Give the reviewer only the goal, workspace path, immutable refs, focus, evidence budget, and output contract. Do not precompute or paste a full diff; the reviewer discovers the fixed diff and nearby context with tools inside the clean/frozen workspace.",
        "8. `isolated_review` is low-level compatibility/diagnostic tooling only. It cannot start, satisfy, substitute for, or count as the named internal single review; its lifecycle does not add a reviewer.",
        "9. Persist the named Codex artifact only as `internal_review`. Run `external_review` separately only when required, and never reuse the internal artifact for it. A fallback-readiness smoke is availability evidence only and never review coverage.",
        f"10. Reconcile the run with: `{_runner_command('reconcile-parent', '--run-dir', str(run_dir), '--child-status', '<completed|failed|interrupted>', '--child-session-id', '<child_session_id>')}`",
        "11. Read the resulting `summary.md` and only then give the user the consolidated finish-line result.",
        "",
        "Guardrails:",
        "- Do not spawn additional delivery children for this run.",
        "- Do not call `finalize` directly from the parent when `reconcile-parent` is available.",
        "- If the user explicitly interrupts or materially redirects the run, record that through the terminal child status instead of pretending the old run completed cleanly.",
    ]
    return "\n".join(lines) + "\n"


def _non_terminal_phase_names(state: WaitedDeliveryState) -> list[str]:
    return [
        phase_name
        for phase_name in state["phases_order"]
        if state["phases"][phase_name]["status"] not in TERMINAL_PHASE_STATUSES
    ]


def _prepare(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo)
    changed_files = (
        _ensure_relative_paths(args.changed_file)
        if args.changed_file
        else _collect_changed_files(repo_root)
    )
    run_id = (
        args.run_id
        or f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    )
    phases_order = args.phase or list(DEFAULT_PHASES)
    if "internal_review" not in phases_order:
        raise UserError("phase order must include the required internal_review phase")
    run_dir = repo_root / ".codex-tmp" / "waited-delivery" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    state_path = run_dir / "state.json"
    contract_path = run_dir / "child-contract.md"
    child_prompt_path = run_dir / "child-prompt.md"
    parent_prompt_path = run_dir / "parent-prompt.md"
    smoke_prompt_path = run_dir / "fallback-smoke.prompt.md"
    smoke_command_path = run_dir / "fallback-smoke.command.txt"

    smoke_prompt_path.write_text(FALLBACK_SMOKE_PROMPT, encoding="utf-8")

    state: WaitedDeliveryState = {
        "schema_version": 3,
        "run_id": run_id,
        "repo_root": str(repo_root),
        "goal": args.goal,
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "known_blockers": list(args.known_blocker),
        "changed_files": changed_files,
        "phases_order": phases_order,
        "phases": {phase: _phase_template() for phase in phases_order},
        "review_policy": {
            "external_lane": args.external_lane,
            "fallback_lane": args.fallback_lane,
            "fallback_entrypoint": args.fallback_entrypoint,
            "external_helper": str(pathlib.Path(args.external_helper).resolve()),
        },
        "fallback_readiness_smoke": {
            "enabled": not args.no_fallback_smoke,
            "status": "pending",
            "lane": args.fallback_lane,
            "entrypoint": args.fallback_entrypoint,
            "prompt_file": str(smoke_prompt_path),
            "command": [],
            "sample": None,
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "updated_at": None,
        },
        "orchestration": _orchestration_template(
            parent_session_id=args.parent_session_id,
            parent_turn_id=args.parent_turn_id,
            parent_transcript_path=args.parent_transcript_path,
            permission_mode=args.permission_mode,
        ),
        "artifacts": {
            "state_json": str(state_path),
            "child_contract": str(contract_path),
            "child_prompt": str(child_prompt_path),
            "parent_prompt": str(parent_prompt_path),
            "fallback_smoke_prompt": str(smoke_prompt_path),
            "fallback_smoke_command": str(smoke_command_path),
        },
        "overall_status": "pending",
    }
    state["fallback_readiness_smoke"]["command"] = _smoke_command_argv(state)
    contract_path.write_text(_build_child_contract(state), encoding="utf-8")
    child_prompt_path.write_text(_build_child_prompt(run_dir, state), encoding="utf-8")
    parent_prompt_path.write_text(
        _build_parent_prompt(run_dir, state), encoding="utf-8"
    )
    smoke_command_path.write_text(
        _shell_command(state["fallback_readiness_smoke"]["command"]) + "\n",
        encoding="utf-8",
    )
    _write_json(state_path, state)

    if args.json:
        print(
            json.dumps(
                {
                    "run_dir": str(run_dir),
                    "state_json": state["artifacts"]["state_json"],
                    "child_contract": state["artifacts"]["child_contract"],
                    "child_prompt": state["artifacts"]["child_prompt"],
                    "parent_prompt": state["artifacts"]["parent_prompt"],
                    "fallback_smoke_prompt": state["artifacts"][
                        "fallback_smoke_prompt"
                    ],
                    "fallback_smoke_command": state["artifacts"][
                        "fallback_smoke_command"
                    ],
                }
            )
        )
    else:
        print(run_dir)
    return 0


def _load_state_from_run_dir(
    run_dir_arg: str,
) -> tuple[pathlib.Path, WaitedDeliveryState]:
    run_dir = pathlib.Path(run_dir_arg).resolve()
    state_path = run_dir / "state.json"
    if not state_path.is_file():
        raise UserError(f"state file not found: {state_path}")
    payload = _load_json(state_path)
    if not isinstance(payload, dict):
        raise UserError(f"invalid state payload: {state_path}")
    state = cast(WaitedDeliveryState, payload)
    orchestration = state["orchestration"]
    orchestration.setdefault("parent_session_id", None)
    orchestration.setdefault("parent_turn_id", None)
    orchestration.setdefault("parent_transcript_path", None)
    orchestration.setdefault("permission_mode", None)
    return run_dir, state


def _save_state(run_dir: pathlib.Path, state: WaitedDeliveryState) -> None:
    state["updated_at"] = _utc_now()
    _write_json(run_dir / "state.json", state)


def _attach_child(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    if not args.child_session_id.strip():
        raise UserError("attach-child requires a nonblank child session id")
    orchestration = state["orchestration"]
    if orchestration["child_status"] != "pending" or orchestration["child_session_id"]:
        raise UserError(
            "cannot attach child after child orchestration has already started"
        )
    orchestration["child_session_id"] = args.child_session_id
    orchestration["child_status"] = "running"
    orchestration["child_started_at"] = _utc_now()
    orchestration["updated_at"] = _utc_now()
    if args.parent_session_id:
        orchestration["parent_session_id"] = args.parent_session_id
    if args.parent_turn_id:
        orchestration["parent_turn_id"] = args.parent_turn_id
    if args.parent_transcript_path:
        orchestration["parent_transcript_path"] = args.parent_transcript_path
    if args.permission_mode:
        orchestration["permission_mode"] = args.permission_mode
    _save_state(run_dir, state)
    return 0


def _bind_parent(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    if (
        not args.parent_session_id
        and not args.parent_turn_id
        and not args.parent_transcript_path
        and not args.permission_mode
    ):
        raise UserError("bind-parent requires at least one parent metadata field")
    orchestration = state["orchestration"]
    if args.parent_session_id:
        orchestration["parent_session_id"] = args.parent_session_id
    if args.parent_turn_id:
        orchestration["parent_turn_id"] = args.parent_turn_id
    if args.parent_transcript_path:
        orchestration["parent_transcript_path"] = args.parent_transcript_path
    if args.permission_mode:
        orchestration["permission_mode"] = args.permission_mode
    orchestration["updated_at"] = _utc_now()
    _save_state(run_dir, state)
    return 0


def _begin_phase(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    phases = state["phases"]
    if args.phase not in phases:
        raise UserError(f"unknown phase: {args.phase}")
    phase = phases[args.phase]
    phase["status"] = "running"
    phase["summary"] = args.summary or ""
    phase["findings"] = []
    phase["evidence"] = []
    phase["updated_at"] = _utc_now()
    _save_state(run_dir, state)
    return 0


def _validate_review_pass(state: WaitedDeliveryState, evidence: list[str]) -> None:
    orchestration = state["orchestration"]
    if orchestration["child_status"] not in CHILD_TERMINAL_STATUSES:
        raise UserError("cannot record a passed review before the child is terminal")
    child_session_id = orchestration["child_session_id"]
    if not isinstance(child_session_id, str) or not child_session_id.strip():
        raise UserError(
            "cannot record a passed review without a nonblank attached child session id"
        )
    changed_files = _collect_changed_files(pathlib.Path(state["repo_root"]))
    if changed_files:
        sample = ", ".join(changed_files[:5])
        suffix = "" if len(changed_files) <= 5 else ", ..."
        raise UserError(
            "cannot record a passed review while implementation state is "
            f"dirty or untracked: {sample}{suffix}"
        )
    if not any(item.strip() for item in evidence):
        raise UserError(
            "cannot record a passed review without nonblank terminal reviewer evidence"
        )


def _validate_passed_reviews(state: WaitedDeliveryState) -> None:
    if "internal_review" not in state["phases"]:
        raise UserError(
            "waited-delivery state is missing the required internal_review phase"
        )
    for phase_name in REVIEW_PHASES:
        phase = state["phases"].get(phase_name)
        if phase is not None and phase["status"] == "passed":
            _validate_review_pass(state, phase["evidence"])


def _record_phase(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    phases = state["phases"]
    if args.phase not in phases:
        raise UserError(f"unknown phase: {args.phase}")
    if args.status not in PHASE_STATUSES:
        raise UserError(f"unsupported status: {args.status}")
    if args.phase in REVIEW_PHASES and args.status == "passed":
        _validate_review_pass(state, list(args.evidence))
    phase = phases[args.phase]
    phase["status"] = args.status
    phase["summary"] = args.summary or ""
    phase["findings"] = list(args.finding)
    phase["evidence"] = list(args.evidence)
    phase["updated_at"] = _utc_now()
    _save_state(run_dir, state)
    return 0


def _close_open_phases(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    if args.status not in TERMINAL_PHASE_STATUSES:
        raise UserError(f"close-open-phases requires a terminal status: {args.status}")
    findings = list(args.finding)
    evidence = list(args.evidence)
    if args.status == "passed" and any(
        phase_name in REVIEW_PHASES
        and state["phases"][phase_name]["status"] not in TERMINAL_PHASE_STATUSES
        for phase_name in state["phases_order"]
    ):
        raise UserError(
            "close-open-phases cannot mark review phases passed; record each "
            "review phase with its own terminal evidence"
        )
    updated = False
    for phase_name in state["phases_order"]:
        phase = state["phases"][phase_name]
        if phase["status"] in TERMINAL_PHASE_STATUSES:
            continue
        phase["status"] = args.status
        phase["summary"] = args.summary or ""
        phase["findings"] = findings.copy()
        phase["evidence"] = evidence.copy()
        phase["updated_at"] = _utc_now()
        updated = True
    if updated:
        _save_state(run_dir, state)
    return 0


def _transition_child_terminal(
    state: WaitedDeliveryState,
    *,
    child_status: str,
    child_session_id: str | None,
) -> None:
    if child_status not in CHILD_TERMINAL_STATUSES:
        raise UserError(f"unsupported child status: {child_status}")
    orchestration = state["orchestration"]
    attached_id = orchestration["child_session_id"]
    if not attached_id:
        raise UserError(
            "cannot finish child before attach-child records its session id"
        )
    if not child_session_id or not child_session_id.strip():
        raise UserError(
            "child terminal transition requires a nonblank child session id"
        )
    if child_session_id != attached_id:
        raise UserError(
            "child session id does not match the attached child: "
            f"expected {attached_id}, got {child_session_id}"
        )
    current_status = orchestration["child_status"]
    if current_status == "running":
        orchestration["child_status"] = child_status
        orchestration["child_finished_at"] = _utc_now()
        orchestration["updated_at"] = _utc_now()
    elif current_status in CHILD_TERMINAL_STATUSES:
        if current_status != child_status:
            raise UserError(
                "child terminal status does not match the recorded status: "
                f"expected {current_status}, got {child_status}"
            )
    else:
        raise UserError(
            "cannot finish child before attach-child transitions it to running"
        )


def _finish_child(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    _transition_child_terminal(
        state,
        child_status=args.child_status,
        child_session_id=args.child_session_id,
    )
    _save_state(run_dir, state)
    return 0


def _classify_smoke(
    stdout: str, stderr: str, returncode: int
) -> tuple[str, str | None]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if lines and lines[-1] == "READY":
        return "passed", "READY"
    blocked = next((line for line in lines if line.startswith("BLOCKED:")), None)
    if blocked:
        return "blocked", blocked
    if returncode == 0:
        sample = lines[-1] if lines else None
        return "decision_point", sample
    err_lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if err_lines:
        return "blocked", err_lines[-1]
    return "blocked", f"process exited with code {returncode}"


def _run_fallback_smoke(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    smoke = state["fallback_readiness_smoke"]
    if not smoke["enabled"]:
        raise UserError("fallback readiness smoke is disabled for this run")

    command = list(smoke["command"])
    completed = subprocess.run(
        command,
        cwd=state["repo_root"],
        text=True,
        capture_output=True,
        check=False,
    )
    status, sample = _classify_smoke(
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )
    smoke["status"] = status
    smoke["sample"] = sample
    smoke["stdout"] = completed.stdout
    smoke["stderr"] = completed.stderr
    smoke["returncode"] = completed.returncode
    smoke["updated_at"] = _utc_now()
    _save_state(run_dir, state)
    if sample:
        print(sample)
    return 0 if status == "passed" else 1


def _overall_status(phases: dict[str, PhaseState]) -> str:
    statuses = [phase["status"] for phase in phases.values()]
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "decision_point" for status in statuses):
        return "decision_point"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "unavailable" for status in statuses):
        return "unavailable"
    if statuses and all(status == "passed" for status in statuses):
        return "passed"
    if any(status == "running" for status in statuses):
        return "running"
    return "pending"


def _write_summary(
    run_dir: pathlib.Path, state: WaitedDeliveryState, *, require_terminal: bool
) -> pathlib.Path:
    non_terminal = _non_terminal_phase_names(state)
    if require_terminal and non_terminal:
        raise UserError(
            "cannot finalize before all phases reach terminal status: "
            + ", ".join(non_terminal)
        )
    orchestration = state["orchestration"]
    if (
        require_terminal
        and orchestration["child_status"] not in CHILD_TERMINAL_STATUSES
    ):
        raise UserError(
            "cannot finalize before child reaches terminal status: "
            f"{orchestration['child_status']}"
        )
    child_session_id = orchestration["child_session_id"]
    if orchestration["child_status"] in CHILD_TERMINAL_STATUSES and (
        not isinstance(child_session_id, str) or not child_session_id.strip()
    ):
        raise UserError(
            "cannot finalize a terminal run without a nonblank attached child session id"
        )
    _validate_passed_reviews(state)
    overall_status = _overall_status(state["phases"])
    state["overall_status"] = overall_status
    lines = [
        "# Waited Delivery Summary",
        "",
        f"- Run ID: `{state['run_id']}`",
        f"- Overall status: `{overall_status}`",
        "",
        "## Phases",
    ]
    for phase_name in state["phases_order"]:
        phase = state["phases"][phase_name]
        summary = phase["summary"] or "no summary"
        lines.append(f"- `{phase_name}`: `{phase['status']}` - {summary}")
    lines.extend(
        [
            "",
            "## Orchestration",
            f"- Parent session: `{orchestration['parent_session_id'] or 'unknown'}`",
            f"- Parent turn: `{orchestration['parent_turn_id'] or 'unknown'}`",
            f"- Parent transcript: `{orchestration['parent_transcript_path'] or 'unknown'}`",
            f"- Permission mode: `{orchestration['permission_mode'] or 'unknown'}`",
            f"- Child session: `{orchestration['child_session_id'] or 'unknown'}`",
            f"- Child status: `{orchestration['child_status']}`",
        ]
    )
    smoke = state["fallback_readiness_smoke"]
    lines.extend(
        [
            "",
            "## Fallback Readiness Smoke",
            f"- Enabled: `{str(smoke['enabled']).lower()}`",
            f"- Status: `{smoke['status']}`",
        ]
    )
    if smoke["sample"]:
        lines.append(f"- Sample: `{smoke['sample']}`")
    summary_path = run_dir / "summary.md"
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _save_state(run_dir, state)
    return summary_path


def _finalize(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    summary_path = _write_summary(
        run_dir, state, require_terminal=args.require_terminal
    )
    print(summary_path)
    return 0


def _reconcile_parent(args: argparse.Namespace) -> int:
    run_dir, state = _load_state_from_run_dir(args.run_dir)
    _transition_child_terminal(
        state,
        child_status=args.child_status,
        child_session_id=args.child_session_id,
    )
    orchestration = state["orchestration"]
    summary_path = _write_summary(run_dir, state, require_terminal=True)
    if args.json:
        print(
            json.dumps(
                {
                    "summary_path": str(summary_path),
                    "overall_status": state["overall_status"],
                    "child_status": orchestration["child_status"],
                    "child_session_id": orchestration["child_session_id"],
                }
            )
        )
    else:
        print(summary_path)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and track deterministic waited-delivery runs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument(
        "--repo", required=True, help="Git repo root or path inside the repo."
    )
    prepare.add_argument(
        "--goal", required=True, help="Short delivery goal for the current run."
    )
    prepare.add_argument("--run-id", help="Optional explicit run identifier.")
    prepare.add_argument(
        "--json",
        action="store_true",
        help="Print the prepared run/artifact paths as JSON.",
    )
    prepare.add_argument(
        "--parent-session-id", help="Optional parent session identifier."
    )
    prepare.add_argument("--parent-turn-id", help="Optional parent turn identifier.")
    prepare.add_argument(
        "--parent-transcript-path",
        help="Optional parent transcript/rollout path from an outer hook or adapter.",
    )
    prepare.add_argument(
        "--permission-mode",
        help="Optional parent permission mode from an outer hook or adapter.",
    )
    prepare.add_argument(
        "--phase",
        action="append",
        help="Override phase order; every override must include internal_review.",
    )
    prepare.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Repo-relative changed file.",
    )
    prepare.add_argument(
        "--known-blocker", action="append", default=[], help="Known blocker to record."
    )
    prepare.add_argument("--external-lane", default="bounded-semantic")
    prepare.add_argument("--fallback-lane", default="baseline")
    prepare.add_argument("--fallback-entrypoint", default="gh-copilot")
    prepare.add_argument(
        "--external-helper",
        default=str(DEFAULT_EXTERNAL_HELPER),
        help="Path to the external review helper used for readiness smoke.",
    )
    prepare.add_argument(
        "--no-fallback-smoke",
        action="store_true",
        help="Disable fallback readiness smoke artifacts for this run.",
    )
    prepare.set_defaults(func=_prepare)

    attach_child = subparsers.add_parser("attach-child")
    attach_child.add_argument("--run-dir", required=True)
    attach_child.add_argument("--child-session-id", required=True)
    attach_child.add_argument("--parent-session-id")
    attach_child.add_argument("--parent-turn-id")
    attach_child.add_argument("--parent-transcript-path")
    attach_child.add_argument("--permission-mode")
    attach_child.set_defaults(func=_attach_child)

    bind_parent = subparsers.add_parser("bind-parent")
    bind_parent.add_argument("--run-dir", required=True)
    bind_parent.add_argument("--parent-session-id")
    bind_parent.add_argument("--parent-turn-id")
    bind_parent.add_argument("--parent-transcript-path")
    bind_parent.add_argument("--permission-mode")
    bind_parent.set_defaults(func=_bind_parent)

    begin_phase = subparsers.add_parser("begin-phase")
    begin_phase.add_argument("--run-dir", required=True)
    begin_phase.add_argument("--phase", required=True)
    begin_phase.add_argument("--summary", default="")
    begin_phase.set_defaults(func=_begin_phase)

    record_phase = subparsers.add_parser("record-phase")
    record_phase.add_argument("--run-dir", required=True)
    record_phase.add_argument("--phase", required=True)
    record_phase.add_argument("--status", required=True)
    record_phase.add_argument("--summary", default="")
    record_phase.add_argument("--finding", action="append", default=[])
    record_phase.add_argument("--evidence", action="append", default=[])
    record_phase.set_defaults(func=_record_phase)

    close_open = subparsers.add_parser("close-open-phases")
    close_open.add_argument("--run-dir", required=True)
    close_open.add_argument("--status", required=True)
    close_open.add_argument("--summary", default="")
    close_open.add_argument("--finding", action="append", default=[])
    close_open.add_argument("--evidence", action="append", default=[])
    close_open.set_defaults(func=_close_open_phases)

    run_smoke = subparsers.add_parser("run-fallback-smoke")
    run_smoke.add_argument("--run-dir", required=True)
    run_smoke.set_defaults(func=_run_fallback_smoke)

    finish_child = subparsers.add_parser("finish-child")
    finish_child.add_argument("--run-dir", required=True)
    finish_child.add_argument("--child-status", required=True)
    finish_child.add_argument("--child-session-id", required=True)
    finish_child.set_defaults(func=_finish_child)

    reconcile_parent = subparsers.add_parser("reconcile-parent")
    reconcile_parent.add_argument("--run-dir", required=True)
    reconcile_parent.add_argument("--child-status", required=True)
    reconcile_parent.add_argument("--child-session-id", required=True)
    reconcile_parent.add_argument(
        "--json",
        action="store_true",
        help="Print summary/result fields as JSON instead of only the summary path.",
    )
    reconcile_parent.set_defaults(func=_reconcile_parent)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--run-dir", required=True)
    finalize.add_argument(
        "--require-terminal",
        action="store_true",
        help="Fail unless the child and all phases already reached terminal status.",
    )
    finalize.set_defaults(func=_finalize)

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
