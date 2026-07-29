---
name: waited-delivery-compat
description: Inspect or explicitly exercise historical waited-delivery child-and-wait artifacts. Use only when the user names waited-delivery compatibility, asks to recover a prior waited-delivery run, or requests a bounded experiment against its runner, bridge, or hooks; never use it for default change delivery, task supervision, or PR readiness.
---

# Waited Delivery Compatibility

## Overview

Use this skill only when the user explicitly wants to inspect, recover, or test the historical workflow where the main session stays blocked, spawns exactly one delivery child, and waits for that child to reach a terminal result before replying.

Treat this skill as reference-only historical compatibility infrastructure.

- Do not install or link it into the active personal skill directory.
- Do not silently replace `$change-delivery-workflow` with it.
- Do not use it for PR readiness; use `$review-orchestration-playbook`.
- Prefer `cbth` for new long-running task supervision and delivery experiments unless the user specifically asks to exercise waited-delivery.
- Do not register its `UserPromptSubmit` or `Stop` hooks by default.
- Require `--enable-compat-hook` on either historical hook command; without that flag the command returns `{}` without reading or persisting its payload.
- Keep hook diagnostic `prompt_preview` and `assistant_preview` fields null. Never restore prompt or assistant-message content logging.

## Execution Layer

Prefer the deterministic runner under `scripts/waited_delivery_runner.py` when setting up a real run.
When thinking about future hooks or app-side adapters, also use the env-aware bridge under `scripts/waited_delivery_bridge.py`.
When the user explicitly requests a compatibility hook experiment and verified `UserPromptSubmit` / `Stop` hooks are available, use the outer adapter under `scripts/waited_delivery_hook_adapter.py` with `--enable-compat-hook` to bind a session to a run and to gate premature stop attempts.

- `prepare`: create `.codex-tmp/waited-delivery/<run-id>/`, write `state.json`, `child-contract.md`, `child-prompt.md`, `parent-prompt.md`, and fallback-smoke artifacts. Any `--phase` override must retain the required `internal_review` phase. Use `--json` when a future supervisor or hook needs machine-readable artifact paths.
- `prepare-live`: bridge command that wraps `prepare --json` and injects parent metadata from args or the bridge env contract.
- `bind-parent-live`: bridge command that patches parent metadata into an existing run after the ids become known.
- `attach-child-live`: bridge command that wraps `attach-child` and also propagates parent metadata from args or env.
- `refresh-prompts`: runner recovery command that rewrites `child-prompt.md` and `parent-prompt.md` with commands bound to the currently loaded compatibility runner and rebinds their canonical run-local artifact paths. It holds the same run-level lock as phase and child-terminal updates, rejects symlink/non-regular state or prompt artifacts, and commits prompt/state changes with descriptor-relative atomic replacement. State loads return the opened file's device/inode plus content digest; the subsequent save compares that original version and distinguishes missing, replaced, content-changed, and unreadable state. Publication also proves that the final named file is the fsynced temporary inode with the intended bytes.
- `refresh-prompts-live`: bridge command that wraps `refresh-prompts --json`; the explicitly enabled stop hook uses it before returning continuation guidance for an older active run and binds the initially validated run-directory device/inode plus POSIX owner/group/mode through the bridge.
- `finish-child-live`: bridge command that requires the attached child's exact nonblank `child_session_id` and records its matching terminal status after `wait` and before parent-owned review.
- `reconcile-live`: bridge command that requires the same exact `child_session_id` and wraps `reconcile-parent --json`.
- `user-prompt-submit-hook`: compatibility hook entrypoint that is inert unless passed `--enable-compat-hook`; when explicitly enabled, it records the current session metadata into a repo-local adapter index.
- `stop-hook`: compatibility hook entrypoint that is inert unless passed `--enable-compat-hook`; when explicitly enabled, it first proves that the indexed run is a direct no-symlink child of the current repo's `.codex-tmp/waited-delivery`, that `state.repo_root` exactly matches that repo, and that state/prompt artifacts are regular no-follow files. It keeps that validated run-directory descriptor open throughout bridge refresh, binds its device/inode and POSIX owner/group/mode, regenerates both persisted prompts through the loaded compatibility runner so historical absolute runner paths are not reused, and blocks premature finish with a continuation prompt. An external, access-changed, replaced, or linked run fails closed without refreshing it.
- `prepare-active-run`: outer-adapter command that resolves an unambiguous observed session and binds it to a new `run_dir` through `prepare-live`; prefer `--session-id` when available, let host-injected `CODEX_THREAD_ID` act as the default explicit parent-session selector when present, and otherwise use `--transcript-path` or `--prompt-text` as explicit recovery selectors instead of trusting repo-global recency.
- `attach-child-active-run`: outer-adapter command that wraps `attach-child-live` while preserving the recorded parent metadata; blank child ids are rejected before the run can enter `running`.
- `finish-child-active-run`: outer-adapter command that wraps `finish-child-live` while requiring both the selected session to own the run and the caller-supplied child id to match the attachment, keeping that association for review and reconciliation.
- `reconcile-active-run`: outer-adapter command that requires that same exact child id, wraps `reconcile-live`, and clears the active-run association when reconciliation completes.
- `attach-child`: record the parent/child session metadata as soon as the delivery child is spawned; reject blank child ids without mutating the pending run.
- `begin-phase`: let the child mark a phase as `running` before the actual gate work starts.
- `run-fallback-smoke`: open one run-directory descriptor and one lock-file descriptor, snapshot the smoke command and state version while that lock is held, unlock it while executing the command with a hard deadline, captured-byte ceiling, and process-group cleanup, then reacquire the same lock descriptor and CAS-merge only the smoke result. Phase and child-terminal updates can therefore complete while the smoke is still running; lock replacement, run identity/access drift, or a concurrent smoke-state change blocks the merge instead of being overwritten.
- `record-phase`: persist a phase result with summary, findings, and evidence.
- `close-open-phases`: let the child close untouched downstream phases with one terminal status when the run stops early at an earlier decisive gate.
- `finish-child`: require the caller to provide the attached child's exact nonblank id, then let the parent record that `wait` returned and the child is now terminal; a matching terminal replay preserves the original `child_finished_at`.
- `reconcile-parent`: require that same exact child id and let the parent collapse `finish-child + finalize --require-terminal` into one deterministic post-`wait` command without rewriting the child's recorded finish time.
- `finalize`: derive an overall delivery status and write `summary.md`; every invocation revalidates any passed review against terminal-child, clean-worktree, and evidence guards and requires the `internal_review` phase, and any invocation that sees a terminal child requires its nonblank attached identity, while `--require-terminal` additionally requires the child and every phase to be terminal.

Use the runner as the control plane even when the actual child work is still driven by a Codex subagent. The goal is to move run state, fallback smoke artifacts, and terminal accounting out of pure prompt memory.
For an explicit compatibility hook or supervisor experiment, prefer the repo-owned bridge env contract documented in [hook-supervisor-bridge.md](references/hook-supervisor-bridge.md) over guessing undocumented product env names inside the runner itself. The current bridge can already preserve `session_id`, `turn_id`, `transcript_path`, and `permission_mode` when an outer adapter has them, and it remains valid even when `turn_id` is temporarily unavailable.
For an explicit verified hook experiment against the historical `codex-cli 0.116.0` contract, also see the repo-local adapter guidance in [hook-adapter.md](references/hook-adapter.md).

## Workflow

1. Require explicit opt-in.
- Use this skill only when the user explicitly names it, explicitly asks for the experimental child-and-wait path, or explicitly asks to test whether `main session spawns delivery child and waits` solves delivery failures.
- Do not implicitly swap this in just because a task is non-trivial.

2. Finish the implementation first.
- Use the main session for normal exploration, design discussion, implementation, and low-level fixes.
- Do not spawn the delivery child before the intended code change is actually implemented.
- If the task is still in planning or coding, stay in the main session and defer delivery.

3. Prepare the delivery contract before spawning the child.
- Keep the contract small and explicit.
- Include only the current change goal, the repository/worktree path, immutable refs or changed-file scope, the required finish-line gates, known blockers, and the current review policy.
- Do not embed a complete diff in the contract or reviewer handoff. Let the reviewer discover the fixed range and necessary nearby context with tools inside the review workspace.
- Prefer `scripts/waited_delivery_runner.py prepare ...` so the contract, run directory, and fallback-smoke prompt are written to disk before the child starts.
- Prefer the generated `child-prompt.md` as the bounded handoff payload for the delivery child instead of rebuilding the control-plane instructions ad hoc.
- Prefer the generated `parent-prompt.md` as the bounded handoff/checklist for the main session instead of relying on prompt memory for `attach-child`, `wait`, and reconciliation.
- When recovering a run created before the compatibility rename, use `refresh-prompts` (or let the explicitly enabled stop hook call `refresh-prompts-live`) before following either persisted prompt. For an already active legacy child, have that same child re-read the regenerated child prompt before its next runner command.
- Prefer forked context when the runtime naturally provides it through Codex subagent spawning, but still restate the delivery contract explicitly so the child does not rely only on implicit history.
- Decide upfront which gates must end in a terminal result during this run.

4. Spawn exactly one delivery child and immediately wait.
- Spawn one child for the current delivery run.
- The child owns the post-implementation test, docs-sync, and verification gates for that run; the main session already owns implementation and the parent later owns review.
- Immediately persist the child metadata with `attach-child` before the parent starts waiting.
- Prefer reading the generated `parent-prompt.md` right before spawn so the parent follows the exact live sequence for this run.
- After spawning, the main session must wait for the child result instead of continuing with unrelated work or summarizing early.
- Do not end the main turn while the child is still active.
- Do not interrupt the child unless the user explicitly asks to interrupt or materially redirect the run.

5. Have the child run its finish-line sequence, then let the parent own review.
- The child should run its delivery stages in order:
- broad tests and e2e when applicable
- project journal or repo tracking doc sync
- terminal verification summary for the already-implemented change
- The child must not mark `internal_review` or `external_review` as passed. Review phases are parent-owned after the child returns.
- The parent owns the named internal single review. After the child returns, the parent must form an authorized, committed, clean/frozen `base_sha..head_sha` before review; dirty or untracked implementation state cannot count as reviewed.
- The runner always requires an `internal_review` phase, binds child completion to the attached child session, requires a nonblank attached child id before review `passed` or terminal finalization, rejects a review `passed` result before that child is terminal, while implementation state is dirty/untracked, or when nonblank terminal reviewer evidence is missing, and rechecks passed reviews when finalizing. The hook adapter likewise does not treat a legacy terminal status without that phase or identity as a completed run. `close-open-phases` cannot mark review phases passed. These are narrow state guards, not substitutes for the parent's fixed-range review contract.
- A named internal single review directly launches exactly one fresh/clear-context Codex `reviewer` agent. The parent requires it to load `$review-orchestration-playbook` plus applicable `AGENTS.md` and repository guidance, and has it discover the diff and necessary nearby context itself with tools inside the clean/frozen workspace.
- Keep the reviewer handoff bounded to the goal, workspace path, immutable refs, required skills/guidance, evidence budget, and output contract. Do not precompute or paste the full diff into the reviewer prompt.
- `isolated_review` is low-level compatibility/diagnostic tooling only. It cannot start, satisfy, substitute for, or count as the named internal single review; its `start` / `status` / `wait` / `final` lifecycle does not add a reviewer.
- If the configured `reviewer` agent is unavailable or inconclusive, do not substitute the helper or start a different Codex reviewer. After bounded attempts, record the single review as `blocked`, `unavailable`, or `decision_point` and explain the runtime state in the summary.
- Do not route the internal-review phase through a default coding subagent.
- Do not substitute Cursor/headless `agent` CLI for the Codex internal-review phase.
- Keep the external-review phase and its fallback-readiness smoke separate from the internal single review. The smoke is lane-availability evidence only and never changes the internal reviewer count or outcome.
- The child should call `begin-phase` before entering each child-owned gate and `record-phase` as soon as that gate reaches a terminal result.
- If the child stops early after one decisive gate, it should close untouched downstream phases with `close-open-phases` before returning, so the parent can still reconcile with `--require-terminal`.
- Decide the primary external-review lane and likely fallback lane before the main review attempt starts.
- If a cheap fallback readiness smoke can de-risk the fallback lane without paying full review cost, run it early and keep it narrow.
- When practical, overlap that fallback readiness smoke with child-owned work such as tests or docs sync so the workflow learns whether the fallback lane is alive before the parent starts review.
- Treat readiness smoke as a latency-reduction probe only, not as review coverage.
- Prefer `scripts/waited_delivery_runner.py run-fallback-smoke ...` to run and persist that sample instead of treating the smoke as ad-hoc shell output.
- If a stage fails, the child should stop at the earliest decisive failure point and report the exact failed gate.
- If a stage needs code changes to continue, the child should report that and return control to the main session instead of pretending the gate passed.

6. Treat review as terminal-state work, not as background commentary.
- Intermediate reviewer reasoning, stream output, tool traces, and file-read progress are not final review results.
- Internal review must end in a terminal outcome such as:
- `passed`
- `failed` with findings
- `blocked`
- `unavailable`
- External review must also be forced toward a terminal outcome.
- Distinguish `fallback readiness smoke` from the real `external_review`.
- A readiness smoke should aim to produce a tiny terminal sample such as `READY` or a crisp `BLOCKED: ...` line.
- Use that sample only to decide whether the fallback lane is worth keeping warm; do not count it as one of the delivery review verdicts.
- `inconclusive` is not a terminal outcome.
- If an external review lane stalls, retry with one materially different bounded attempt such as a narrower diff, explicit file list, or different entrypoint.
- Prefer a fallback lane that already produced a cheap readiness sample over an unexercised lane with only theoretical availability.
- If bounded retries are exhausted, stop at a the user decision point with a precise statement of what was verified and what remains unverified.

7. Keep the parent blocked until the child reaches a terminal result.
- The parent should treat the child result as the authoritative status for the child-owned finish-line work in that delivery run.
- The parent may act on the child result only after the child reaches a terminal state.
- Once `wait` returns, the parent should call `finish-child` with the exact attached `child_session_id`, form the authorized committed review range, run and record the parent-owned review phases, and only then use `reconcile-parent` with that same id to finalize before presenting the consolidated result to the user.
- If the implementation remains dirty/untracked or a commit is not authorized, record the review gate as `blocked` or `decision_point`; never claim that the child reviewed live implementation state.
- If the user interrupts the parent while the child is active, assume the child may have been interrupted too and re-verify state before resuming.
- If the user adds new steering while the parent is waiting, either:
- interrupt the child and restart from the earliest affected stage
- or send a bounded follow-up to the same child and keep waiting
- Do not mix old child results with new steering without explicitly reconciling the stage boundary.

8. Return a concise terminal summary.
- The parent's final response should say which stages passed, which failed, and whether any gate ended in a the user decision point.
- If the child returned because a review lane stayed blocked or unavailable, say that explicitly.
- Do not collapse `blocked`, `unavailable`, or `decision point` into fake success.
- Prefer `record-phase` during the run and `finalize` at the end so the child summary is backed by a persisted run record.

## Guardrails

- This skill is compatibility-only, reference-only, and opt-in only.
- Do not add it to active personal installation manifests.
- Do not enable either hook without `--enable-compat-hook`.
- Do not record prompt or assistant-message previews in hook diagnostics.
- Do not use it for tiny edits or pure discussion turns.
- Do not spawn multiple concurrent delivery children for the same task unless the user explicitly asks for a different parallel experiment.
- Do not let the parent end its turn before the child is terminal.
- Do not treat reviewer progress as a successful review.
- Do not silently drop external review just because it is inconvenient in the current environment.
- If the external review path depends on auth, approval, or runtime properties that the child cannot safely exercise, report that as `blocked` or `unavailable` instead of pretending the child covered it.
- If the user explicitly interrupts the run, respect the interrupt and report that the delivery result is incomplete.
