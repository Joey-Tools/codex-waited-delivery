---
name: waited-delivery
description: Historical and experimental child-and-wait delivery workflow. Use only when the user explicitly asks to test or use waited-delivery itself, to inspect its runner/hooks, or to recover prior waited-delivery runs; do not use as the default change delivery or PR readiness workflow.
---

# Waited Delivery

## Overview

Use this skill when the user explicitly wants to test or use a delivery workflow where the main session stays blocked, spawns exactly one delivery child, and waits for that child to reach a terminal result before replying.

This skill is historical/experimental compatibility infrastructure.

- Do not silently replace `$change-delivery-workflow` with it.
- Do not use it for PR readiness; use `$review-orchestration-playbook`.
- Prefer `cbth` for new long-running task supervision and delivery experiments unless the user specifically asks to exercise waited-delivery.

## Execution Layer

Prefer the deterministic runner under `scripts/waited_delivery_runner.py` when setting up a real run.
When thinking about future hooks or app-side adapters, also use the env-aware bridge under `scripts/waited_delivery_bridge.py`.
When verified `UserPromptSubmit` / `Stop` hooks are available, prefer the outer adapter under `scripts/waited_delivery_hook_adapter.py` to bind a session to a run and to gate premature stop attempts.

- `prepare`: create `.codex-tmp/waited-delivery/<run-id>/`, write `state.json`, `child-contract.md`, `child-prompt.md`, `parent-prompt.md`, and fallback-smoke artifacts. Use `--json` when a future supervisor or hook needs machine-readable artifact paths.
- `prepare-live`: bridge command that wraps `prepare --json` and injects parent metadata from args or the bridge env contract.
- `bind-parent-live`: bridge command that patches parent metadata into an existing run after the ids become known.
- `attach-child-live`: bridge command that wraps `attach-child` and also propagates parent metadata from args or env.
- `reconcile-live`: bridge command that wraps `reconcile-parent --json`.
- `user-prompt-submit-hook`: hook entrypoint that records the current session metadata into a repo-local adapter index.
- `stop-hook`: hook entrypoint that checks whether a waited-delivery run is still active and, if so, blocks premature finish with a continuation prompt.
- `prepare-active-run`: outer-adapter command that resolves an unambiguous observed session and binds it to a new `run_dir` through `prepare-live`; prefer `--session-id` when available, let host-injected `CODEX_THREAD_ID` act as the default explicit parent-session selector when present, and otherwise use `--transcript-path` or `--prompt-text` as explicit recovery selectors instead of trusting repo-global recency.
- `attach-child-active-run`: outer-adapter command that wraps `attach-child-live` while preserving the recorded parent metadata.
- `reconcile-active-run`: outer-adapter command that wraps `reconcile-live` and clears the active-run association when reconciliation completes.
- `attach-child`: record the parent/child session metadata as soon as the delivery child is spawned.
- `begin-phase`: let the child mark a phase as `running` before the actual gate work starts.
- `run-fallback-smoke`: execute the prepared fallback readiness smoke and record the sample back into `state.json`.
- `record-phase`: persist a phase result with summary, findings, and evidence.
- `close-open-phases`: let the child close untouched downstream phases with one terminal status when the run stops early at an earlier decisive gate.
- `finish-child`: let the parent record that `wait` returned and the child is now terminal.
- `reconcile-parent`: let the parent collapse `finish-child + finalize --require-terminal` into one deterministic post-`wait` command.
- `finalize`: derive an overall delivery status and write `summary.md`; prefer `--require-terminal` when the parent is reconciling after `wait`.

Use the runner as the control plane even when the actual child work is still driven by a Codex subagent. The goal is to move run state, fallback smoke artifacts, and terminal accounting out of pure prompt memory.
For future hooks / supervisor integration, prefer the repo-owned bridge env contract documented in [hook-supervisor-bridge.md](references/hook-supervisor-bridge.md) over guessing undocumented product env names inside the runner itself. The current bridge can already preserve `session_id`, `turn_id`, `transcript_path`, and `permission_mode` when an outer adapter has them, and it remains valid even when `turn_id` is temporarily unavailable.
For actual verified hook integration on `codex-cli 0.116.0`, also see the repo-local adapter guidance in [hook-adapter.md](references/hook-adapter.md).

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
- Include only the current change goal, the relevant diff or changed-file scope, the required finish-line gates, known blockers, and the current review policy.
- Prefer `scripts/waited_delivery_runner.py prepare ...` so the contract, run directory, and fallback-smoke prompt are written to disk before the child starts.
- Prefer the generated `child-prompt.md` as the bounded handoff payload for the delivery child instead of rebuilding the control-plane instructions ad hoc.
- Prefer the generated `parent-prompt.md` as the bounded handoff/checklist for the main session instead of relying on prompt memory for `attach-child`, `wait`, and reconciliation.
- Prefer forked context when the runtime naturally provides it through Codex subagent spawning, but still restate the delivery contract explicitly so the child does not rely only on implicit history.
- Decide upfront which gates must end in a terminal result during this run.

4. Spawn exactly one delivery child and immediately wait.
- Spawn one child for the current delivery run.
- The child owns the finish-line work for that run.
- Immediately persist the child metadata with `attach-child` before the parent starts waiting.
- Prefer reading the generated `parent-prompt.md` right before spawn so the parent follows the exact live sequence for this run.
- After spawning, the main session must wait for the child result instead of continuing with unrelated work or summarizing early.
- Do not end the main turn while the child is still active.
- Do not interrupt the child unless the user explicitly asks to interrupt or materially redirect the run.

5. Have the child run the finish-line sequence.
- The child should run the delivery stages in order:
- broad tests and e2e when applicable
- project journal or repo tracking doc sync
- internal review
- external review when the current environment can actually run it
- final delivery summary for the parent
- Internal review should prefer the pinned Codex lane through `isolated_review stateful start --reviewer codex --base-ref <base_sha> --head-ref <head_sha>`, not a spawned reviewer subagent, because writable parent runtime overrides can leak into child sessions and the helper preserves a durable terminal artifact. If the Codex runtime is deterministically unavailable only after a successful preflight, use the retained frozen workspace with the clean-context `reviewer` agent exactly as `$review-orchestration-playbook` specifies, then clean up through the helper.
- When the internal lane needs subagent-like progress reporting, drive it through the helper's `start` / `status` / `wait` / `final` actions instead of `spawn_agent`.
- Keep the read-only custom `reviewer` agent only as an explicit weaker fallback when the helper-backed root lane is unavailable.
- Do not route the internal-review phase through a default coding subagent.
- Do not substitute Cursor/headless `agent` CLI for the Codex internal-review phase.
- The child should call `begin-phase` before entering each gate and `record-phase` as soon as that gate reaches a terminal result.
- If the child stops early after one decisive gate, it should close untouched downstream phases with `close-open-phases` before returning, so the parent can still reconcile with `--require-terminal`.
- Decide the primary external-review lane and likely fallback lane before the main review attempt starts.
- If a cheap fallback readiness smoke can de-risk the fallback lane without paying full review cost, run it early and keep it narrow.
- When practical, overlap that fallback readiness smoke with other late delivery work such as docs sync or internal review so the workflow learns whether the fallback lane is alive before the primary lane stalls.
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
- The parent should treat the child result as the authoritative finish-line status for that delivery run.
- The parent may summarize the child result only after the child reaches a terminal state.
- Once `wait` returns, the parent should prefer `reconcile-parent` so `finish-child + finalize --require-terminal` happen together before presenting the consolidated result to the user.
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

- This skill is experimental and opt-in only.
- Do not use it for tiny edits or pure discussion turns.
- Do not spawn multiple concurrent delivery children for the same task unless the user explicitly asks for a different parallel experiment.
- Do not let the parent end its turn before the child is terminal.
- Do not treat reviewer progress as a successful review.
- Do not silently drop external review just because it is inconvenient in the current environment.
- If the external review path depends on auth, approval, or runtime properties that the child cannot safely exercise, report that as `blocked` or `unavailable` instead of pretending the child covered it.
- If the user explicitly interrupts the run, respect the interrupt and report that the delivery result is incomplete.
