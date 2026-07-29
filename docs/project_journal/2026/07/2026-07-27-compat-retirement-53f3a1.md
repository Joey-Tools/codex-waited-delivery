---
id: 20260727-53f3a1
title: Waited Delivery Compatibility Retirement
status: active
created: 2026-07-27
updated: 2026-07-29
branch: codex/compat-retirement
pr: https://github.com/Joey-Tools/codex-waited-delivery/pull/7
supersedes: []
superseded_by:
---

# Waited Delivery Compatibility Retirement

## Summary

- Retire waited-delivery from active skill discovery while preserving explicit recovery tooling and fail-open behavior for stale hook registrations.

## Current State

- The compatibility skill lives at `skills/waited-delivery-compat` and requires explicit invocation.
- A byte-identical shim remains at both the standalone release asset and historical direct-link target; neither target has a `SKILL.md`.
- Recovery rewrites persisted child and parent prompts through the loaded compatibility runner before returning continuation guidance.
- Every runner state read-modify-write operation now holds one run-level lock; state loads bind the opened file's device/inode and SHA-256 content version, and state saves compare that original version before descriptor-relative atomic replacement while distinguishing missing, replaced, content-changed, and unreadable state. Final publication also binds the named artifact back to the fsynced temporary inode and intended bytes.
- Fallback smoke execution keeps one run-directory fd and one lock-file fd, snapshots its command and state version with the lock held, unlocks that same fd for a hard-time/byte-bounded process-group run, and CAS-merges only its result after reacquiring it. Output supervision is initialized before process launch, and every nonzero helper result becomes a `BLOCKED:` sample even if stdout or stderr contains `READY`. One deferred `SIGHUP`/`SIGTERM`/`SIGQUIT` transaction remains armed across the start-new-session helper, proves bounded process-group kill/drain/reap, restores the original handlers/mask, and only then redelivers the first signal; default handlers terminate and returning custom handlers resume with a nonzero blocked result. Phase and child-terminal updates remain available while a smoke is hung; lock replacement or run object/access drift fails closed.
- The Stop hook validates exact current-repo containment, exact `state.repo_root`, no-symlink path components, regular state/prompt files, current-user ownership, mode `0700`, and stable run object/access identity before and after automatic prompt refresh. It keeps the original run fd open and carries device/inode plus uid/gid/mode through the bridge. Artifact reads bind named entry and descriptor object/access/size plus two bounded byte reads and SHA-256 digests, accepting metadata-only timestamp churn while rejecting content instability. External, access-changed, content-changed, symlink-backed, or ordinary-directory replacement records block without writing through them.
- Linux-only test support distinguishes a proven zombie-only process group from a live descendant with bounded `/proc` evidence; unreadable or ambiguous evidence remains live.

## Next Steps

- Confirm the current patch in PR CI's Linux runner after branch publication; the local Apple container image store is incomplete and the installed Podman has no running machine.
- Propagate the inert shim and later `removed_links` retirement through aggregate and private-overlay releases in two distinct phases.

## Evidence

- PR: https://github.com/Joey-Tools/codex-waited-delivery/pull/7
- GitHub Codex request: `5088799547`
- Provider review: `4784949604`
- Addressed inline comments: `3655428980`, `3655428974`
- Local full suite: `105` tests passed.
- Focused runner suite: `29` tests passed, including deterministic lock interleavings, one-descriptor smoke snapshot/merge, stdout/stderr `READY`-then-failure classification, selector-construction failure before launch, bounded timeout/byte/residual-process cleanup, default and returning-handler terminal-signal process-group cleanup and redelivery, state identity/digest CAS classifications, and published-temp identity binding.
- Focused hook-adapter suite: `50` tests passed, including external run, repo mismatch, run/state/prompt symlink, pre-refresh and post-refresh link/replacement checks, ordinary-directory replacement, run access-policy drift, metadata-only churn, and actual content-change fail-closed cases.
- Linux-path focused suite: `6` tests passed with synthetic `/proc` states covering zombie-only, live, deadline, unreadable, ambiguous, and cleanup behavior.
- Static gates: Ruff format/check, Python compile, skill validation, and project-journal validation passed.
- Previous signed implementation checkpoint: `21dad301253d5cef0d873d968f517f9f2dd6131d` (`Good signature`).
- Exact-secret admission: clean from `2cc1f97efc86dfbcb582743e5f0eb46440f2f713` through the final signed handoff head; temporary cleanup complete.
