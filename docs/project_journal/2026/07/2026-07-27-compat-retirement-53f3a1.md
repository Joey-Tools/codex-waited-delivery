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
- Recovery rewrites persisted child and parent prompts through descriptor-bound bridge and runner snapshots while publishing the canonical compatibility-runner path before returning continuation guidance.
- Every runner state read-modify-write operation now holds one run-level lock; state loads bind the opened file's device/inode and SHA-256 content version, and state saves compare that original version before descriptor-relative atomic replacement while distinguishing missing, replaced, content-changed, and unreadable state. Final publication also binds the named artifact back to the fsynced temporary inode and intended bytes.
- Fallback smoke execution keeps one run-directory fd and one lock-file fd, snapshots its command, state version, and stable no-follow prompt bytes with the lock held, and gives the helper only an inherited `O_RDONLY` descriptor path for an owner-private, verified, unlinked copy of those bytes. It unlocks that same run-lock fd for the hard-time/byte-bounded process-group run, closes the prompt snapshot before reacquiring the lock, and CAS-merges only the result. Output supervision is initialized before process launch, and every nonzero helper result becomes a `BLOCKED:` sample even if stdout or stderr contains `READY`. One deferred `SIGHUP`/`SIGTERM`/`SIGQUIT` transaction remains armed across the start-new-session helper, proves bounded process-group kill/drain/reap, restores the original handlers/mask, and only then redelivers the first signal; default handlers terminate and returning custom handlers resume with a nonzero blocked result. Phase and child-terminal updates remain available while a smoke is hung; lock replacement, run object/access drift, prompt-path replacement, or a concurrent smoke-state change fails closed.
- The Stop hook validates exact current-repo containment, exact `state.repo_root`, no-symlink path components, regular state/prompt files, current-user ownership, mode `0700`, and stable run object/access identity before and after automatic prompt refresh. It keeps the original run fd open and, before any refresh process starts, stable-reads both bridge and runner sources, copies the bound bytes into an owner-only `0700` temporary directory as `0600` files, opens and verifies them as `O_RDONLY`, unlinks both names, and revalidates each source object's identity, access policy, size, and digest. It executes only the inherited snapshot FDs through Python `-I -B -S` with Python injection variables removed and no source/sibling fallback. The bridge forwards both FDs with the same isolation; under the run lock, the runner performs the final dual-snapshot revalidation immediately before the first prompt/state write. Refresh schema `2` binds both exact executed snapshot versions, both read-only access modes, isolated execution, and the prompt versions. Permanent source replacement, access-policy drift, or content drift fails before process or run-file writes; a launch-window A→B→A change cannot execute the intermediate object. The adapter still rereads each named prompt along the pinned run fd, binding object/access/size plus two bounded byte reads and SHA-256 digests. Metadata-only timestamp churn remains benign, while external, access-changed, content-changed, symlink-backed, or regular-file/directory replacement run records fail closed before a prompt path is rendered.
- Linux-only test support distinguishes a proven zombie-only process group from a live descendant with bounded `/proc` evidence; unreadable or ambiguous evidence remains live. Its selector is initialized before any pipe or process group exists, so selector resource exhaustion cannot leak a launched process or file descriptors.

## Next Steps

- Confirm the current patch in PR CI's Linux runner after branch publication; the local Apple container image store is incomplete and the installed Podman has no running machine.
- Propagate the inert shim and later `removed_links` retirement through aggregate and private-overlay releases in two distinct phases.

## Evidence

- PR: https://github.com/Joey-Tools/codex-waited-delivery/pull/7
- GitHub Codex request: `5088799547`
- Provider review: `4784949604`
- Addressed inline comments: `3655428980`, `3655428974`
- Local full suite: `123` tests passed.
- Focused runner suite: `36` tests passed, including deterministic lock interleavings, lock-bound descriptor-only smoke prompt consumption despite named-path symlink replacement, process-group disappearance after zombie-only cleanup, stdout/stderr `READY`-then-failure classification, selector-construction failure before launch, bounded timeout/byte/residual-process cleanup, default and returning-handler terminal-signal process-group cleanup and redelivery, state identity/access/digest CAS classifications, published-temp object/access binding through the final read, source-path and writable-FD rejection, exact bridge/runner receipts, and final dual-snapshot drift rejection before prompt/state writes.
- Focused bridge suite: `11` tests passed, including descriptor-only bridge/runner launch, Python `-I -B -S` plus `PYTHONPATH`/`sitecustomize` injection exclusion, read-only FD enforcement, exact executed-snapshot receipts, source-path bridge rejection with zero run-file writes, and bridge/runner source A→B→A replacement without intermediate-code execution.
- Focused hook-adapter suite: `55` tests passed, including external run, repo mismatch, run/state/prompt symlink, post-refresh child/parent regular-file replacement, prelaunch bridge/runner source identity/content/access drift with zero process/run-file writes, metadata-only timestamp churn, exact returned-version fail-closed checks, private snapshot cleanup, failed execution-path FD cleanup, and source A→B→A replacement without intermediate-code execution.
- Linux-path focused suite: `7` tests passed with synthetic `/proc` states covering zombie-only, live, deadline, unreadable, ambiguous, cleanup behavior, and selector-initialization failure before pipe/process creation.
- Static gates: Ruff format/check, Python compile, skill validation, and project-journal validation passed.
- Previous signed implementation checkpoint: `d0d3e7c7089a8ef9c291c1a68d6f9ab32071a833` (`Good signature`).
- Exact-secret admission: clean from `2cc1f97efc86dfbcb582743e5f0eb46440f2f713` through the final signed handoff head; temporary cleanup complete.
