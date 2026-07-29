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
- Every runner state read-modify-write operation now holds one run-level lock; prompt, state, and summary files use pinned-directory no-follow checks and descriptor-relative atomic replacement.
- The Stop hook validates exact current-repo containment, exact `state.repo_root`, no-symlink path components, regular state/prompt files, and stable run identity before and after automatic prompt refresh. External or replaced/link-backed records block without writing through them.
- Linux-only test support distinguishes a proven zombie-only process group from a live descendant with bounded `/proc` evidence; unreadable or ambiguous evidence remains live.

## Next Steps

- Confirm the current patch in PR CI's Linux runner after branch publication; the local Apple container image store is incomplete and the installed Podman has no running machine.
- Propagate the inert shim and later `removed_links` retirement through aggregate and private-overlay releases in two distinct phases.

## Evidence

- PR: https://github.com/Joey-Tools/codex-waited-delivery/pull/7
- GitHub Codex request: `5088799547`
- Provider review: `4784949604`
- Addressed inline comments: `3655428980`, `3655428974`
- Local full suite: `89` tests passed.
- Focused runner suite: `18` tests passed, including deterministic lock interleavings for prompt refresh versus phase and child-terminal RMW.
- Focused hook-adapter suite: `45` tests passed, including external run, repo mismatch, run/state/prompt symlink, and post-preflight link-replacement fail-closed cases.
- Linux-path focused suite: `6` tests passed with synthetic `/proc` states covering zombie-only, live, deadline, unreadable, ambiguous, and cleanup behavior.
- Static gates: Ruff format/check, Python compile, skill validation, and project-journal validation passed.
- Signed implementation commit: `28c972a62b8ea3df65d8cdfc46644c7968ad813e` (`Good signature`).
- Exact-secret admission: clean for `2cc1f97efc86dfbcb582743e5f0eb46440f2f713..28c972a62b8ea3df65d8cdfc46644c7968ad813e`; temporary cleanup complete.
