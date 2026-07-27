---
id: 20260727-53f3a1
title: Waited Delivery Compatibility Retirement
status: active
created: 2026-07-27
updated: 2026-07-27
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
- Linux-only test support distinguishes a proven zombie-only process group from a live descendant with bounded `/proc` evidence; unreadable or ambiguous evidence remains live.

## Next Steps

- Confirm the current patch in PR CI's Linux runner after branch publication; the local Apple container image store is incomplete and the installed Podman has no running machine.
- Complete signed delivery and exact secret admission for the current PR range.
- Propagate the inert shim and later `removed_links` retirement through aggregate and private-overlay releases in two distinct phases.

## Evidence

- PR: https://github.com/Joey-Tools/codex-waited-delivery/pull/7
- GitHub Codex request: `5088799547`
- Provider review: `4784949604`
- Addressed inline comments: `3655428980`, `3655428974`
- Local full suite: `83` tests passed.
- Linux-path focused suite: `6` tests passed with synthetic `/proc` states covering zombie-only, live, deadline, unreadable, ambiguous, and cleanup behavior.
- Static gates: Ruff format/check, Python compile, skill validation, and project-journal validation passed.
