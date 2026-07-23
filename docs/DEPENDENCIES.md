# Dependencies

The waited-delivery compatibility runner is intentionally historical and
experimental. Its optional external fallback-lane readiness smoke defaults to
`isolated_review` from the sibling `review-orchestration-playbook` skill layout
used by the public `codex-review-workflows` repository. In this workflow, that
helper is low-level compatibility/diagnostic tooling for the readiness probe
only. It cannot start, satisfy, substitute for, or count as the named internal
single review, and the probe never counts as review coverage.

The named internal single review remains exactly one fresh/clear-context Codex
`reviewer` agent owned by the parent after the delivery child returns. The
parent forms an authorized, committed, clean/frozen range first; dirty or
untracked implementation state cannot count as reviewed. The reviewer then
loads the applicable skills and repository guidance and discovers the fixed
diff and nearby context with tools instead of receiving a precomputed full
diff. The runner rejects a review `passed` result before the child is terminal,
while implementation state is dirty/untracked, or when nonblank terminal
reviewer evidence is missing. Bulk phase closure cannot mark review phases
passed.

Operators can avoid that layout dependency by passing `--external-helper` to
the runner or bridge commands, or disable the readiness smoke when it is not
needed. Neither choice changes the internal reviewer identity or count.

The private overlay may retain the compatibility source under the explicit
`personal_codex/skills/waited-delivery-compat` reference-only distribution
layout without this repository-level README or dependency document. It must not
link that directory into the active personal skill installation.

Legacy hook removal is a two-release migration:

1. First map the repository asset
   `legacy-hook-shims/waited-delivery/scripts/waited_delivery_hook_adapter.py`
   onto every installed or aggregate
   `skills/waited-delivery/scripts/waited_delivery_hook_adapter.py` path still
   named by a hook registration. The source lives outside the skill discovery
   root and has no `SKILL.md`; its adapter never parses argv, reads stdin, writes
   state, or returns a blocking status.
2. Remove every default `UserPromptSubmit` and `Stop` registration on each host,
   then verify the effective hook configuration contains no legacy adapter path.
3. Only after that proof, retire the legacy `skills/waited-delivery` target
   through downstream `removed_links` metadata with
   `skills/change-delivery-workflow` as its replacement.

Do not remove the legacy link in the same transaction that merely requests hook
configuration cleanup. A stale registration must continue to reach the inert
shim until absence is independently verified. The compatibility implementation
under `waited-delivery-compat` remains explicit-only and is never substituted at
the legacy path.

Distribution-profile contract tests keep validating a synced reference-only
copy in that recognized layout, but skip only the canonical documentation
assertions. Missing or partial documentation in the canonical
`skills/waited-delivery-compat` layout remains an error.
