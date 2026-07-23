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
link that directory into the active personal skill installation. The legacy
`skills/waited-delivery` target should instead be retired through downstream
`removed_links` metadata with `skills/change-delivery-workflow` as its
replacement.

Distribution-profile contract tests keep validating a synced reference-only
copy in that recognized layout, but skip only the canonical documentation
assertions. Missing or partial documentation in the canonical
`skills/waited-delivery-compat` layout remains an error.
