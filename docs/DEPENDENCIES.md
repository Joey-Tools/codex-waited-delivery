# Dependencies

The waited-delivery runner is intentionally experimental. Its optional external
fallback-lane readiness smoke defaults to `isolated_review` from the sibling
`review-orchestration-playbook` skill layout used by the public
`codex-review-workflows` repository. In this workflow, that helper is low-level
compatibility/diagnostic tooling for the readiness probe only. It cannot start,
satisfy, substitute for, or count as the named internal single review, and the
probe never counts as review coverage.

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

## Required CI activation boundary

This repository publishes `.github/workflows/required-ci.yml` as an input-free
reusable leaf that intentionally exposes only `workflow_call`. The leaf does
not schedule itself, does not create or claim a required check by itself, and
does not independently prove that the check is enforced.

Enforcement requires both the external central router at
`Joey-Tools/codex-review-gate/.github/workflows/required-ci-router.yml` and
organization required-workflow/ruleset activation. Until operators
independently verify both for the target repository, they must treat the leaf
as published but not enforced. This repository does not claim that activation
has occurred.

Direct triggers in the leaf and a duplicate caller in this repository are
forbidden; scheduling authority remains with the central router. The target
caller event must supply the exact GitHub context consumed by the input-free
leaf. For this leaf, `github.repository` must be exactly
`Joey-Tools/codex-waited-delivery`, and `github.sha` must be the exact target
commit under evaluation. The repository guard and bound checkout fail closed
when that caller context does not match.

The private overlay packages the skill under the explicit
`personal_codex/skills/waited-delivery` distribution layout without this
repository-level README or dependency document. Distribution-profile contract
tests therefore keep validating the synced skill and runtime in that recognized
layout, but skip only the canonical documentation assertions. Missing or partial
documentation in the canonical `skills/waited-delivery` layout remains an error.
