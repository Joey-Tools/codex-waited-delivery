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

1. In the first release, replace the old active `kind: skill` link with an
   inert `kind: directory` link backed by the repository asset
   `legacy-hook-shims/waited-delivery/scripts/` onto every installed or
   aggregate `skills/waited-delivery/scripts/` path still named by a hook
   registration or persisted active-run command. Direct repository links use
   the byte-identical checked-in historical target at that path. Both source
   directories omit `SKILL.md`; the adapter never parses argv, reads stdin,
   writes state, or returns a blocking status. The runner is a fixed executable
   redirect to the sibling packaged
   `skills/waited-delivery-compat/scripts/waited_delivery_runner.py`. It opens
   that source with `O_NOFOLLOW | O_NONBLOCK`, rejects a FIFO or other
   non-regular object after `fstat` without waiting for another endpoint, binds
   the regular-file object, current-user access policy, bounded size, and two
   equal byte reads, then forks a one-shot writer that transfers those verified
   bytes through an anonymous pipe. The current Python interpreter is replaced
   by a fixed `-I -B -S -c` bootstrap that verifies the exact length, EOF, and
   SHA-256 digest, reaps the writer, preserves the canonical compatibility path
   in `__file__` and the original runner arguments, and compiles the bytes in
   memory. No regular-file source snapshot is created. Replacing or modifying
   the source path after binding,
   including through a pre-held writable descriptor or hard link, cannot
   change the executed bytes. Aggregate and private-overlay packaging must
   preserve both legacy files and the compatibility runner at those relative
   release paths. Record that
   active-skill-to-inert-directory identity change with its own append-only
   `removed_links` migration entry while keeping the target installed.
2. Remove every default `UserPromptSubmit` and `Stop` registration on each host,
   then verify the effective hook configuration contains no legacy adapter
   path. Independently verify that no active run still persists a command for
   the legacy runner path.
3. Only after both proofs, retire the legacy `skills/waited-delivery` target by
   removing the non-discoverable directory link in a later release and
   appending a second entry to downstream `removed_links` metadata with
   `skills/change-delivery-workflow` as its replacement. Preserve the first
   migration entry as history.

Do not remove the legacy link in the same transaction that merely requests hook
configuration cleanup. A stale registration must continue to reach the inert
adapter until absence is independently verified, and an active pre-rename child
must continue to reach the fixed runner redirect until legacy runs drain. The
compatibility implementation under `waited-delivery-compat` remains
explicit-only; only the non-discoverable fixed redirect is retained at the
legacy path.

Contract tests exercise the direct repository link, aggregate and private
overlay release layouts, and the two-phase order: the inert adapter and runner
redirect remain callable while a registration or active legacy run exists,
then `removed_links` may retire the target only after the effective hook list
is empty and active legacy runs have drained.

Distribution-profile contract tests keep validating a synced reference-only
copy in that recognized layout, but skip only the canonical documentation
assertions. Missing or partial documentation in the canonical
`skills/waited-delivery-compat` layout remains an error.
