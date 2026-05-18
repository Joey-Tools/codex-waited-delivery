# Dependencies

The waited-delivery runner is intentionally experimental. Its default fallback
review helper expects the sibling `review-orchestration-playbook` skill layout
used by the public `codex-review-workflows` repository.

Operators can avoid that layout dependency by passing `--external-helper` to
the runner or bridge commands.
