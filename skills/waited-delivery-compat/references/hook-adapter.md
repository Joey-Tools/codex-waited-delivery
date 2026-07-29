# Compatibility Hook Adapter

Use the hook adapter only for an explicitly requested waited-delivery
compatibility experiment with verified Codex hook events. Do not install this
skill into the active personal skill directory or register either hook by
default.

## Adapter Script

- [waited_delivery_hook_adapter.py](../scripts/waited_delivery_hook_adapter.py)

## Responsibilities

The adapter adds one explicitly enabled layer above the bridge:

- `UserPromptSubmit` hook records the current session metadata in a repo-local session index only when its command includes `--enable-compat-hook`
- `prepare-active-run` resolves an unambiguous observed session and binds it to a new `run_dir`
- `Stop` hook checks that session index and blocks premature finish while the run is still active only when its command includes `--enable-compat-hook`
- before rendering an active-run continuation, `Stop` calls `refresh-prompts-live` so both persisted prompts use the currently loaded compatibility runner instead of a removed historical absolute path
- before that refresh, `Stop` opens the repo/run path component-by-component without following links, requires the indexed `run_dir` to be a direct child of the current repo's `.codex-tmp/waited-delivery`, requires exact `state.repo_root` equality, requires regular no-follow state and prompt files, requires the current user plus mode `0700`, and records the opened run directory's exact device/inode and POSIX uid/gid/mode
- `Stop` keeps that descriptor open while the bridge runs, sends its full recorded identity through the bridge, and rereads state/prompts through the same descriptor before rendering guidance; each bounded artifact read binds the descriptor to the named entry and compares stable object/access/size plus two actual byte reads and their SHA-256 digests, while deliberately allowing timestamp-only churn. A symlink, ordinary-directory replacement, owner/group drift, mode change, or content change therefore fails closed.
- `finish-child-active-run` requires the exact attached child id, records the child's terminal status, and preserves the active-run association for parent-owned review
- `reconcile-active-run` requires that same exact child id and clears the active-run association only when reconciliation finishes cleanly with the required `internal_review` phase and a nonblank attached child identity

This keeps hooks product-facing and lets the bridge remain product-agnostic.

## Session Index

The adapter stores repo-local state under:

- `.codex-tmp/waited-delivery-hook-adapter/index.json`

Current records are keyed by `session_id` and include:

- `session_id`
- `cwd`
- `transcript_path`
- `permission_mode`
- `last_prompt`
- `run_dir`
- `status`
- `updated_at`

The adapter also keeps `latest_session_id` as an observation hint, but `prepare-active-run` no longer trusts it blindly once multiple sessions have been observed for the same repo.
When the host shell exposes `CODEX_THREAD_ID`, the adapter treats that as the default explicit parent-session selector for the current interactive thread instead of relying on repo-global recency.

## Hook Commands

- Both hook commands return `{}` without reading stdin when
  `--enable-compat-hook` is absent. This keeps stale legacy registrations inert
  until downstream removal metadata unlinks the old active installation.
- `user-prompt-submit-hook`
  - requires `--enable-compat-hook` to run the historical behavior
  - reads payload JSON from stdin
  - resolves the repo root from `cwd`
  - records the current session metadata into the adapter index
  - returns `{}` on success
- `stop-hook`
  - requires `--enable-compat-hook` to run the historical behavior
  - reads payload JSON from stdin
  - looks up the active `run_dir` for the current `session_id`
  - allows stop if no active run exists
  - blocks stop with a continuation prompt when the run is still active or not yet reconciled
  - regenerates `child-prompt.md` and `parent-prompt.md` through the loaded compatibility bridge before referring the parent back to either file
  - passes the exact current repo root plus the preflight run-directory device/inode, uid/gid, and mode through the bridge to the runner; the runner revalidates them under its run-level lock and atomically replaces prompt/state files through a pinned run-directory descriptor
  - fails closed without following record-provided prompt paths when the run points outside the repo, any run component or state/prompt file is a symlink/non-regular file, `state.repo_root` mismatches, or the pinned run object/access identity changes through a link, ordinary directory replacement, ownership drift, or mode change
  - tells a parent with an already active legacy child to have that same child re-read the regenerated child prompt before another runner command
  - uses `stop_hook_active` to avoid continuation loops
  - if continuation prompt rendering fails on an active run, it records diagnostics, falls back to a generic continuation prompt, and still blocks
  - every prompt variant preserves the current child terminal status and exact `child_session_id` when it suggests `reconcile-active-run`; an inconsistent terminal state with no nonblank child id produces recovery guidance instead of an unexecutable command
  - if even that fallback prompt builder fails, the hook still blocks with a last-resort prompt; if that builder also fails, it falls through to a static emergency prompt that still carries terminal reconcile instructions
  - the emergency reconcile command uses the absolute path of the currently loaded adapter, so both canonical `skills/waited-delivery-compat` and private `personal_codex/skills/waited-delivery-compat` distributions remain executable
  - if writing that prompt to `stderr` fails, it falls back to the outer fail-open path instead of silently blocking with no message
  - outside the active-run blocking path, unexpected internal errors still record diagnostics and fail-open instead of breaking unrelated sessions

## Hook Diagnostics

- Hook-internal failures are recorded under:
  - `~/.codex/log/waited-delivery-hooks.jsonl`
- Rolling policy:
  - active uncompressed window: `1 MiB x 3`
  - if `WAITED_DELIVERY_HOOK_LOG_MAX_BYTES` is unset, invalid, or non-positive, the adapter falls back to the default `1 MiB` active-file limit instead of degenerating into per-append rotation
  - active files:
    - `waited-delivery-hooks.jsonl`
    - `waited-delivery-hooks.1.jsonl`
    - `waited-delivery-hooks.2.jsonl`
  - when the uncompressed window would exceed `3 MiB`, the oldest rolled file is archived to a unique timestamped name
  - if `zstd` is available, the archive is compressed as:
    - `waited-delivery-hooks-<timestamp>-<unique>-<stem>.jsonl.zst`
  - if `zstd` is unavailable or compression fails, the archive is preserved uncompressed as:
    - `waited-delivery-hooks-<timestamp>-<unique>-<stem>.jsonl`
  - archives older than `7` days are pruned on the next due daily prune pass
- Diagnostic payload includes:
  - `hook_command`
  - `session_id`
  - `cwd`
  - `transcript_path`
  - `permission_mode`
  - `prompt_preview`, retained as `null` for legacy schema compatibility
  - `assistant_preview`, retained as `null` for legacy schema compatibility
  - `error_type`
  - `error_message`
  - `traceback_tail` for non-`UserError` exceptions
- Set `WAITED_DELIVERY_HOOK_DEBUG=1` to also mirror fail-open hook errors to `stderr` during live debugging.
- Prompt and assistant-message content is never written to hook diagnostics,
  including when debug mode is enabled.

## Active-Run Commands

- `prepare-active-run`
  - resolves the target session from the adapter index
  - accepts `--session-id`, `--transcript-path`, or `--prompt-text` as explicit selectors
  - when no CLI selector is provided, prefers host-injected `CODEX_THREAD_ID` as the default parent-session selector
  - auto-selects only when the repo index currently contains exactly one observed session
  - fails safe if `CODEX_THREAD_ID` points at a session the repo index has not observed yet
  - fails safe with an ambiguity error when multiple sessions are present and no selector was provided
  - calls `waited_delivery_bridge.py prepare-live`
  - records the returned `run_dir` as the active run for that session
- `attach-child-active-run`
  - requires `--run-dir` to already belong to one observed session
  - rejects a blank `--child-session-id` without moving the child state to `running`
  - wraps `attach-child-live` while preserving the session metadata already recorded in the index
- `finish-child-active-run`
  - requires `--run-dir` to already belong to one observed session
  - requires every supplied session/run selector to match the same index record
  - requires `--child-session-id` to exactly match the id recorded at attachment, including terminal replays
  - wraps `finish-child-live` after `wait` while keeping the association active for parent-owned review
- `reconcile-active-run`
  - requires `--run-dir` to already belong to one observed session
  - requires `--child-session-id` to exactly match the id recorded at attachment
  - wraps `reconcile-live`
  - clears the active-run association once the run is terminal and reconciled
- `show-index`
  - prints the current adapter index for debugging

## Explicit Compatibility Hook Config

Do not install this configuration as a default or persistent personal hook
surface. Use it only for a bounded compatibility experiment, then remove it.
Replace `<compat-skill-root>` with the absolute path to an explicit checkout of
`skills/waited-delivery-compat` if the hook runtime does not expand shell
variables in command strings.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/python3 <compat-skill-root>/scripts/waited_delivery_hook_adapter.py user-prompt-submit-hook --enable-compat-hook",
            "timeoutSec": 10,
            "statusMessage": "tracking waited-delivery session metadata"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/python3 <compat-skill-root>/scripts/waited_delivery_hook_adapter.py stop-hook --enable-compat-hook",
            "timeoutSec": 10,
            "statusMessage": "checking waited-delivery active run state"
          }
        ]
      }
    ]
  }
}
```

## Current Limitation

The current adapter is now fail-safe for multi-session repos, but it is still not a complete ownership protocol.

If multiple live sessions are steering the same repo concurrently, prefer passing `--session-id` explicitly.
When the host shell provides `CODEX_THREAD_ID`, the adapter now already prefers it over repo-global recency; `--transcript-path` and `--prompt-text` remain useful recovery selectors for older or partial flows.
If stock Codex App integration later exposes a stable way to hand both parent `session_id` and `turn_id` into `prepare-active-run`, that should become the preferred path.
