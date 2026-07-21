# Hook Adapter

Use the hook adapter when `waited-delivery` needs to cooperate with verified Codex hook events instead of only with manual bridge commands.

## Adapter Script

- [waited_delivery_hook_adapter.py](../scripts/waited_delivery_hook_adapter.py)

## Responsibilities

The adapter adds one layer above the bridge:

- `UserPromptSubmit` hook records the current session metadata in a repo-local session index
- `prepare-active-run` resolves an unambiguous observed session and binds it to a new `run_dir`
- `Stop` hook checks that session index and blocks premature finish while the run is still active
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

- `user-prompt-submit-hook`
  - reads payload JSON from stdin
  - resolves the repo root from `cwd`
  - records the current session metadata into the adapter index
  - returns `{}` on success
- `stop-hook`
  - reads payload JSON from stdin
  - looks up the active `run_dir` for the current `session_id`
  - allows stop if no active run exists
  - blocks stop with a continuation prompt when the run is still active or not yet reconciled
  - uses `stop_hook_active` to avoid continuation loops
  - if continuation prompt rendering fails on an active run, it records diagnostics, falls back to a generic continuation prompt, and still blocks
  - every prompt variant preserves the current child terminal status and exact `child_session_id` when it suggests `reconcile-active-run`; an inconsistent terminal state with no nonblank child id produces recovery guidance instead of an unexecutable command
  - if even that fallback prompt builder fails, the hook still blocks with a last-resort prompt; if that builder also fails, it falls through to a static emergency prompt that still carries terminal reconcile instructions
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
- Current diagnostic payload includes:
  - `hook_command`
  - `session_id`
  - `cwd`
  - `transcript_path`
  - `permission_mode`
  - `prompt_preview`
  - `assistant_preview`
  - `error_type`
  - `error_message`
  - `traceback_tail` for non-`UserError` exceptions
- Set `WAITED_DELIVERY_HOOK_DEBUG=1` to also mirror fail-open hook errors to `stderr` during live debugging.

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

## Example Hook Config

Replace `<expanded-home>` with the current user's absolute home path before installing this JSON if the hook runtime does not expand shell variables in command strings.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/python3 <expanded-home>/.codex/skills/waited-delivery/scripts/waited_delivery_hook_adapter.py user-prompt-submit-hook",
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
            "command": "/usr/bin/python3 <expanded-home>/.codex/skills/waited-delivery/scripts/waited_delivery_hook_adapter.py stop-hook",
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
