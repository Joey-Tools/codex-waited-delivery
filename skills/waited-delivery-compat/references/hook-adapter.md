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
- every session-index load/mutation/commit uses a descriptor-bound repo-local transaction, while `prepare-active-run` uses two short transactions around bridge work so other commands can observe and respect the durable intermediate reservation
- `prepare-active-run` resolves an unambiguous observed session, persists an exact `preparing` reservation and inherited preparation lease before bridge execution, then CAS-promotes only the same fully-attested run to `active`
- `recover-active-run` reports, resumes, or clears the exact reservation only after descriptor-bound lease evidence proves the cooperating adapter/bridge/runner writer chain is quiescent; an already committed `cleanup_pending` record also supports the final-CAS recovery path after durable lease absence
- `Stop` hook checks that session index and blocks premature finish while the run is active or a `preparing`, `recovery_required`, or `cleanup_pending` recovery fence is present only when its command includes `--enable-compat-hook`
- before rendering an active-run continuation, `Stop` calls `refresh-prompts-live` so both persisted prompts use the currently loaded compatibility runner instead of a removed historical absolute path
- before that refresh, `Stop` opens the repo/run path component-by-component without following links, requires the indexed `run_dir` to be a direct child of the current repo's `.codex-tmp/waited-delivery`, requires exact `state.repo_root` equality, and requires regular no-follow state and prompt files. It accepts either the current user plus mode `0700`, or the exact owned legacy mode `0755`; the latter is tightened to `0700` through the open directory descriptor and revalidated for unchanged device/inode and owner/group before any artifact read. Every other access policy fails closed. It records the resulting run directory's exact device/inode and POSIX uid/gid/mode.
- `Stop` keeps that run descriptor open while refresh runs. It stable-reads both bridge and runner sources, binding each named entry, object identity, uid/gid/mode, size, and two bounded byte reads plus SHA-256 digest, then revalidates both source versions before process launch. It frames those exact bytes with magic, bounded lengths, and digests and sends them through anonymous stdin to a fixed Python `-I -B -S -c` bootstrap after removing Python environment-injection variables. The bootstrap requires exact bytes and EOF before compiling the bridge in memory; the bridge then sends the runner through a separately framed anonymous pipe to another fixed bootstrap. Neither layer creates a regular-file source snapshot, inherits a source descriptor, or falls back to a source path or sibling lookup. The outer refresh process runs in a new session with a seven-second hard deadline, a captured-byte ceiling, and bounded whole-process-group kill/drain/reap. Its selector services source input together with stdout/stderr, classifies an early reader close or incomplete input as terminal `126`, closes the writer before cleanup, and never accepts success before the whole frame is delivered. One deferred `SIGHUP`/`SIGTERM`/`SIGQUIT` transaction remains armed until cleanup finishes and only then restores and redelivers the first terminal signal. On Linux, the protected cleanup property is absence of live same-PGID members that can retain resources or act: a bounded byte-oriented `/proc` scan accepts a proven zombie-only group, including a non-UTF-8 process name, while unreadable, iteration-failed, or parse-ambiguous evidence remains live and fails closed. Under the run lock, the runner revalidates its injected bytes immediately before the first prompt/state write. Refresh schema `3` returns exact bridge/runner source-provenance versions, both `anonymous-pipe-memory` transports, non-reopenability, canonical compile filenames, isolated-execution attestation, and each newly published prompt version. The adapter compares those receipts to its stable-bound versions and rereads state/prompts through the pinned run descriptor before rendering guidance. Timestamp-only churn is deliberately excluded because it changes none of the protected properties. A source replacement, owner/group drift, mode change, or content change observed before launch fails before any prompt/state write, while a source-path A→B→A change after stable binding cannot execute the intermediate object.
- `finish-child-active-run` requires the exact attached child id, records the child's terminal status, and preserves the active-run association for parent-owned review
- `reconcile-active-run` requires that same exact child id and clears the active-run association only when reconciliation finishes cleanly with the required `internal_review` phase and a nonblank attached child identity

This keeps hooks product-facing and lets the bridge remain product-agnostic.

## Session Index

The adapter stores repo-local state under:

- `.codex-tmp/waited-delivery-hook-adapter/index.json`
- `.codex-tmp/waited-delivery-hook-adapter/index.lock`
- `.codex-tmp/waited-delivery-hook-adapter/prepare-<preparation-id>.lease`

The adapter directory is owner-only `0700`; each newly committed index snapshot,
transaction lock, and preparation lease is `0600`. Directory name entries are
descriptor-revalidated and parent-directory-fsynced. The files are opened
descriptor-relative with no-follow semantics. Index reads bind the named entry,
regular-file object identity, owner/access policy, size, and two bounded byte
reads. A changed index is written completely to a verified `0600` sibling
temporary file, fsynced, atomically replaced, and directory-fsynced. Deliberate
inode replacement at commit is expected; following or overwriting an object
outside the adapter directory, exposing a newly persisted prompt through the
umask, partial JSON visibility, and lost cooperative read-modify-write updates
are the protected properties.

Current records are keyed by `session_id` and include:

- `session_id`
- `cwd`
- `transcript_path`
- `permission_mode`
- `last_prompt`
- `run_dir`
- `status`
- `updated_at`
- `preparation_id`
- `preparation_run_id`
- `preparation_lease_path`
- `preparation_started_at`
- `preparation_reason`

Index schema `3` treats `preparing`, `recovery_required`, `cleanup_pending`, and
`cleanup_complete` as explicit recovery records. `cleanup_pending` retains
every reservation field until the exact lease has been descriptor-unlinked and
its adapter parent fsynced; the later exact-record CAS publishes
`cleanup_complete` without discarding that identity. This makes final
replace/fsync/readback/post-commit-revalidation ambiguity recoverable from the
next disk snapshot. A verified tombstone may be superseded by a new exact
reservation, but an old cleanup retry cannot clear that new identity. Frozen
schema-v2 readers reject schema `3` before a write and therefore cannot
reinterpret a cleanup record as active.
The transaction identity remains present after activation so a
replace-then-fsync/readback ambiguity can be resumed idempotently. Schemas `1`
and `2` are decoded as legacy records without inventing transaction
provenance. Every preparing record is preflighted against a projected
`recovery_required` record with the maximum bounded reason, so a near-limit
phase-one commit cannot prevent later recovery fencing or cleanup intent.

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
  - blocks without opening the prospective run or refreshing prompts when the record is `preparing`, `recovery_required`, or `cleanup_pending`, and emits the exact `recover-active-run` command
  - blocks stop with a continuation prompt when the run is still active or not yet reconciled
  - regenerates `child-prompt.md` and `parent-prompt.md` through framed anonymous-pipe bridge and runner source delivery before referring the parent back to either file
  - refuses to launch when either named source changes object identity, access policy, size, or content between its initial stable read and final prelaunch revalidation; timestamp-only changes remain benign
  - executes no bridge or runner source path after stable binding, uses fixed Python `-I -B -S -c` bootstraps with Python injection variables removed, requires exact bounded frames plus EOF and SHA-256, and binds schema `3` receipts to source-provenance versions, both `anonymous-pipe-memory` transports, non-reopenability, and canonical compile filenames
  - supervises that anonymous-pipe-bound refresh in a new session with a seven-second hard timeout, a `256 KiB` combined capture ceiling, and bounded process-group kill/drain/reap; early input rejection or incomplete delivery is terminal `126`; terminal `SIGHUP`, `SIGTERM`, and `SIGQUIT` are deferred until live descendants are gone and pipe ends can be closed; on Linux, proven zombie-only membership is terminal while unknown scan evidence fails closed
  - has the runner revalidate its injected bytes under the run lock immediately before the first prompt/state write, so a bound-content drift failure leaves those persistent artifacts unchanged
  - passes the exact current repo root plus the preflight run-directory device/inode, uid/gid, and mode through the bridge to the runner; the runner revalidates them under its run-level lock and atomically replaces prompt/state files through a pinned run-directory descriptor
  - accepts an exact owned legacy mode `0755` run directory only by tightening the already opened object to `0700` and revalidating its identity; fails closed without following record-provided prompt paths when the run points outside the repo, any run component or state/prompt file is a symlink/non-regular file, `state.repo_root` mismatches, or the pinned run object/access identity changes through a link, ordinary directory replacement, ownership drift, or another mode change
  - relies on the ordinary runner's stricter reopen gate before any prompt/state write: repository-side parents, the run, state, child/parent prompts, smoke prompt, and lock must be current-user-owned, reject group/other write, and carry no Darwin extended or Linux POSIX ACL; only the current-user exact `0755` run can be descriptor-tightened before any artifact read
  - keeps a non-discoverable legacy runner redirect available until active pre-rename runs drain, and tells a parent with an already active legacy child to have that same child re-read the regenerated child prompt before another runner command
  - uses `stop_hook_active` to avoid continuation loops
  - if continuation prompt rendering fails on an active run, it records diagnostics, falls back to a generic continuation prompt, and still blocks
  - once an active nonterminal path has successfully rendered a blocking prompt, an index commit or final revalidation failure is recorded but cannot downgrade the hook result from exit `2` to fail-open exit `0`
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

Every index mutation below uses the same descriptor-bound atomic commit and
index-version CAS as the prompt and Stop hooks. `prepare-active-run` does not
hold `index.lock` across bridge work: phase one commits a durable reservation,
the inherited preparation lease spans bridge/runner work, and phase two
reopens the index and verifies the exact reservation before activation.

- `prepare-active-run`
  - resolves the target session from the adapter index
  - accepts `--session-id`, `--transcript-path`, or `--prompt-text` as explicit selectors
  - when no CLI selector is provided, prefers host-injected `CODEX_THREAD_ID` as the default parent-session selector
  - auto-selects only when the repo index currently contains exactly one observed session
  - fails safe if `CODEX_THREAD_ID` points at a session the repo index has not observed yet
  - fails safe with an ambiguity error when multiple sessions are present and no selector was provided
  - replaces an existing association only when its direct repo-local run path, access policy, state, prompts, repo root, and terminal status pass descriptor-bound no-follow validation
  - rejects another pending preparation for the session or the same run path reserved by another session
  - validates the complete prospective schema `3` reservation and worst-case recovery-reason capacity before creating its owner-private `0600` lease
  - commits `preparing` before calling `waited_delivery_bridge.py prepare-live`, and passes the locked lease descriptor plus a stable preparation UUID through bridge to runner
  - requires the bridge receipt to return the exact reserved `run_dir`, preparation UUID, and runner lease-inheritance attestation
  - validates the reserved run directory and preparation-aware schema `4` or `5` state/prompt artifacts through pinned no-follow descriptors, including exact repo root, run ID, parent session, and preparation UUID; current writes use schema `5`, while schema `4` remains recovery-readable
  - CAS-promotes only the unchanged reservation to `active`, revalidates the run after commit, and removes the exact lease before emitting success JSON
  - on bridge failure, retires its original inherited lease reference exactly once, then independently reopens and nonblocking-locks the lease; a busy or close-ambiguous lease remains `recovery_required` without any run-entry read
  - for a quiescent unchanged reservation whose exact run entry is descriptor-proven absent, CAS-commits `cleanup_pending` with the complete reservation intact, descriptor-unlinks only the exact lease and fsyncs the adapter parent, and then exact-record-CAS-publishes a full-identity `cleanup_complete` tombstone; present, partial, mismatched, or unprovable results remain recovery-fenced
- `recover-active-run`
  - requires exact `--session-id` and `--preparation-id`
  - defaults to `--action doctor`; a busy inherited lease returns `in_progress` without inspecting changing run artifacts
  - reports quiescent states as `absent`, `partial_or_untrusted`, `complete_not_activated`, or `active`; cleanup recovery distinguishes a present lease, `cleanup_pending_final_cas` after durable lease absence, and a verified `cleanup_complete` tombstone
  - `--action resume` validates a complete same-transaction run and idempotently CAS-promotes it to `active`
  - `--action clear-absent` either acquires the still-present lease and re-proves absence, accepts a previously committed `cleanup_pending` record with descriptor-proven lease absence, or idempotently confirms the exact `cleanup_complete` tombstone; it preserves the full reservation through lease unlink, fsyncs and revalidates the adapter parent even when recovering an already absent lease, and finalizes only by a full-identity CAS
  - never deletes, recursively cleans, follows, or adopts an unattested run directory
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

## Recovery Boundaries

The index, lease, and run tree are separate durable objects rather than one
filesystem transaction. Their created directory entries are parent-fsynced,
but the durable reservation still makes intermediate states visible and
recoverable instead of making multi-file run creation atomic. The lease proves
quiescence only for cooperating adapter/bridge/runner descendants that
inherited it. Bridge-failure settlement first closes the adapter's original
open-file-description reference and then requires a separately opened lease to
acquire the lock; otherwise an inherited descendant can remain invisible behind
the adapter's own lock. It does not exclude arbitrary same-UID writers, root,
`ptrace`, debugger, or process-memory attacks, and no timestamp or PID is used
to steal a busy lease.

Absence is a descriptor-bound point-in-time observation. A missing, replaced,
unreadable, incomplete, or transaction-mismatched run is never automatically
deleted or promoted. A bridge receipt that names another path is not followed.
Absent cleanup deliberately spans two durable commits around lease unlink:
`cleanup_pending` is the crash-recovery proof that writer quiescence and run
absence were established while the complete reservation still existed. A
crash before unlink leaves the exact lease available for recovery; a crash
after unlink leaves descriptor-proven absence plus the full pending record for
the final CAS. The absent-lease recovery path fsyncs and revalidates the adapter
parent before attempting that CAS. Its terminal `cleanup_complete` result still
contains the exact reservation, so a CAS that reached `os.replace` but later
reported fsync, readback, or revalidation uncertainty is safe to retry from
disk. Concurrent observation updates make the CAS fail without discarding
either the observation or reservation. A later new preparation can supersede
only that exact verified tombstone; the old preparation ID then fails closed.
If index publication is externally replaced after phase one, the adapter
cannot reconstruct provenance from an orphaned directory. A stale verified
lease may remain after an ambiguous index commit; same-transaction `resume`
cleans it after proving the run is active. This recovery surface preserves
evidence and availability, not automatic disk-space reclamation.

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
