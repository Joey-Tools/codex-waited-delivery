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
- every Stop/reconcile state load accepts runner state schema `1`, `2`, `3`, `4`, or `5` only; a boolean, missing, malformed, or future schema fails closed before the state can authorize guidance or index cleanup
- every trusted adapter path applies one descriptor-bound access-policy gate: the repository root, `.codex-tmp`, adapter directory, index, lock, preparation lease, runs root, run, state/prompts, and bridge/runner source parents and files must be owned by the current user, reject group/other write, and carry no Darwin extended or Linux POSIX ACL. The held descriptors are revalidated at the corresponding commit, read, or launch boundary.
- before prompt refresh, `Stop` opens the repo/run path component-by-component without following links, requires the indexed `run_dir` to be a direct child of the current repo's `.codex-tmp/waited-delivery`, requires exact `state.repo_root` equality, and requires regular no-follow state and prompt files. It accepts either the current user plus mode `0700`, or the exact owned legacy mode `0755`; the latter is tightened to `0700` through the open directory descriptor and revalidated for unchanged device/inode, owner/group, mode, and ACL policy before any artifact read. Every other access policy fails closed. It records the resulting run directory's exact device/inode and POSIX uid/gid/mode.
- every adapter-to-bridge command—prepare, parent binding, child attachment, child finish, parent reconciliation, and prompt refresh—stable-reads both bridge and runner sources, binds each named entry, object identity, uid/gid/mode, ACL policy, size, and two bounded byte reads plus SHA-256 digest, and revalidates both versions before process launch. It frames those exact bytes with magic, bounded lengths, and digests and sends them through anonymous stdin to a fixed Python `-I -B -S -c` bootstrap after removing Python environment-injection variables. The bootstrap requires exact bytes and EOF before compiling the bridge in memory; the bridge sends the already bound runner bytes through a separately framed anonymous pipe to another fixed bootstrap. Neither layer creates a regular-file source snapshot, inherits a source descriptor, path-executes, reopens a source, or falls back to sibling lookup.
- before any runner fallback, adapter bridge, or subprocess-test selector, pipe, or `Popen`, a native `sigaction(SIGCHLD)` attestation requires both the Python and native handlers to be default and rejects `SA_NOCLDWAIT`. The reviewed `Popen` finalizer contract requires CPython. Darwin uses its public `struct sigaction`; Linux is supported only for the reviewed LP64 glibc `x86_64-linux-gnu` and `aarch64-linux-gnu` layouts. Another Python implementation, musl, an unknown machine/multiarch/layout, native-query failure, unsupported platform, or missing observer primitive fails closed before libc process operations or launch. Linux also requires `waitid`; Darwin requires `kqueue` with `NOTE_EXIT` and the required filter/flag constants. The child-specific observer is bound only after launch and then keeps the leader unreaped while cleanup may still signal the group.
- `SIGCHLD` disposition is process-global and cooperating code must not mutate it during one supervised transaction. The supervisor re-attests immediately before `Popen`, after launch and observer registration, and before each status observation, numeric PID/PGID signal or probe, and final reap. A whole-group scan re-attests immediately before Darwin's PID-list call and every individual `proc_pidinfo`, or before every numeric Linux `/proc/<pid>/stat` read; it never relies on one attestation for the complete scan. Once a post-launch check or wait-status operation reports identity loss, that transaction latches the loss: it performs no later numeric PID/PGID operation, closes owned pipes, performs no direct-child wait, poll, or reap because the numeric PID may already have been reused, and treats status as unavailable. A transient A→B→A disposition change therefore fails the current scan at B and cannot resume at the restored A state. Before any reference can be released, it verifies the impossible POSIX return-code sentinel `sys.maxsize` as the core numeric-identity barrier; on reviewed CPython this prevents later `poll`, `wait`, or `Popen.__del__` from reaching `waitpid`. It separately retries clearing `_child_created` and retaining the strong `Popen` object as recovery evidence, and reports whether each secondary action succeeded. A Darwin `kqueue` remains locally owned until observer binding succeeds; every constructor failure closes it without allowing a cleanup failure to mask the primary exception.
- any exception from an after-spawn native re-attestation, including `KeyboardInterrupt` or another `BaseException`, is wrapped as permanent identity loss while preserving its cause. Python 3.9 and current-Python CI exercise the real CPython `Popen.__del__` behavior. If the sentinel cannot be verified after bounded retries, the supervisor permanently pins the object by deliberately leaking one CPython `Py_IncRef`; if both pin attempts fail, `_exit(70)` fail-stops without running Python finalizers. Recovery-list retention is separately retried and reported, but numeric-identity safety does not depend on that list.
- Linux observes leader exit with `waitid(P_PID, pid, WEXITED | WNOHANG | WNOWAIT)`. Darwin observes the leader with a one-shot `kqueue` `NOTE_EXIT` event and proves group membership through `/usr/lib/libproc.dylib`. `proc_listpgrppids` receives a PID array plus that array's byte size but returns a PID count; negative, capacity-equal/full-buffer, deadline-expired, or zero-with-errno results are unknown. The code clears `errno` before the list call and before every `proc_pidinfo(pid, 3, 1, ...)`, reads it after a zero result, and requires a full `_DarwinProcBSDInfo` plus matching PID/PGID. Status `5` is zombie; another status is live, except that the exact `kqueue`-attested, still-unreaped known leader may ignore a temporarily stale non-`5` status only after that complete structural and identity match. That exception never applies to a same-group descendant or an unattested PID. Every zero-size result, including `ESRCH` for that known leader, and every short result, unexpected disappearance, ABI/identity mismatch, exception, or other error is unknown and fails closed.
- if child-specific observer binding fails after `Popen` while the leader fence is still attested, emergency cleanup establishes one absolute deadline before attempting `SIGKILL`; the same remaining budget covers nonblocking stdout/stderr drain, whole-group proof, and bounded reap. It never resets the deadline between phases. If pipe registration/drain, group proof, or reap does not complete, it does not reap and retains the strong `subprocess.Popen` object in the recovery set, preserving the leader PID/PGID identity together with signal error, last group state, and open-pipe evidence. A completed path reaps only after pipes are drained and the group is zombie-only or absent; no later signal or group probe may run after that reap. If the fence is already lost, the latched identity-loss path above replaces this group cleanup entirely.
- each successfully bound adapter bridge subprocess starts a new session with a hard runtime deadline, a captured-byte ceiling, and bounded whole-process-group cleanup. The refresh selector additionally services source input together with stdout/stderr, classifies an early reader close or incomplete input as terminal `126`, closes the writer before cleanup, and never accepts success before the whole frame is delivered. One deferred `SIGHUP`/`SIGTERM`/`SIGQUIT` transaction remains armed until cleanup finishes and only then restores and redelivers the first terminal signal.
- under the run lock, the runner revalidates its injected bytes immediately before the first prompt/state write. Refresh schema `3` returns exact bridge/runner source-provenance versions, both `anonymous-pipe-memory` transports, non-reopenability, canonical compile filenames, isolated-execution attestation, and each newly published prompt version. The adapter compares those receipts to its stable-bound versions and rereads state/prompts through the pinned run descriptor before rendering guidance. Timestamp-only churn is deliberately excluded because it changes none of the protected properties. A source replacement, owner/group drift, mode or ACL change, or content change observed before launch fails before any prompt/state write, while a source-path A→B→A change after stable binding cannot execute the intermediate object.
- `finish-child-active-run` requires the exact attached child id, records the child's terminal status, and preserves the active-run association for parent-owned review
- `reconcile-active-run` requires that same exact child id and pre-binds the no-follow run descriptor, full run identity, no-follow owner-private `.state.lock` object without holding it, initial `state.json` receipt, indexed run ID, parent session, preparation transaction, attached child ID, and requested terminal status before starting `reconcile-live`. Runner JSON must return the exact previous and newly published state versions plus the same run identity. After the bridge releases its lock, the adapter acquires that same pinned lock object, compares the previous receipt to its initial descriptor read, compares the published receipt to its post-call descriptor read, and rereads the same object constrained to that published version and semantic binding. It keeps the lock until the descriptor-bound index transaction has actually published and revalidated its atomic replacement. The atomic publisher invokes the complete named run/lock/state guard immediately before `os.replace` and again after durable index readback. Once replacement is attempted, an exception first descriptor-classifies the visible entry as the exact previous snapshot, the exact prepared publication, or neither; the second case restores the previous bytes or absence, while the third requires manual recovery. Failures after a returned replacement—including directory fsync, published readback, the post-publication guard, and transaction-final directory/lock revalidation—must restore through a sibling recovery file whose complete prepared device/inode/uid/gid/mode/size/digest version is matched after replacement. An unproved recovery reports `manual_recovery_required=true` plus previous/published snapshot digests and never returns success. This claim ends at transaction-final revalidation and does not treat later descriptor-close or unlock cleanup as part of the publication receipt. It clears the active-run association only when the locked exact final object/version is terminal, finishes cleanly with the required `internal_review` phase and nonblank child identity, and matches the runner's returned overall/child fields.

This keeps hooks product-facing and lets the bridge remain product-agnostic.

## Session Index

The adapter stores repo-local state under:

- `.codex-tmp/waited-delivery-hook-adapter/index.json`
- `.codex-tmp/waited-delivery-hook-adapter/index.lock`
- `.codex-tmp/waited-delivery-hook-adapter/prepare-<preparation-id>.lease`

The repository root, `.codex-tmp`, and adapter directory are current-user-owned
directories with no group/other write and no Darwin extended or Linux POSIX
ACL; the adapter directory is exact `0700`. Each newly committed index
snapshot, transaction lock, and preparation lease is a current-user-owned
`0600` regular file with the same ACL exclusion. Directory name entries are
descriptor-revalidated and parent-directory-fsynced. The files are opened
descriptor-relative with no-follow semantics. Index reads bind the named
entry, regular-file object identity, owner/access/ACL policy, size, and two
bounded byte reads. A changed index is written completely to a verified `0600`
sibling temporary file, fsynced, atomically replaced, and directory-fsynced;
the parent and final named object are descriptor-revalidated. Deliberate inode
replacement at commit is expected; following or overwriting an object outside
the adapter directory, accepting a writable or ACL-extended trust boundary,
exposing a newly persisted prompt through the umask, partial JSON visibility,
and lost cooperative read-modify-write updates are the protected properties.

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
  - accepts runner state schemas `1` through `5` only and fails closed on a boolean, missing, malformed, or future schema
  - regenerates `child-prompt.md` and `parent-prompt.md` through framed anonymous-pipe bridge and runner source delivery before referring the parent back to either file
  - refuses to launch when either named source changes object identity, access policy, size, or content between its initial stable read and final prelaunch revalidation; timestamp-only changes remain benign
  - executes no bridge or runner source path after stable binding, uses fixed Python `-I -B -S -c` bootstraps with Python injection variables removed, requires exact bounded frames plus EOF and SHA-256, and binds schema `3` receipts to source-provenance versions, both `anonymous-pipe-memory` transports, non-reopenability, and canonical compile filenames
  - supervises that anonymous-pipe-bound refresh in a new session with a seven-second hard timeout, a `256 KiB` combined capture ceiling, and bounded process-group kill/drain/reap; Linux `waitid(..., WNOWAIT)` or Darwin `kqueue` `NOTE_EXIT` observes the leader without reaping it until pipes drain and live group membership is absent; Darwin `libproc` distinguishes live, zombie-only, and absent groups, while unknown evidence fails closed; early input rejection or incomplete delivery is terminal `126`; terminal `SIGHUP`, `SIGTERM`, and `SIGQUIT` are deferred until cleanup completes
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
  - commits `preparing` before launching stable-bound bridge and runner bytes for `prepare-live` through the isolated two-frame Python `-I -B -S -c` chain, and passes the locked lease descriptor plus a stable preparation UUID through bridge to runner
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
  - runs `attach-child-live` from the same stable-bound bridge/runner bytes while preserving the session metadata already recorded in the index
- `finish-child-active-run`
  - requires `--run-dir` to already belong to one observed session
  - requires every supplied session/run selector to match the same index record
  - requires `--child-session-id` to exactly match the id recorded at attachment, including terminal replays
  - runs `finish-child-live` from the same stable-bound bridge/runner bytes after `wait` while keeping the association active for parent-owned review
- `reconcile-active-run`
  - requires `--run-dir` to already belong to one observed session
  - requires `--child-session-id` to exactly match the id recorded at attachment
  - opens and pins the run, the no-follow owner-private `.state.lock` object without holding it, and the initial `state.json` identity/access/content receipt before bridge launch, then binds run/session/preparation/child semantics to the selected index record
  - runs `reconcile-live` from the same stable-bound bridge/runner bytes
  - requires runner JSON to bind the same run identity and return both the exact previous state receipt and exact newly published state receipt
  - after the bridge releases `.state.lock`, acquires the same pinned lock object, validates those receipts against the initial and post-call descriptor reads, repeats the semantic binding and final exact-version reread, and holds the lock through atomic index publication
  - runs the complete named run/lock/state guard immediately before `os.replace` and after durable index readback; pre-publication failure is no-publish, while post-publication failure must restore and read back the exact prior index or report manual recovery
  - clears the active-run association only for that locked unchanged terminal object/version
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
