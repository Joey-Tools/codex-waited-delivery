# Codex Waited Delivery Compatibility

Historical and experimental child-and-wait delivery workflow tooling retained
for explicit compatibility work and run recovery.

This repository no longer represents an active personal skill. Do not add
`waited-delivery-compat` to a personal-skill link manifest and do not register
its hooks by default. The historical hook commands are inert unless the caller
passes `--enable-compat-hook`, and their diagnostics never record prompt or
assistant-message previews.

The repository retains byte-identical non-skill legacy assets at both
`legacy-hook-shims/waited-delivery/scripts/` and the historical direct-link
target `skills/waited-delivery/scripts/`. The hook adapter remains inert and
fail-open. The runner is a fixed in-memory redirect to the packaged
`waited-delivery-compat` runner: it nonblocking-opens and stable-reads the
source, rejects a non-regular object without waiting for a FIFO writer,
transfers those exact bytes through a one-shot anonymous pipe to an isolated
fixed bootstrap, and compiles them in memory instead of creating or reopening
a filesystem snapshot. An active pre-rename child can therefore complete even
before the Stop hook regenerates its prompt. Neither directory has a
`SKILL.md`, so these paths are not discoverable skills. Aggregate and overlay
release tooling can copy the standalone legacy asset onto the same installed
target. Remove that target only after every host has independently verified
both the absence of stale hook registrations and the drain of active
pre-rename runs.

Dirty-file discovery reads `git status --porcelain=v1 -z` as bytes, validates
its NUL framing, and retains both paths from rename/copy records. Filesystem
`surrogateescape` decoding preserves non-UTF-8 path bytes in state JSON.
Human-facing paths keep ordinary printable Unicode readable but use one
unambiguous grammar for backslashes, Markdown backticks, leading/trailing
spaces, undecodable bytes, and every Unicode control, format, line-separator,
or paragraph-separator character. Each rendered path is at most `512` UTF-8
bytes. A reserved, input-unforgeable `⟦truncated;...⟧` token records identity
kind, byte length, and SHA-256: filesystem-encodable paths bind exact
`os.fsencode()` bytes, while strings containing non-surrogateescape surrogates
or otherwise rejected by the filesystem codec use an explicitly labeled,
stable `utf8-surrogatepass` identity.

State updates serialize completely before atomic publication. The hard ceiling
accepts a fully serialized terminal state of exactly `4 MiB`; any current state
or required terminal projection above that ceiling is rejected before a
temporary name is allocated or a file is created or replaced, leaving the
previous descriptor-bound state unchanged and recoverable. Every nonterminal
state update reserves enough space for that worst-case terminal projection: an
encoded worst-case child session ID, child-start timestamp, bounded late-bound
parent metadata, interrupted child, decision-point closure of every open
phase, mandatory terminal timestamps, and the derived overall status. Child
session IDs are capped at `1024` UTF-8 bytes and `6146` JSON-value bytes;
late-bound parent metadata is likewise bounded and projected. Child
attachment, child finish, and parent reconciliation construct one timestamped
candidate and validate its encoded size before publishing a summary or
terminal state. Prompt refresh likewise binds its canonical prompt paths into
a candidate and validates the candidate before replacing either prompt. State
schema `5` records exact SHA-256/UTF-8/JSON identities only for oversized text
loaded from schema `1` through `4`: an unchanged legacy child ID or parent
metadata value can still pass phase, finish, reconciliation, and finalization,
while any new or changed oversized value fails closed.

Runner `prepare` now constructs the complete prospective state, worst-case
terminal projection, and every initial UTF-8 artifact before opening or
creating the run path. An over-limit state, invalid explicit/automatic run ID,
or unencodable prompt therefore emits no success payload and leaves the run
tree untouched. Once creation begins, each parent/name entry is descriptor
revalidated and parent-directory-fsynced before artifact publication, so a
successful receipt does not outrun run-tree name durability.

Every ordinary runner reopen walks the repository, `.codex-tmp`,
`waited-delivery`, and run entries descriptor-relative with no-follow
semantics. The repository-side directories must be current-user-owned, reject
group/other write bits, and carry no Darwin extended or Linux POSIX ACL. A run
must be `0700`; only an exact current-user-owned legacy `0755` run can be
tightened through its already-open descriptor to `0700`, with object,
owner/group, mode, and ACL policy revalidated before any artifact read.
State, child/parent prompts, the smoke prompt, and the run lock must be
current-user-owned regular files with no group/other write and no named or
extended ACL. Before fallback-smoke `Popen`, the runner revalidates the bound
run, lock, state, and prompt versions; a missing, replaced, unreadable,
content-changed, or access-policy-changed object fails before process start.

The hook adapter applies the same access-policy property to every object it
trusts: the repository root, `.codex-tmp`, adapter directory, index, lock,
preparation lease, runs root, run directory, state and prompt artifacts, and
the bridge/runner source parent directories and files must be owned by the
current user, reject group/other write, and carry no Darwin extended or Linux
POSIX ACL. No-follow descriptor walks bind each parent, name entry, and opened
object; policy is revalidated on the held descriptors at the operation's
commit or launch boundary.

Every adapter-to-bridge operation—prepare, parent binding, child attachment,
child finish, parent reconciliation, and prompt refresh—stable-binds the
bridge and runner source objects and exact bytes before launch. The adapter
then sends a bounded two-source frame to a fixed Python `-I -B -S -c`
bootstrap, which compiles the bridge in memory; that bridge sends the already
bound runner bytes through a second bounded frame to another isolated
bootstrap. Adapter-driven execution never path-executes or reopens either
source after binding.

Runner fallback smoke, adapter bridge supervision, and the subprocess test
support keep the process-group leader unreaped while cleanup is still allowed
to signal its group. Linux observes leader exit with `waitid(..., WNOWAIT)`;
Darwin uses `kqueue` `NOTE_EXIT`. The leader is reaped only after output pipes
are drained and the group is proven to have no live members, so its numeric
PGID cannot be recycled before the last group signal. Darwin classifies
live, zombie-only, and absent groups through `libproc`; unknown evidence fails
closed.

`prepare-active-run` uses a durable two-phase reservation instead of keeping
one index transaction open across the bridge. Phase one writes an index-schema
`3` `preparing` record with the exact session, run ID/path, preparation UUID,
and owner-private preparation-lease path; it also reserves bounded capacity
for a later recovery reason. The locked lease descriptor is inherited by the
bridge and runner, so recovery cannot treat an absent path as quiescent while a
cooperating descendant may still create it. Runner state schema `5` attests
the same preparation UUID while schema `4` remains recovery-readable. Only an
exact bridge receipt plus descriptor-bound
state/prompt validation can CAS that same record to `active`. Bridge or final
commit failures emit no success payload. After bridge failure, the adapter
retires its original inherited lease reference exactly once, then uses a
separate open and nonblocking lock acquisition to prove the descendant chain
is quiescent; a busy or ambiguous lease is fenced without reading the run
entry. A proven quiescent absent entry first CAS-transitions to
`cleanup_pending` while retaining the complete reservation, then removes only
the descriptor-bound lease and fsyncs its adapter parent, and only then uses a
second exact-record CAS to publish the full-identity cleanup tombstone. Recovery handles both
a still-present cleanup lease and an already-absent lease whose final CAS
remains pending. That CAS publishes `cleanup_complete` without deleting the
exact reservation identity, so replace/fsync/readback/revalidation uncertainty
is idempotently recoverable from disk; a later new preparation may supersede
the tombstone under its own exact CAS, and an old retry cannot clear it. The
already-absent path fsyncs and revalidates the adapter parent again before that
final CAS. Schema-v2 clients reject schema `3` before mutation rather than
misreading `cleanup_pending` as active. Any present, partial, mismatched, tampered,
or unprovable run remains recovery-fenced. An existing indexed run is likewise
retired only after descriptor-bound terminal-state validation. Use
`recover-active-run` with `doctor`, `resume`, or `clear-absent`; no recovery
path recursively deletes a run directory. `reconcile-active-run` also reloads
and validates the terminal reconciled state through its pinned run-directory
descriptor after the bridge returns; only that exact state may authorize
clearing the index association.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -m py_compile skills/waited-delivery-compat/scripts/*.py
python3 -m unittest discover -s skills/waited-delivery-compat/tests
```

CI runs the compatibility suite on both Ubuntu and macOS with Python `3.9`
and the current supported Python.
