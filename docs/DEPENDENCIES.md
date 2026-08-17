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

### Bootstrap and trusted-harness promotion

The initial bootstrap is not self-authorizing. While no earlier enforced
trusted generation exists, a run of this leaf is not promotion evidence for
the leaf or its trusted harness. Before the first router/ruleset activation,
an independent formal review must cover the exact immutable bootstrap revision
selected for publication. That review is a prerequisite for repository-side
promotion only; it does not activate or claim activation of the external router
or ruleset.

After bootstrap, an ordinary candidate run validates the candidate only
against the harness generation selected by the caller. It must not promote
changes to `.github/workflows/required-ci.yml` or any path in the complete
`skills/waited-delivery/tests/` trusted-harness namespace. Such changes require
a protected two-stage promotion: first, independent review and admission of
the exact new harness revision; second, a separately authorized external change
that makes the central router/ruleset consume that admitted revision and
independently verifies enforcement. Until both stages complete, a candidate
green result is compatibility evidence only.

### Trusted source and bytecode boundary

The formal harness captures the complete active test namespace through one
held tests-root descriptor. Every selected source must remain the same
single-link ordinary object, keep the same permissions and ownership, and
produce the same complete bytes across two bounded reads and a second full
namespace capture. Object identity, source content, and access policy are the
protected properties; `mtime` and `ctime` changes alone are benign metadata
transitions and are not treated as mutations.

Every namespace enumeration independently enforces the 256-entry bound, and
the descriptor walk retains its eight-level depth bound. Each captured file is
limited to 2 MiB and the complete captured source set is limited to 16 MiB.
Cross-root validation derives the expected candidate leaf set before reading
candidate content, so an unexpected leaf is metadata evidence to reject rather
than an authorization to read more source.

Before a supported formal checkout is captured, the harness opens the trusted
and candidate checkout roots without following links, verifies their selected
directory identity, runner ownership, and ACL state, and fixes their mode to
`0700` through the held descriptors. Those prepared root descriptors remain
open through the complete namespace capture, and the tests-root descriptor is
opened component by component from the held trusted-root descriptor instead
of reopening the checkout root by path. Before the root descriptors close, the
harness revalidates their descriptor and path bindings, the complete component
chain, and the root ACL state. Every later strict boundary check is verify-only
and idempotent; it cannot change a mode after a commitment has been formed.
Namespace capture returns the binding of its held tests-root descriptor to its
caller, which must match both the enclosing descriptor chain and the final path
lookup. Both the repository root path and repository directory binding are
included in each control-plane commitment.

The supervisor starts its child from the already captured supervisor bytes,
not by asking Python to reopen the supervisor path. It stages those bytes in
an owner-private, read-only file, unlinks the file, passes only its descriptor,
and uses a fixed isolated bootstrap to verify the descriptor binding, length,
and SHA-256 before compiling the bytes. The parent freezes the launch authority
and test-suite snapshot before any isolation callback can run. A canonical
formal run reuses one parent-held authorized snapshot for both roles; the local
fixture instead uses a pre-yield private-copy launch authority whose supervisor
and support bytes must exactly match the already loaded parent sources.

The same bootstrap verifies a second unlinked descriptor containing a bounded,
canonical bundle derived from the parent-captured suite snapshot. The child
verifies both commitments, reconstructs that snapshot, and compiles the test
modules directly from its captured source bytes in memory. The original tests
root is used only for before-and-after revalidation: test loading never reopens
its source paths or consumes adjacent bytecode. Captured support bytes are
injected before support execution and are the only formal support source; the
support module must consume those exact bytes. An ordinary direct support
import uses the same no-follow, nonblocking, double-read descriptor policy
instead of a bare path read.

The captured workflow module receives an immutable, validated source row for
every active test module. Test fixtures that must execute or copy harness code
use those rows rather than the logical original paths. When an operating-system
helper requires a filename, the harness writes the captured support bytes to a
fresh owner-private staging directory, verifies its ordinary-file binding and
content before and after use, and then destroys that private stage. The trusted
`TextTestRunner.run` bound method is also captured before any test module is
executed, so module top-level code cannot replace the runner and forge an exact
test count.

Captured test and support modules retain an in-memory source loader and a
captured `linecache` entry, and the fixed child bootstrap seeds that same cache
before compiling the captured supervisor. Introspection, including an explicit
`InspectLoader.get_source` lookup, and both import-time and later tracebacks use
the committed bytes instead of reopening the logical filename. On one selected
filesystem side, the precheck, opened descriptor, final path lookup, and loaded
support binding must identify the same ordinary object and access policy. The
stable reader performs parent checks before its final descriptor and path
lookups, leaving the final path binding as its last filesystem observation;
strict support revalidation must also equal the initially loaded support
binding. A private-copy boundary compares source bytes, digest, schema, and
access policy, but deliberately does not compare device or inode identities
across copies.

Once execution baselines exist, test failures, child failures, timeouts, and
cleanup failures do not skip terminal integrity checks. Every launch, inventory,
trusted namespace, candidate namespace, candidate binding, and import-path
revalidation still runs in its fixed order; combined reports preserve the
primary failure first and then each independently observed integrity failure.
Each rendered detail applies its head-and-tail bound directly, so a later slice
cannot silently discard the diagnostic tail. Structure validation applies the
same rule to its primary result, both control-plane snapshots, and the candidate
binding.

The documented ordinary discovery command creates a fresh owner-private
absolute bytecode-cache prefix outside the checkout, passes it with Python's
`-X pycache_prefix`, and disables bytecode writes with `-B`. It therefore does
not consume, write, rename, or temporarily hide repository `__pycache__`
artifacts. Local formal fixtures run from a private control-plane copy, while a
formal entry continues to reject any cache artifact inside its trusted source
namespace. The ordinary `Run tests` step in `.github/workflows/ci.yml` is locked
to that exact documented discovery command rather than a second, weaker test
entrypoint.

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
