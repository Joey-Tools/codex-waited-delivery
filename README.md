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

State updates serialize completely before atomic publication. A serialized
state of exactly `4 MiB` is accepted; any larger payload is rejected before a
temporary name is allocated or a file is created or replaced, leaving the
previous descriptor-bound state unchanged and recoverable.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -m py_compile skills/waited-delivery-compat/scripts/*.py
python3 -m unittest discover -s skills/waited-delivery-compat/tests
```
