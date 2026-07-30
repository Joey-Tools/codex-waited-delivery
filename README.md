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
`waited-delivery-compat` runner: it stable-reads the source, transfers those
exact bytes through a one-shot anonymous pipe to an isolated fixed bootstrap,
and compiles them in memory instead of creating or reopening a filesystem
snapshot. An active pre-rename child can therefore complete even before the
Stop hook regenerates its prompt. Neither directory has a `SKILL.md`, so these
paths are not discoverable skills. Aggregate and overlay release tooling can
copy the standalone legacy asset onto the same installed target. Remove that
target only after every host has independently verified both the absence of
stale hook registrations and the drain of active pre-rename runs.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -m py_compile skills/waited-delivery-compat/scripts/*.py
python3 -m unittest discover -s skills/waited-delivery-compat/tests
```
