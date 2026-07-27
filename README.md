# Codex Waited Delivery Compatibility

Historical and experimental child-and-wait delivery workflow tooling retained
for explicit compatibility work and run recovery.

This repository no longer represents an active personal skill. Do not add
`waited-delivery-compat` to a personal-skill link manifest and do not register
its hooks by default. The historical hook commands are inert unless the caller
passes `--enable-compat-hook`, and their diagnostics never record prompt or
assistant-message previews.

The repository retains byte-identical non-skill legacy hook shims at both
`legacy-hook-shims/waited-delivery/scripts/waited_delivery_hook_adapter.py` and
the historical direct-link target
`skills/waited-delivery/scripts/waited_delivery_hook_adapter.py`. Neither
directory has a `SKILL.md`. Direct repository links therefore keep stale hook
registrations fail-open, while aggregate and overlay release tooling can copy
the standalone legacy asset onto the same installed target. Remove that target
only after every host has removed and independently verified the absence of
those registrations.

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the optional review
compatibility/diagnostic dependency used by external lane-readiness smoke.

## Test

```bash
python3 -m py_compile skills/waited-delivery-compat/scripts/*.py
python3 -m unittest discover -s skills/waited-delivery-compat/tests
```
