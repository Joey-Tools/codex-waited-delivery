# Compatibility Hook / Supervisor Bridge

Use this bridge only when an explicit compatibility experiment needs to drive historical `waited-delivery` state without hard-coding runner internals.

## Bridge Script

- [waited_delivery_bridge.py](../scripts/waited_delivery_bridge.py)
- If the user explicitly requests a compatibility hook experiment and hooks are
  already available, use the higher-level adapter documented in
  [hook-adapter.md](hook-adapter.md) with its required
  `--enable-compat-hook` flag.

## Stable Env Contract

The bridge deliberately uses a repo-owned env contract instead of assuming any undocumented Codex hook env names:

- `WAITED_DELIVERY_PARENT_SESSION_ID`
- `WAITED_DELIVERY_PARENT_TURN_ID`
- `WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH`
- `WAITED_DELIVERY_PERMISSION_MODE`

Future hooks or app adapters should translate product-specific metadata into these env vars before calling the bridge.
If a future hook payload exposes only a subset of those fields, the bridge still accepts partial metadata and lets the runner persist what is actually known.
The current outer adapter already follows this rule: it may observe product-specific values such as host-injected `CODEX_THREAD_ID`, but it translates them before calling the bridge rather than teaching the runner about undocumented product env names.

## Commands

- `prepare-live`
  - wraps `waited_delivery_runner.py prepare --json`
  - injects parent metadata from args or env
- `bind-parent-live`
  - patches parent metadata into an existing run when the ids or other outer-adapter metadata become known later
- `attach-child-live`
  - wraps `attach-child`, rejects a blank child id before state mutation, and also propagates parent metadata from args or env
- `refresh-prompts-live`
  - is an internal descriptor-only target for the outer adapter; it refuses an ordinary source-path launch
  - requires inherited bridge and runner snapshot FDs, their complete device/inode, uid/gid/mode, size, and SHA-256 versions, and the separate canonical runner path to publish in regenerated prompts
  - requires Python `-I -B -S`, verifies both inherited descriptors are `O_RDONLY` with `F_GETFL`, proves that the loaded bridge came from the inherited bridge FD, and strips Python environment-injection variables before launching the runner with the same interpreter isolation
  - launches the runner only through the inherited runner FD while forwarding both inherited descriptors; the runner revalidates both complete versions under the run lock immediately before the first prompt/state write
  - validates and returns refresh schema `2` with exact executed bridge/runner paths and versions, both read-only FD attestations, isolated-execution attestation, and regenerated run-local child/parent versions
  - accepts `--expected-repo-root` from the outer adapter so the runner can enforce exact repo containment again under the run-level state lock
  - accepts `--expected-run-dev`, `--expected-run-ino`, `--expected-run-uid`, `--expected-run-gid`, and `--expected-run-mode` only as one complete set, forwards them to the runner, and returns the refreshed identity so the outer adapter can bind one exact directory object and POSIX access identity across the bridge call
  - never falls back to the bridge's or runner's mutable source path; the outer adapter owns source binding, private snapshot creation, prelaunch source revalidation, and cleanup
- `finish-child-live`
  - requires the exact attached `child_session_id` and wraps `finish-child` so the bridge can persist the child's matching terminal status after `wait` and before parent-owned review
- `reconcile-live`
  - requires that same exact child id and wraps `reconcile-parent --json`
- `print-env-contract`
  - prints the current env keys expected by the bridge

## Intended Use

1. A hook or supervisor resolves whichever parent metadata it can reliably observe.
2. It exports those fields as `WAITED_DELIVERY_*`.
3. It calls `prepare-live`.
4. The parent session or adapter spawns the delivery child and calls `attach-child-live`.
5. After `wait` returns, it calls `finish-child-live` with the exact id recorded by `attach-child-live`.
6. The parent forms the committed clean/frozen range and records its review phases.
7. It calls `reconcile-live` with that same exact id only after every phase is terminal.

## Notes

- This bridge does not assume a specific Codex App or Codex CLI hook payload shape.
- Call `refresh-prompts-live` only through the outer adapter's descriptor-bound snapshot launcher. Other bridge commands retain their ordinary source-path CLI behavior.
- If stock App / hooks later expose different metadata names, only the outer adapter should need to change.
- `prepare-live` and `attach-child-live` prefer explicit CLI args over env vars when both are present.
- The bridge remains useful even when an outer hook can only provide `session_id`, `transcript_path`, or `permission_mode` but not a true `turn_id`.
