# Hook / Supervisor Bridge

Use this bridge when future experimental hooks, a local supervisor, or an app-side adapter needs to drive `waited-delivery` without hard-coding runner internals.

## Bridge Script

- [waited_delivery_bridge.py](../scripts/waited_delivery_bridge.py)
- If hooks are already available and you want repo-local session indexing plus a stop gate, prefer the higher-level adapter documented in [hook-adapter.md](hook-adapter.md).

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
  - wraps `attach-child` and also propagates parent metadata from args or env
- `reconcile-live`
  - wraps `reconcile-parent --json`
- `print-env-contract`
  - prints the current env keys expected by the bridge

## Intended Use

1. A hook or supervisor resolves whichever parent metadata it can reliably observe.
2. It exports those fields as `WAITED_DELIVERY_*`.
3. It calls `prepare-live`.
4. The parent session or adapter spawns the delivery child and calls `attach-child-live`.
5. After `wait` returns, it calls `reconcile-live`.

## Notes

- This bridge does not assume a specific Codex App or Codex CLI hook payload shape.
- If stock App / hooks later expose different metadata names, only the outer adapter should need to change.
- `prepare-live` and `attach-child-live` prefer explicit CLI args over env vars when both are present.
- The bridge remains useful even when an outer hook can only provide `session_id`, `transcript_path`, or `permission_mode` but not a true `turn_id`.
