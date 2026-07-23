# Compatibility Terminal Outcomes

Use these labels consistently when the delivery child returns control to the parent:

- `passed`
- `failed`
- `blocked`
- `unavailable`
- `decision_point`

## Meanings

- `passed`: the gate completed successfully.
- `failed`: the gate completed and found a concrete problem that must be fixed before a clean delivery result exists.
- `blocked`: the gate could not proceed because a required dependency or prerequisite was missing, misconfigured, or currently refusing execution.
- `unavailable`: the requested gate is not runnable in the current environment, and the run already exhausted the bounded retries that could have made it available.
- `decision_point`: the child reached the furthest responsible stopping point and needs the user to choose whether to proceed with a known gap.

## Notes

- `inconclusive` is not a terminal outcome.
- Intermediate reviewer output is not a terminal outcome.
- "Still streaming" is not a terminal outcome.
- If a review lane never emits a final message, convert that state into either `blocked`, `unavailable`, or `decision_point` after bounded retries.
