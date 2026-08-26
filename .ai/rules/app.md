---
paths:
  - 'app/Actions/**'
  - 'app/Data/**'
  - 'app/Domain/**'
  - 'app/Exceptions/**'
  - 'app/Infrastructure/**'
  - 'app/Rules/**'
---

# App

## Keep Gateway application boundaries explicit
Keep controllers and console adapters thin. Put synchronous behavior in final readonly actions, use typed data objects at boundaries, and keep narrow domain contracts independent of native infrastructure implementations. Do not add queues, permissions, a background Agent, a UI, or a generic executor.

## Keep Linux privilege boundaries narrow
Linux control-plane work runs through pinned gateway SSH with explicit narrow sudo.
