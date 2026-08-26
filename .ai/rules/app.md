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
Keep controllers and console adapters thin. Put synchronous behavior in final readonly actions, use typed data objects at boundaries, and keep narrow domain contracts independent of native infrastructure implementations. Do not add queues, a background Agent, a UI, or a generic executor.

## Keep node access binary
Enforce binary directed node access at the HTTP boundary. One access edge permits all commands for its serving node. The active Gateway peer is implicit authority, and access to the Gateway is fleet-wide. Do not add granular permissions, presets, wildcards, or permission compatibility code.

## Keep Linux privilege boundaries narrow
Linux control-plane work runs through pinned gateway SSH with explicit narrow sudo.
