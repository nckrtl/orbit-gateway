---
paths:
  - 'app/**'
---

# App

## Respect Linux and Darwin privilege boundaries
Linux control-plane work runs through pinned gateway SSH with explicit narrow sudo. Darwin actions belong to the local macOS adapter and must not assume unattended gateway elevation.
