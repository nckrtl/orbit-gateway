---
paths:
  - 'app/Models/**'
  - 'database/**'
---

# Models and database

## Preserve control-plane data
SQLite under `$ORBIT_HOME` is the Gateway's central store. Use explicit migrations, preserve existing control-plane state, and fail closed when ownership or migration input is ambiguous. Do not put mutable runtime data in the checkout or add seed/factory ceremony that the behavior does not need.
