---
paths:
  - 'app/Http/**'
  - 'routes/**'
---

# HTTP and routes

## Keep the API contract authenticated and redacted
Keep controllers thin. Use Form Requests and typed data objects at the boundary. Except for the explicit bootstrap trust endpoints, require an active WireGuard peer for every API route. Preserve stable error envelopes, request correlation, and colon-delimited route names. Recursively redact secrets before responses, errors, logs, debug text, and activity persistence.

## Enforce binary node access
Enforce binary directed node access at the HTTP boundary. One access edge permits all commands for its serving node. The active Gateway peer is implicit authority, and access to the Gateway is fleet-wide. Do not add granular permissions, presets, wildcards, or permission compatibility code.
