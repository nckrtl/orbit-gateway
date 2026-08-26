---
paths:
  - 'app/Http/**'
  - 'routes/**'
---

# HTTP and routes

## Keep the API contract authenticated and redacted
Keep controllers thin. Use Form Requests and typed data objects at the boundary. Except for the explicit bootstrap trust endpoints, require an active WireGuard peer for every API route. Preserve stable error envelopes, request correlation, and colon-delimited route names. Recursively redact secrets before responses, errors, logs, debug text, and activity persistence.
