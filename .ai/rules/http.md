---
paths:
  - 'app/Http/**'
  - 'routes/**'
---

# HTTP and routes

## Keep the API contract authenticated and redacted
Keep controllers thin. Use Form Requests and typed data objects at the boundary. Except for the explicit bootstrap trust endpoints, require an active WireGuard peer for every API route. Preserve stable error envelopes, request correlation, and colon-delimited route names. Recursively redact secrets before responses, errors, logs, debug text, and activity persistence.

Only `node:setup:app-dev:script` and `node:setup:app-dev:result` may authenticate registered Darwin WireGuard peers whose lifecycle is provisioning, failed, or active. Keep active-peer authentication unchanged on every other route. Derive setup caller identity from the trusted FastCGI transport boundary, never from request data, route parameters, or forwarding headers.

Reject malformed JSON plus duplicate and unknown top-level keys before Form Request execution. Create and complete one correlated failed activity without persisting raw rejected bytes.
