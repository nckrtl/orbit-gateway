---
paths:
  - 'app/Console/**'
  - 'app/Providers/**'
  - 'bootstrap/**'
  - 'config/**'
  - 'AGENTS.md'
  - 'boost.json'
  - 'composer.json'
  - 'composer.lock'
  - '.ai/**'
  - '.agents/**'
  - '.codex/**'
---

# Bootstrap and project tooling

## Treat incomplete guidance as a bootstrap failure
Run `composer guidance:check` before edits. If it fails, make no product-code edits. Restore the exact tracked guidance paths from the current branch, install dependencies, and run the check again. Use `composer guidance:update` only after the committed sources pass validation; Boost cannot recreate deleted project-owned rules.

Keep project guidance sources in `.ai`, generated Codex skills in `.agents`, and the effective `AGENTS.md` synchronized. Do not patch vendor files or framework caches.
