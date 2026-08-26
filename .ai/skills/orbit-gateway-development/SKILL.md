---
name: orbit-gateway-development
description: Use when changing Orbit gateway API contracts, control-plane state, provisioning, SSH execution, native services, or gateway-local quality tooling.
---

# Orbit Gateway Development

This Laravel application is Orbit's central store and control plane. It owns
business logic and performs explicit infrastructure actions over SSH.

## Boundaries

- Keep operational business logic in this repository.
- Keep SDK request objects in `orbit-php-sdk`.
- Keep CLI presentation and local-only OS actions in `orbit-cli`.
- Use SQLite under `$ORBIT_HOME`. Do not put mutable state in the checkout.
- Use fixed argument arrays, pinned SSH host keys, narrow managed files, probes,
  candidate validation, atomic publication, and rollback where activation can
  fail.
- Keep secrets out of local and remote argument arrays, process invocation
  state, exceptions, API responses, and activity records. Send secrets only
  through stdin or mode-0600 protected files with guaranteed cleanup.
- Require exact Orbit ownership before mutation. Lock every shared aggregate,
  snapshot it after lock acquisition, validate a candidate, switch atomically,
  and restore the exact previous state when activation fails.
- Use systemd for Linux services. Do not add Docker/Swarm gateway deployment,
  an Agent, a hidden executor, generic scripts, or unattended macOS elevation.
- Keep Linux privilege escalation behind narrow remote commands. Keep Darwin
  privilege-sensitive actions in the local macOS adapter.
- Before designing infrastructure behavior, search `/home/nckrtl/orbit/orbit` for its
  implementation and tests. Port compatible invariants, not retired topology.

## Required skills

- Read `spatie-laravel-php` for PHP and Laravel changes.
- Read `pest-testing` before changing tests.
- Read `spatie-security` for credentials, SSH, CA, DNS, firewall, WireGuard,
  filesystem permissions, or server configuration.

## Verification

```bash
composer test
composer check
composer test:full
```

Run focused Pest tests during TDD. Run Pest 5 with TIA, full Pest without TIA,
Rector, Mago format/lint/analyse, and `git diff --check` before handoff.
