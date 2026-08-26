---
paths:
  - 'app/Infrastructure/**'
---

# Infrastructure

## Use fixed typed argv
Build remote operations from fixed, typed argv in narrow infrastructure contracts. Never add a generic executor, arbitrary script endpoint, Agent, or caller-supplied shell program.

## Keep secrets out of command arguments
Transport secrets through stdin or narrowly scoped mode-0600 protected files. Secret bytes must never enter local or remote argv, ProcessInvocation state, exception or debug text, API responses, or activity data.

## Publish managed state atomically
Require exact Orbit ownership before mutation. For shared state, lock first, snapshot after locking, write a candidate, validate it, switch atomically, and restore the exact prior file or symlink plus service state when activation fails. Keep an explicit recovery path.

## Search the legacy Orbit project before infrastructure design
Search /home/nckrtl/orbit implementations and tests before inventing infrastructure behavior. Port proven invariants when compatible, but never port the retired Agent, Docker or Swarm gateway, permissions, operation topology, generic executors, Compose, FrankenPHP, or image-building architecture.

## Use only pinned Sury Resolute PHP packages
Require Ubuntu Resolute before remote mutation. Use the direct Sury PHP repository with an Orbit-owned scoped keyring, pinned key digest and fingerprints, exact candidate-origin checks, and atomic recovery. Never use a Launchpad PPA, mix Ubuntu suites, or accept caller-provided package sources.

## Route project JavaScript work through Vite+

Use `vp` for generic project dependency and script commands. Follow Vite+'s
native package-manager selection order; a project without a manager signal
defaults to pnpm. Let Vite+ resolve that project state instead of adding a PHP
resolver.

Vite+ manages Node through `vp env`. It owns package-manager dispatch. Orbit
installs pnpm by default. Orbit installs Bun separately. Bun is a host runtime
on `app-dev` and `app-prod` hosts. `vp install -g` uses Vite+'s managed global store.
Do not replace PHP or Composer commands. Use a native package-manager command
only at an intentional bootstrap, publication, or runtime boundary.
