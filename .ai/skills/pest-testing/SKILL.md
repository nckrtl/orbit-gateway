---
name: pest-testing
description: Use when writing, changing, debugging, or reviewing Pest tests in the Orbit Gateway.
---

# Pest testing

This repository uses Pest 5 and PHPUnit 13. Use `describe()` and `it()` with clear behavior names.

## Test design

- Start with a focused failing test and confirm the expected failure before implementation.
- Prefer real boundaries and Laravel fakes over tests that only restate mock expectations.
- Use factories or named states when they exist. Do not add unused factory or seeder ceremony.
- Use datasets for meaningful input matrices. Test API authentication, validation, redaction, ownership, rollback, and stable error contracts at their executing boundary.
- Do not delete tests without explicit approval.
- This Gateway has no UI or browser-test surface. Do not invent browser, Livewire, or Inertia tests.

## Commands

Run the narrowest useful test while developing:

```bash
vendor/bin/pest --compact tests/Feature/Path/To/Test.php
vendor/bin/pest --compact --filter='test name'
```

`composer test` runs Pest with Test Impact Analysis. TIA replays cached results; it does not skip assertions. Before handoff, also run `composer test:full`, which uses `--no-tia`, plus the repository Rector and Mago gates.
