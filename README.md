# Orbit Gateway

The Laravel control plane for Orbit. It stores fleet state in SQLite and runs
synchronous infrastructure actions on registered nodes through SSH.

The gateway runs directly on Linux with Caddy and PHP-FPM. It does not use a
container, a background agent, or a queue worker.

## Requirements

- PHP 8.5
- Composer 2
- SQLite

## Development

```bash
composer setup
php artisan serve
```

The versioned status endpoint is `GET /api/v1/gateway/status`.

Use `ORBIT_HOME` to override the application data directory. The default is
`$HOME/.orbit`.

## Quality

```bash
composer test       # Pest 5 with local TIA
composer test:full  # full Pest suite
composer format     # Mago formatter
composer check      # TIA tests and all Mago checks
```
