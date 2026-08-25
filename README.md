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
php artisan orbit:bootstrap 85.9.218.89 \
    --wireguard-endpoint=85.9.218.89:51820 \
    --private-interface=eth3
```

Run migrations explicitly after each pull. The bootstrap command creates the
gateway SSH key, WireGuard key, root CA, gateway node, roles, and VPN settings
under `ORBIT_HOME`.

Provision the first peer directly on the gateway. Later peers use the public
CLI and the same gateway action.

```bash
php artisan orbit:node-provision operator 94.237.108.25 \
    --role=app-dev \
    --wireguard-address=10.44.0.2 \
    --wireguard-endpoint=10.0.0.2:51820 \
    --dns-server=10.0.0.2
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
