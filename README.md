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

Provision the first role-less operator directly on the gateway. Later peers use
the public CLI and the same gateway action.

Get the SSH host fingerprint from the node's provider console or another
trusted out-of-band channel. For an Ed25519 host key, run this on the node:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

If you collect a candidate fingerprint over the public network, compare it with
the trusted value before you approve it. A network scan alone does not prove the
node's identity.

```bash
php artisan orbit:node-provision operator '<PUBLIC_SSH_HOST>' \
    --architecture='<x86_64-or-aarch64>' \
    --host-key-fingerprint='SHA256:<APPROVED_HOST_KEY_FINGERPRINT>'
```

Orbit allocates the peer WireGuard address and uses the gateway WireGuard and
DNS settings by default. For a peer that must use a private underlay, append the
optional `--wireguard-endpoint='<PRIVATE_GATEWAY_IP>:51820'` and
`--dns-server='<PRIVATE_DNS_IP>'` overrides.

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
