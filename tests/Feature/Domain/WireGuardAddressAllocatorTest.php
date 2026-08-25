<?php

declare(strict_types=1);

use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Domain\WireGuard\WireGuardAddressAllocator;
use App\Models\Node;

it('allocates the next unused peer address from the configured subnet', function (): void {
    app(SettingRepository::class)->put(
        new SettingScope(SettingScopeType::Gateway),
        'vpn.subnet',
        '10.44.0.0/24',
    );
    Node::query()->create([
        'name' => 'gateway',
        'public_ssh_host' => '85.9.218.89',
        'wireguard_address' => '10.44.0.1',
    ]);
    Node::query()->create([
        'name' => 'operator',
        'public_ssh_host' => '94.237.108.25',
        'wireguard_address' => '10.44.0.2',
    ]);

    expect(app(WireGuardAddressAllocator::class)->next())->toBe('10.44.0.3');
});
