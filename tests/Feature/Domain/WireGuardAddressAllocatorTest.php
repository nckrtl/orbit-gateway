<?php

declare(strict_types=1);

use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\VpnSettings;
use App\Domain\WireGuard\WireGuardAddressAllocator;
use App\Models\Node;

it('allocates the next unused peer address from the configured subnet', function (): void {
    app(VpnSettings::class)->configure(subnet: '10.44.0.0/24');
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

it('accepts a requested usable address inside the configured subnet', function (): void {
    configure_wireguard_subnet('10.44.0.0/29');

    expect(app(WireGuardAddressAllocator::class)->forProvisioning('10.44.0.3'))
        ->toBe('10.44.0.3');
});

it('rejects requested network broadcast and outside addresses', function (string $address): void {
    configure_wireguard_subnet('10.44.0.0/29');

    expect(fn (): string => app(WireGuardAddressAllocator::class)->forProvisioning($address))
        ->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('vpn.peer_address_invalid');
        });
})->with([
    'network' => '10.44.0.0',
    'broadcast' => '10.44.0.7',
    'outside subnet' => '10.44.0.8',
]);

it('rejects another nodes address while permitting stable reuse by the same node', function (): void {
    configure_wireguard_subnet('10.44.0.0/29');
    $node = Node::query()->create([
        'name' => 'operator',
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $allocator = app(WireGuardAddressAllocator::class);

    expect($allocator->forProvisioning('10.44.0.2', $node))
        ->toBe('10.44.0.2')
        ->and(fn (): string => $allocator->forProvisioning('10.44.0.2'))
        ->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('vpn.peer_address_taken');
        });
});

it('returns stable errors for invalid and exhausted configured subnets', function (): void {
    configure_wireguard_subnet('invalid');

    expect(fn (): string => app(WireGuardAddressAllocator::class)->next())
        ->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('vpn.subnet_invalid');
        });

    configure_wireguard_subnet('10.44.0.0/30');
    Node::query()->create([
        'name' => 'gateway',
        'public_ssh_host' => '192.0.2.1',
        'wireguard_address' => '10.44.0.1',
    ]);
    Node::query()->create([
        'name' => 'operator',
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);

    expect(fn (): string => app(WireGuardAddressAllocator::class)->next())
        ->toThrow(function (ResourceOperationException $exception): void {
            expect($exception->errorCode)->toBe('vpn.peer_address_exhausted');
        });
});

function configure_wireguard_subnet(string $subnet): void
{
    app(VpnSettings::class)->configure(subnet: $subnet);
}
