<?php

declare(strict_types=1);

use App\Domain\WireGuard\WireGuardEndpoint;

it('accepts safe WireGuard endpoint forms', function (string $endpoint): void {
    expect(WireGuardEndpoint::isValid($endpoint))->toBeTrue();
})->with([
    'IPv4' => '10.0.0.2:51820',
    'hostname' => 'vpn.private.example:51820',
    'bracketed IPv6' => '[fd00::2]:51820',
]);

it('rejects unsafe or incomplete WireGuard endpoint forms', function (string $endpoint): void {
    expect(WireGuardEndpoint::isValid($endpoint))->toBeFalse();
})->with([
    'missing port' => '10.0.0.2',
    'invalid port' => '10.0.0.2:70000',
    'bare IPv6' => 'fd00::2:51820',
    'shell control' => "10.0.0.2:51820\nPostUp = touch /tmp/orbit-injected",
]);
