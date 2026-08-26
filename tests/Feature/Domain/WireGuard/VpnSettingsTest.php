<?php

declare(strict_types=1);

use App\Domain\Settings\SettingRepository;
use App\Domain\WireGuard\VpnSettings;
use App\Models\Setting;

it('returns typed VPN defaults when gateway settings are absent', function (): void {
    $settings = app(VpnSettings::class);

    expect($settings->subnet())
        ->toBe('10.44.0.0/24')
        ->and($settings->port())
        ->toBe('51820')
        ->and($settings->endpoint())
        ->toBeNull()
        ->and($settings->dnsServer())
        ->toBeNull()
        ->and($settings->domain())
        ->toBe('orbit')
        ->and($settings->configuredDomain())
        ->toBeNull()
        ->and($settings->privateInterface())
        ->toBeNull();
});

it('persists and reloads the complete typed VPN configuration', function (): void {
    app(VpnSettings::class)->configure(
        subnet: '10.80.0.0/24',
        port: 51_821,
        endpoint: 'vpn.example.test:51821',
        dnsServer: '10.80.0.1',
        domain: 'private.example.test',
        privateInterface: 'eth3',
    );

    $settings = new VpnSettings(app(SettingRepository::class));

    expect($settings->subnet())
        ->toBe('10.80.0.0/24')
        ->and($settings->port())
        ->toBe('51821')
        ->and($settings->endpoint())
        ->toBe('vpn.example.test:51821')
        ->and($settings->dnsServer())
        ->toBe('10.80.0.1')
        ->and($settings->domain())
        ->toBe('private.example.test')
        ->and($settings->configuredDomain())
        ->toBe('private.example.test')
        ->and($settings->privateInterface())
        ->toBe('eth3')
        ->and(Setting::query()->count())
        ->toBe(6);
});
